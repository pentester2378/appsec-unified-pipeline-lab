#!/usr/bin/env python3
"""Gate SAST aggregato: un esito unico dai report SARIF di piu' strumenti.

Legge tutti i file *.sarif di una cartella (CodeQL, Semgrep, Gitleaks, Trivy o altri),
porta ogni risultato a una severita' comune, conta una volta sola la stessa vulnerabilita'
segnalata da strumenti diversi e applica la policy dello score:

    score = 100 meno la somma dei pesi; PASS solo con score maggiore di 90 e nessun
    finding High o Critical.

Codici di uscita: 0 PASS, 2 FAIL, 3 INVALID (report mancante, illeggibile o incompleto:
mai un PASS su dati mancanti). Solo libreria standard.

Uso:
    python3 scripts/sast_multi_gate.py --sarif-dir sarif \
        --expect codeql,semgrep,gitleaks,trivy --summary reports/sast-multi-gate.json
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

THRESHOLD = 90
WEIGHTS = {'critical': 40, 'high': 20, 'medium': 3, 'low': 1, 'info': 0}
BLOCKING_SEVERITIES = ('critical', 'high')
LEVEL_TO_SEVERITY = {'error': 'high', 'warning': 'medium', 'note': 'low', 'none': 'info'}
DEFAULT_LEVEL = 'warning'  # valore predefinito di SARIF 2.1.0 quando il livello manca
LINE_TOLERANCE = 5

# Nome del driver SARIF -> nome dello strumento usato nel riepilogo e in --expect.
TOOL_ALIASES = {'codeql': 'codeql', 'semgrep': 'semgrep', 'gitleaks': 'gitleaks', 'trivy': 'trivy'}
# security: ogni risultato dello strumento e' di sicurezza. severity: severita' fissa
# quando il report non ne indica una (una credenziale nel codice blocca).
TOOL_PROFILES = {
    'gitleaks': {'security': True, 'severity': 'high'},
    'trivy': {'security': True},
}
# Punti di montaggio noti dei container: i percorsi assoluti diventano relativi al repository.
WORKSPACE_PREFIXES = ('/github/workspace/', '/repo/', '/src/')
CWE_PATTERN = re.compile(r'cwe[-_/ ]?0*(\d+)', re.IGNORECASE)


def tool_name(run):
    name = str(run['tool']['driver'].get('name') or '').strip().lower()
    for alias, tool in TOOL_ALIASES.items():
        if name.startswith(alias):
            return tool
    return (re.split(r'[^a-z0-9]+', name)[0] if name else '') or 'sconosciuto'


def load_runs(path):
    """Restituisce l'elenco (file, run) di tutti i SARIF sotto path."""
    path = Path(path)
    files = [path] if path.is_file() else sorted(path.rglob('*.sarif')) if path.is_dir() else []
    if not files:
        raise ValueError(f'Nessun file SARIF in {path}: impossibile dichiarare PASS')
    runs = []
    for file in files:
        try:
            data = json.loads(file.read_text(encoding='utf-8'))
        except ValueError as error:
            raise ValueError(f'{file.name}: JSON non valido ({error})') from None
        if not isinstance(data, dict) or data.get('version') != '2.1.0' or not data.get('runs'):
            raise ValueError(f'{file.name}: non e\' un SARIF 2.1.0 con almeno un run')
        for run in data['runs']:
            if not isinstance(run, dict) or not (run.get('tool') or {}).get('driver'):
                raise ValueError(f'{file.name}: run senza tool.driver')
            # Un'esecuzione dichiarata non riuscita puo' avere risultati parziali.
            if any(invocation.get('executionSuccessful') is False for invocation in run.get('invocations') or []):
                raise ValueError(f'{file.name}: lo strumento dichiara un\'esecuzione non riuscita')
            runs.append((file.name, run))
    return runs


def normalize_path(uri):
    path = str(uri or '')
    if path.startswith('file://'):
        path = path[len('file://'):]
    prefixes = [os.environ.get('GITHUB_WORKSPACE', ''), os.getcwd(), *WORKSPACE_PREFIXES]
    for prefix in prefixes:
        prefix = prefix.rstrip('/') + '/' if prefix else ''
        if prefix and path.startswith(prefix):
            path = path[len(prefix):]
            break
    while path.startswith('./'):
        path = path[2:]
    return path.lstrip('/')


def severity_from_score(raw, rule_id):
    try:
        value = float(raw)
    except (TypeError, ValueError):
        raise ValueError(f'security-severity non numerica per {rule_id}: {raw!r}') from None
    if not 0.0 <= value <= 10.0:  # esclude anche NaN
        raise ValueError(f'security-severity fuori dall\'intervallo 0-10 per {rule_id}: {raw!r}')
    if value >= 9.0:
        return 'critical'
    if value >= 7.0:
        return 'high'
    if value >= 4.0:
        return 'medium'
    return 'low' if value > 0 else 'info'


def rules_of(run):
    rules = {}
    tool = run['tool']
    for group in [tool.get('driver') or {}, *(tool.get('extensions') or [])]:
        for rule in group.get('rules') or []:
            if rule.get('id'):
                rules[rule['id']] = rule
    return rules


def normalize(runs):
    """Porta ogni risultato SARIF a un formato comune, indipendente dallo strumento."""
    results = []
    for _, run in runs:
        tool = tool_name(run)
        profile = TOOL_PROFILES.get(tool, {})
        rules = rules_of(run)
        for item in run.get('results') or []:
            # Senza la regola non si conoscono severita' ed etichette: il risultato non puo'
            # essere declassato a informativo, quindi il report e' INVALID (come in sast_gate.py).
            rule_id = item.get('ruleId') or (item.get('rule') or {}).get('id')
            if not rule_id:
                raise ValueError(f'{tool}: risultato senza ruleId, severita\' non valutabile')
            if rule_id not in rules:
                raise ValueError(f'{tool}: regola non dichiarata nel report: {rule_id}')
            rule = rules[rule_id]
            properties = dict(rule.get('properties') or {})
            tags = [str(tag) for tag in (properties.get('tags') or [])]
            tags += [str(tag) for tag in ((item.get('properties') or {}).get('tags') or [])]
            raw_score = properties.get('security-severity')
            if raw_score is None:
                raw_score = (item.get('properties') or {}).get('security-severity')
            if raw_score is not None:
                severity = severity_from_score(raw_score, rule_id)
            elif profile.get('severity'):
                severity = profile['severity']
            else:
                level = item.get('level') or (rule.get('defaultConfiguration') or {}).get('level') or DEFAULT_LEVEL
                severity = LEVEL_TO_SEVERITY.get(str(level).lower(), LEVEL_TO_SEVERITY[DEFAULT_LEVEL])
            cwes = sorted({int(number) for tag in tags for number in CWE_PATTERN.findall(tag)})
            lowered = [tag.lower() for tag in tags]
            security = bool(raw_score is not None or profile.get('security') or cwes or 'security' in lowered)
            low_confidence = ('low confidence' in lowered
                              or str(properties.get('precision') or '').lower() == 'low')
            location = ((item.get('locations') or [{}])[0].get('physicalLocation') or {})
            line = (location.get('region') or {}).get('startLine')
            title = ((rule.get('shortDescription') or {}).get('text')
                     or (item.get('message') or {}).get('text') or rule_id)
            # Soppressione nel codice (per esempio "nosemgrep") o esterna, se non respinta o in revisione.
            suppressed = any((entry.get('status') or 'accepted') == 'accepted'
                             for entry in item.get('suppressions') or [])
            results.append({
                'suppressed': suppressed, 'tool': tool, 'rule': rule_id,
                'path': normalize_path((location.get('artifactLocation') or {}).get('uri')),
                'line': line if isinstance(line, int) else None,
                'severity': severity, 'security': security, 'low_confidence': low_confidence,
                'cwes': cwes, 'title': ' '.join(str(title).split())[:160],
            })
    return results


def heavier(first, second):
    return first if WEIGHTS[first] >= WEIGHTS[second] else second


def same_vulnerability(first, second):
    """Vero se due unita' di strumenti diversi descrivono la stessa vulnerabilita'."""
    if set(first['tools']) & set(second['tools']) or first['path'] != second['path']:
        return False
    if not set(first['cwes']) & set(second['cwes']):
        return False
    return any(abs(a - b) <= LINE_TOLERANCE for a in first['lines'] for b in second['lines'])


def build_units(results):
    """Unita' di conteggio: una per (strumento, regola, file), poi unite tra strumenti diversi."""
    grouped = {}
    for item in results:
        key = (item['tool'], item['rule'], item['path'])
        unit = grouped.setdefault(key, {
            'tools': [item['tool']], 'rules': [item['rule']], 'path': item['path'], 'lines': [],
            'severity': item['severity'], 'low_confidence': True, 'cwes': [], 'title': item['title'],
            'occurrences': 0})
        unit['severity'] = heavier(unit['severity'], item['severity'])
        unit['low_confidence'] = unit['low_confidence'] and item['low_confidence']
        unit['cwes'] = sorted(set(unit['cwes']) | set(item['cwes']))
        unit['occurrences'] += 1
        if item['line'] is not None:
            unit['lines'].append(item['line'])
    merged, duplicates = [], 0
    for unit in grouped.values():
        target = next((other for other in merged if same_vulnerability(other, unit)), None)
        if target is None:
            merged.append(unit)
            continue
        duplicates += 1
        target['tools'] = sorted(set(target['tools']) | set(unit['tools']))
        target['rules'] = sorted(set(target['rules']) | set(unit['rules']))
        target['lines'] = sorted(set(target['lines']) | set(unit['lines']))
        target['cwes'] = sorted(set(target['cwes']) | set(unit['cwes']))
        target['low_confidence'] = target['low_confidence'] and unit['low_confidence']
        target['occurrences'] += unit['occurrences']
        if WEIGHTS[unit['severity']] > WEIGHTS[target['severity']]:
            target['severity'], target['title'] = unit['severity'], unit['title']
    for unit in merged:
        unit['lines'] = sorted(set(unit['lines']))
    return merged, duplicates


def evaluate(results, tools, expected=()):
    """Calcola score, bloccanti ed esito. tools: strumenti che hanno prodotto almeno un run."""
    present = sorted(set(tools))
    missing = [name for name in expected if name not in present]
    if missing:
        raise ValueError('Report mancante per: ' + ', '.join(missing)
                         + ' (presenti: ' + (', '.join(present) or 'nessuno') + ')')
    per_tool = {name: {'results': 0, 'counted': 0, 'blocking': 0, 'informational': 0, 'suppressed': 0}
                for name in present}
    suppressed = []
    for item in results:
        per_tool[item['tool']]['results'] += 1
        if not item['security']:
            per_tool[item['tool']]['informational'] += 1
        elif item['suppressed']:
            # Non conteggiati, ma sempre elencati: una soppressione va verificata in revisione.
            per_tool[item['tool']]['suppressed'] += 1
            suppressed.append({'id': item['rule'], 'tools': [item['tool']], 'severity': item['severity'],
                               'path': item['path'], 'line': item['line'], 'title': item['title']})
    units, duplicates = build_units([item for item in results if item['security'] and not item['suppressed']])
    counts = {severity: 0 for severity in WEIGHTS}
    blocking, findings, excluded = [], [], 0
    for unit in sorted(units, key=lambda u: (-WEIGHTS[u['severity']], u['path'], u['rules'])):
        is_blocking = unit['severity'] in BLOCKING_SEVERITIES
        # I bloccanti valgono a qualunque confidenza: si valutano prima dell'esclusione.
        if not is_blocking and unit['low_confidence']:
            excluded += 1
            continue
        counts[unit['severity']] += 1
        entry = {'id': ' + '.join(unit['rules']), 'tools': sorted(unit['tools']), 'severity': unit['severity'],
                 'path': unit['path'], 'line': unit['lines'][0] if unit['lines'] else None,
                 'occurrences': unit['occurrences'], 'cwes': unit['cwes'], 'title': unit['title']}
        findings.append(entry)
        for name in entry['tools']:
            per_tool[name]['counted'] += 1
        if is_blocking:
            blocking.append(dict(entry, reason="severita' bloccante"))
            for name in entry['tools']:
                per_tool[name]['blocking'] += 1
    score = max(0, 100 - sum(WEIGHTS[severity] * number for severity, number in counts.items()))
    status = 'PASS' if score > THRESHOLD and not blocking else 'FAIL'
    return {'gate': 'sast-multi', 'status': status, 'score': score, 'threshold': THRESHOLD,
            'counts': counts, 'blocking': blocking, 'tools': per_tool, 'findings': findings,
            'merged_duplicates': duplicates, 'excluded_low_confidence': excluded, 'suppressed': suppressed,
            'informational': sum(entry['informational'] for entry in per_tool.values())}


def cell(text):
    return str(text).replace('|', '\\|').replace('\n', ' ')


def to_markdown(summary):
    lines = [f"## SAST aggregato: {summary['status']} - score {summary['score']}/100",
             '',
             f"Soglia: score maggiore di {summary['threshold']} e nessun finding High o Critical. "
             f"Bloccanti: {len(summary['blocking'])}. Duplicati uniti tra strumenti: {summary['merged_duplicates']}. "
             f"Esclusi per confidenza bassa: {summary['excluded_low_confidence']}. "
             f"Soppressi nel codice: {len(summary['suppressed'])}.",
             '',
             '| Strumento | Risultati letti | Conteggiati | Bloccanti | Informativi | Soppressi |',
             '|---|---|---|---|---|---|']
    for name, entry in sorted(summary['tools'].items()):
        lines.append(f"| {cell(name)} | {entry['results']} | {entry['counted']} | {entry['blocking']} | "
                     f"{entry['informational']} | {entry['suppressed']} |")
    if summary['findings']:
        lines += ['', '| Severità | Strumenti | Regola | File | Riga | Ripetizioni |', '|---|---|---|---|---|---|']
        for item in summary['findings']:
            lines.append(f"| {item['severity']} | {cell(' + '.join(item['tools']))} | {cell(item['id'])} | "
                         f"{cell(item['path'])} | {item['line'] or ''} | {item['occurrences']} |")
    if summary['suppressed']:
        lines += ['', '### Soppressi nel codice (non conteggiati: da verificare in revisione)', '',
                  '| Severità | Strumento | Regola | File | Riga |', '|---|---|---|---|---|']
        for item in summary['suppressed']:
            lines.append(f"| {item['severity']} | {cell(' + '.join(item['tools']))} | {cell(item['id'])} | "
                         f"{cell(item['path'])} | {item['line'] or ''} |")
    return '\n'.join(lines) + '\n'


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


def check_job_results(entries, expected):
    """Un job di strumento non riuscito puo' aver lasciato un report parziale: il gate e' INVALID.

    entries: elenco di "strumento=esito". Se e' vuoto il controllo non si applica (uso in locale).
    """
    if not entries:
        return
    results = {}
    for entry in entries:
        name, separator, outcome = entry.partition('=')
        if not separator:
            raise ValueError(f'--job-result non valido: {entry!r} (atteso STRUMENTO=ESITO)')
        results[name.strip().lower()] = outcome.strip().lower()
    bad = [f"{name} ({results.get(name) or 'esito assente'})" for name in expected if results.get(name) != 'success']
    if bad:
        raise ValueError('Job dello strumento non riuscito: ' + ', '.join(bad))


def main(argv=None):
    parser = argparse.ArgumentParser(description='Gate SAST aggregato su piu\' report SARIF.')
    parser.add_argument('--sarif-dir', required=True, type=Path, help='cartella (o file) con i report SARIF')
    parser.add_argument('--expect', default='',
                        help='obbligatoria: strumenti il cui report deve esserci, separati da virgole')
    parser.add_argument('--job-result', action='append', default=[], metavar='STRUMENTO=ESITO',
                        help='esito del job che ha eseguito lo strumento (success, failure, ...); ripetibile. '
                             'Se indicata, ogni strumento atteso deve avere esito success')
    parser.add_argument('--summary', type=Path, default=Path('reports/sast-multi-gate.json'))
    parser.add_argument('--markdown', type=Path, help='file in cui scrivere il riepilogo in Markdown')
    args = parser.parse_args(argv)
    expected = [name.strip().lower() for name in args.expect.split(',') if name.strip()]
    try:
        if not expected:
            raise ValueError('--expect e\' obbligatoria: senza l\'elenco degli strumenti attesi '
                             'un report mancante passerebbe inosservato')
        check_job_results(args.job_result, expected)
        runs = load_runs(args.sarif_dir)
        summary = evaluate(normalize(runs), [tool_name(run) for _, run in runs], expected)
        write(args.summary, json.dumps(summary, indent=2, ensure_ascii=False) + '\n')
        if args.markdown:
            write(args.markdown, to_markdown(summary))
    except (ValueError, OSError, TypeError, KeyError, AttributeError) as error:
        print(f'::error::SAST MULTI GATE INVALID: {error}')
        return 3
    print(f"SAST MULTI GATE: {summary['status']}; score {summary['score']}/100 (soglia {THRESHOLD}); "
          f"blocking High/Critical: {len(summary['blocking'])}; strumenti: {', '.join(sorted(summary['tools']))}")
    for name, entry in sorted(summary['tools'].items()):
        print(f"  {name}: risultati {entry['results']}, conteggiati {entry['counted']}, "
              f"bloccanti {entry['blocking']}, informativi {entry['informational']}, "
              f"soppressi nel codice: {entry['suppressed']}")
    for item in summary['blocking']:
        position = f"file={item['path']}" + (f",line={item['line']}" if item['line'] else '')
        print(f"::error {position}::[{' + '.join(item['tools'])}] {item['id']} ({item['severity']})")
    return 0 if summary['status'] == 'PASS' else 2


if __name__ == '__main__':
    sys.exit(main())
