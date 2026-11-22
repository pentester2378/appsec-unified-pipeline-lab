#!/usr/bin/env python3
"""Agente DAST esterno (opzione C): scansione ZAP su una macchina interna, esito su GitHub.

La macchina non riceve connessioni: a intervalli chiede a GitHub quali commit attendono
il controllo, esegue OWASP ZAP in locale e scrive l'esito sul commit come stato
"DAST ESTERNO (ZAP)". Un ruleset che richiede quello stato blocca il merge finche'
l'esito non e' positivo.

Uso tipico, dalla macchina interna:
    export GH_TOKEN=<token con permesso "Commit statuses: Read and write">
    python3 dast_external_agent.py --repo owner/nome

Prova senza scrivere nulla e senza Docker:
    python3 dast_external_agent.py --repo owner/nome --dry-run --once

Con ZAP installato direttamente sulla macchina (senza l'immagine Docker di ZAP):
    python3 dast_external_agent.py --repo owner/nome --zap-cmd /usr/local/bin/zap

Dopo un DAST superato, anche il penetration test agentico con Strix, che scrive lo stato
"PT AGENTICO (STRIX)". Strix esegue attacchi reali: serve l'autorizzazione a testare il
bersaglio, da dichiarare con --pentest-authorized:
    python3 dast_external_agent.py --repo owner/nome --target-url https://app.test.interna \
        --pentest-cmd strix --pentest-authorized

Requisiti sulla macchina: python3 e git; docker con compose per costruire l'applicazione
(non serve con --target-url); ZAP in Docker oppure installato (--zap-cmd); per il PT, Strix
con Docker e un modello configurato (STRIX_LLM, LLM_API_KEY, LLM_API_BASE). Solo libreria
standard. La scansione ZAP e' sempre passiva: nessun test attivo.
"""
import argparse
import atexit
import getpass
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import zipfile
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

API = "https://api.github.com"
CONTEXT = "DAST ESTERNO (ZAP)"
THRESHOLD = 90
WEIGHTS = {"critical": 40, "high": 20, "medium": 3, "low": 1, "info": 0}
RISK_TO_SEVERITY = {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}
BLOCKING_SEVERITIES = ("critical", "high")
BLOCKING_RULES = ("10038-1",)
FINAL_STATES = ("success", "failure", "error")
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"
CURL_IMAGE = "curlimages/curl:latest"
DESCRIPTION_MAX = 140
LOCAL_ZAP_JOBS = ("passiveScan-config", "spider", "passiveScan-wait", "report", "report")
REQUIRED_ZAP_ADDONS = ("pscanrules", "commonlib")
PT_CONTEXT = "PT AGENTICO (STRIX)"
PENTEST_MODES = ("quick", "standard", "deep")
STRIX_RUNS_DIR = "strix_runs"                    # creata da Strix nella cartella corrente
# Strix crea run.json gia' all'avvio (stato "running") e termina con codice 0 anche a budget
# esaurito o a scansione interrotta (stato "stopped"): vale solo lo stato "completed".
STRIX_RUN_RECORD = "run.json"
STRIX_COMPLETED = "completed"
# Il token che scrive gli stati su GitHub non deve arrivare a Strix ne' al suo sandbox.
SECRET_ENV = ("GH_TOKEN", "GITHUB_TOKEN", "DAST_AGENT_TOKEN")
SIMULATED_PREFIX = "[SIMULATO] "
TERMINATE_GRACE = 30  # secondi concessi a un comando dopo SIGTERM, prima di SIGKILL


class ApiError(Exception):
    pass


class ScanError(Exception):
    pass


class CommandResult:
    """Esito di un comando: codice di uscita e output (standard output ed error insieme)."""

    def __init__(self, returncode, stdout):
        self.returncode, self.stdout = returncode, stdout


def log(message):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}", flush=True)


# ----------------------------------------------------------------- policy

def origin(url):
    parts = urlsplit(str(url))
    if parts.scheme not in ("http", "https") or not parts.netloc:
        raise ValueError(f"Indirizzo non valido nel report: {url!r}")
    return f"{parts.scheme}://{parts.netloc.lower()}"


def evaluate(report, expected_origin):
    """Calcola score ed esito da un report ZAP (formato JSON tradizionale).

    Score = 100 meno la somma dei pesi, una volta per regola di alert. Esito PASS solo
    con score maggiore della soglia e nessun finding bloccante. Un report vuoto, fuori
    perimetro o malformato solleva ValueError: non produce mai un PASS.
    """
    expected = origin(expected_origin)
    if not isinstance(report, dict):
        raise ValueError("Il report ZAP non e' un oggetto JSON")
    sites = report.get("site")
    if not isinstance(sites, list) or not sites:
        raise ValueError("Report ZAP senza siti: scansione incompleta")
    findings = {}
    for site in sites:
        if origin(site.get("@name", "")) != expected:
            raise ValueError(f"Sito fuori perimetro nel report: {site.get('@name')!r}")
        for alert in site.get("alerts", []):
            risk = int(alert.get("riskcode", -1))
            if risk not in RISK_TO_SEVERITY:
                raise ValueError(f"Codice di rischio ZAP non valido: {risk}")
            for instance in alert.get("instances", []):
                uri = instance.get("uri")
                if uri and origin(uri) != expected:
                    raise ValueError(f"Istanza fuori perimetro nel report: {uri!r}")
            alert_ref = str(alert.get("alertRef") or "")
            plugin_id = str(alert.get("pluginid") or "")
            name = str(alert.get("name") or alert.get("alert") or "")
            key = alert_ref or plugin_id or name
            rule_blocking = alert_ref in BLOCKING_RULES or (
                plugin_id == "10038" and "Header Not Set" in name)
            confidence = int(alert.get("confidence", -1))
            # Le regole bloccanti valgono a qualunque livello di confidenza;
            # gli altri alert contano solo da confidenza Medium in su.
            if not rule_blocking and confidence < 2:
                continue
            severity = RISK_TO_SEVERITY[risk]
            entry = findings.setdefault(key, {"id": key, "title": name, "severity": severity,
                                              "rule_blocking": False})
            if WEIGHTS[severity] > WEIGHTS[entry["severity"]]:
                entry["severity"] = severity
            entry["rule_blocking"] = entry["rule_blocking"] or rule_blocking
    counts = {severity: 0 for severity in WEIGHTS}
    blocking = []
    for finding in findings.values():
        counts[finding["severity"]] += 1
        if finding["rule_blocking"]:
            reason = "regola bloccante per policy"
        elif finding["severity"] in BLOCKING_SEVERITIES:
            reason = "severita' bloccante"
        else:
            continue
        blocking.append({"id": finding["id"], "title": finding["title"],
                         "severity": finding["severity"], "reason": reason})
    score = max(0, 100 - sum(WEIGHTS[severity] * number for severity, number in counts.items()))
    status = "PASS" if score > THRESHOLD and not blocking else "FAIL"
    return {"gate": "dast-esterno", "status": status, "score": score, "threshold": THRESHOLD,
            "counts": counts, "blocking": blocking, "alert_rules": len(findings),
            "expected_origin": expected}


def describe(summary):
    prefix = SIMULATED_PREFIX if summary.get("simulated") else ""
    text = (f"{prefix}DAST esterno: {summary['status']} - score {summary['score']}/100 "
            f"(soglia {summary['threshold']}), bloccanti {len(summary['blocking'])}")
    return text[:DESCRIPTION_MAX]


# ----------------------------------------------------------------- GitHub

class GitHub:
    """Accesso minimo all'API di GitHub. Il token viaggia solo nell'intestazione HTTP."""

    def __init__(self, slug, token=None):
        self.slug = slug
        self.token = token

    def request(self, method, path, data=None):
        headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28",
                   "User-Agent": "dast-external-agent"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        body = json.dumps(data).encode("utf-8") if data is not None else None
        request = urllib.request.Request(API + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            detail = error.read().decode("utf-8", "replace")[:200]
            raise ApiError(f"HTTP {error.code} su {method} {path}: {detail}") from None
        except (urllib.error.URLError, OSError) as error:
            raise ApiError(f"GitHub non raggiungibile: {error}") from None
        return json.loads(raw) if raw.strip() else {}

    def open_pulls(self, base):
        return self.request("GET", f"/repos/{self.slug}/pulls?state=open&base={base}&per_page=100")

    def branch_head(self, branch):
        return self.request("GET", f"/repos/{self.slug}/branches/{branch}")["commit"]["sha"]

    def statuses(self, sha):
        return self.request("GET", f"/repos/{self.slug}/commits/{sha}/statuses?per_page=100")

    def check_runs(self, sha):
        return self.request("GET", f"/repos/{self.slug}/commits/{sha}/check-runs?per_page=100").get("check_runs", [])

    def set_status(self, sha, state, description, context=CONTEXT):
        return self.request("POST", f"/repos/{self.slug}/statuses/{sha}",
                            {"state": state, "context": context, "description": description[:DESCRIPTION_MAX]})


def candidates(gh, cfg):
    """Commit da controllare: testa delle pull request aperte, oppure testa di un branch."""
    if cfg["mode"] == "branch":
        return [{"sha": gh.branch_head(cfg["branch"]), "fetch_ref": cfg["branch"],
                 "label": f"branch {cfg['branch']}"}]
    found = []
    for pull in gh.open_pulls(cfg["base"]):
        head_repo = (pull.get("head", {}).get("repo") or {}).get("full_name", "")
        if head_repo.lower() != gh.slug.lower():
            # Il codice di un fork non viene mai costruito ne' eseguito su questa macchina.
            log(f"PR #{pull['number']} ignorata: proviene da un fork ({head_repo or 'sconosciuto'})")
            continue
        found.append({"sha": pull["head"]["sha"], "fetch_ref": f"refs/pull/{pull['number']}/head",
                      "label": f"PR #{pull['number']}"})
    return found


def needs_scan(gh, sha):
    """Vero se il commit non ha ancora un esito definitivo di questo agente.

    Uno stato rimasto in attesa (macchina spenta a meta' scansione) viene ripreso.
    """
    return stage_states(gh, sha).get(CONTEXT) not in FINAL_STATES


def stage_states(gh, sha):
    """Stato piu' recente scritto da questo agente per ogni stadio (DAST e PT).

    GitHub elenca gli stati dal piu' recente: per ogni contesto vale il primo incontrato.
    Un contesto mai scritto non compare nel risultato.
    """
    return {context: item.get("state") for context, item in stage_statuses(gh, sha).items()}


def stage_statuses(gh, sha):
    """Come stage_states, ma restituisce l'intero stato (con la descrizione) per ogni stadio."""
    latest = {}
    for item in gh.statuses(sha):
        context = item.get("context")
        if context in (CONTEXT, PT_CONTEXT) and context not in latest:
            latest[context] = item
    return latest


def required_checks_state(gh, sha, names):
    """Esito complessivo dei controlli che devono precedere il DAST.

    Restituisce (stato, nome): ("success", None) se tutti sono superati; la conclusione
    negativa e il nome del primo controllo non superato; altrimenti ("pending", nome del
    primo controllo non ancora concluso). Un controllo fallito prevale su uno in corso.
    """
    runs = gh.check_runs(sha)
    waiting = None
    for name in names:
        own = [item for item in runs if item.get("name") == name]
        latest = max(own, key=lambda item: item.get("id", 0)) if own else None
        if latest is None or latest.get("status") != "completed" or not latest.get("conclusion"):
            waiting = waiting or name
        elif latest["conclusion"] != "success":
            return latest["conclusion"], name
    return ("pending", waiting) if waiting else ("success", None)


def required_check_state(gh, sha, name):
    """Esito del controllo che deve precedere il DAST (per esempio il gate SAST).

    Restituisce "success", "pending" (non ancora concluso o non ancora avviato) oppure
    la conclusione negativa del controllo (failure, cancelled, skipped, ...).
    """
    runs = [item for item in gh.check_runs(sha) if item.get("name") == name]
    if not runs:
        return "pending"
    latest = max(runs, key=lambda item: item.get("id", 0))
    if latest.get("status") != "completed":
        return "pending"
    return latest.get("conclusion") or "pending"


# -------------------------------------------------------------- scansione

def run_cmd(cmd, cwd=None, env=None, timeout=None, check=True):
    log("  $ " + " ".join(str(part) for part in cmd))
    args = [str(part) for part in cmd]
    try:
        # Segnalazione di Semgrep rivista (regola dangerous-subprocess-use-audit): elenco di
        # argomenti senza shell; i comandi sono composti da questo programma e dalle opzioni
        # dell'operatore, mai da contenuto del repository.
        child = subprocess.Popen(args, cwd=cwd, env=env, text=True,  # nosemgrep
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except FileNotFoundError:
        raise ScanError(f"comando non trovato: {cmd[0]}") from None
    try:
        output, _ = child.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        # Prima SIGTERM: lo strumento puo' fermare i propri container. Poi SIGKILL.
        child.terminate()
        try:
            child.wait(timeout=TERMINATE_GRACE)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait()
        if child.stdout:
            child.stdout.close()
        raise ScanError(f"tempo massimo superato: {cmd[0]}") from None
    proc = CommandResult(child.returncode, output)
    if check and proc.returncode != 0:
        tail = "\n".join((proc.stdout or "").strip().splitlines()[-8:])
        raise ScanError(f"{cmd[0]} terminato con codice {proc.returncode}\n{tail}")
    return proc


def git_env(token):
    """Fa leggere a git il token da una variabile d'ambiente, per i repository privati."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    if token:
        handle, path = tempfile.mkstemp(prefix="dast-agent-askpass-", suffix=".sh")
        with os.fdopen(handle, "w") as script:
            script.write('#!/bin/sh\ncase "$1" in\n  Username*) echo "x-access-token" ;;\n'
                         '  *) echo "$DAST_AGENT_TOKEN" ;;\nesac\n')
        os.chmod(path, stat.S_IRWXU)
        atexit.register(lambda: os.path.exists(path) and os.remove(path))
        env.update(GIT_ASKPASS=path, DAST_AGENT_TOKEN=token)
    return env


def prepare_source(candidate, cfg, run):
    source = cfg["work_dir"] / "source"
    env = git_env(cfg.get("token"))
    git = ["git", "-c", "credential.helper="]
    if not (source / ".git").exists():
        cfg["work_dir"].mkdir(parents=True, exist_ok=True)
        run(git + ["clone", f"https://github.com/{cfg['slug']}.git", source], env=env, timeout=600)
    run(git + ["fetch", "origin", candidate["fetch_ref"]], cwd=source, env=env, timeout=600)
    run(["git", "checkout", "--force", "--detach", candidate["sha"]], cwd=source)
    head = run(["git", "rev-parse", "HEAD"], cwd=source).stdout.strip()
    if head != candidate["sha"]:
        raise ScanError(f"commit scaricato {head[:7]} diverso da quello atteso {candidate['sha'][:7]}")
    return source


def http_ok(url):
    """Vero se l'indirizzo risponde. Non usa proxy: l'applicazione e' sulla stessa macchina."""
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=10) as response:
            return 200 <= response.status < 400
    except (urllib.error.URLError, OSError, ValueError):
        return False


def zap_plan(target, report_dir):
    """Piano dell'Automation Framework per lo ZAP installato: spider e scansione passiva.

    Equivale a ZAP Baseline: nessun job di scansione attiva. E' scritto come JSON, che e'
    anche YAML valido.
    """
    base = origin(target)
    reports = [{"type": "report", "parameters": {
        "template": template, "reportDir": str(report_dir), "reportFile": name,
        "reportTitle": "DAST esterno - ZAP passivo"}}
        for template, name in (("traditional-json", "zap.json"), ("traditional-html", "zap.html"))]
    return {
        "env": {
            "contexts": [{"name": "dast-agent", "urls": [target], "includePaths": [re.escape(base) + ".*"]}],
            "parameters": {"failOnError": True, "failOnWarning": False, "progressToStdout": True},
        },
        "jobs": [
            {"type": "passiveScan-config", "parameters": {"scanOnlyInScope": True}},
            {"type": "spider", "parameters": {"context": "dast-agent", "maxDuration": 1}},
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
        ] + reports,
    }


def check_zap_addons(zap_cmd, zap_home):
    """Verifica che le regole passive dello ZAP installato siano presenti e integre.

    Con le regole mancanti o corrotte ZAP termina senza errori e produce un report senza
    alert: il controllo evita che quel report diventi un esito positivo.
    """
    found = shutil.which(str(zap_cmd))
    if not found:
        raise ScanError(f"comando ZAP non trovato: {zap_cmd}")
    folders = [Path(found).resolve().parent / "plugin", Path(zap_home) / "plugin"]
    for addon in REQUIRED_ZAP_ADDONS:
        files = [item for folder in folders if folder.is_dir() for item in folder.glob(f"{addon}-*.zap")]
        if not files:
            raise ScanError(f"add-on ZAP mancante: {addon} (regole passive non disponibili)")
        for item in files:
            try:
                with zipfile.ZipFile(item) as archive:
                    damaged = archive.testzip()
            except (zipfile.BadZipFile, OSError):
                damaged = item.name
            if damaged:
                raise ScanError(f"add-on ZAP corrotto: {item}")
    return found


def run_local_zap(target, report_dir, cfg, run):
    """Scansione passiva con lo ZAP installato sulla macchina, in una home dedicata all'agente."""
    zap = check_zap_addons(cfg["zap_cmd"], cfg["zap_home"])
    Path(cfg["zap_home"]).mkdir(parents=True, exist_ok=True)
    plan = report_dir / "zap-plan.yaml"
    plan.write_text(json.dumps(zap_plan(target, report_dir), indent=2) + "\n", encoding="utf-8")
    run([zap, "-cmd", "-silent", "-dir", cfg["zap_home"], "-autorun", plan], check=False, timeout=1500)


def publish_override(cfg):
    """File Compose aggiuntivo: pubblica l'applicazione solo su 127.0.0.1, su una porta libera.

    Serve allo ZAP installato, che non e' nella rete Docker. Il file sta nella cartella di
    lavoro dell'agente: il repository non viene modificato.
    """
    parts = urlsplit(cfg["target"])
    service, port = parts.hostname, parts.port or 80
    override = cfg["work_dir"] / "compose.dast-agent.json"
    override.write_text(json.dumps({"services": {service: {"ports": [f"127.0.0.1::{port}"]}}}) + "\n",
                        encoding="utf-8")
    return override, service, port


def scan_commit(candidate, cfg, run=run_cmd, sleep=time.sleep, reachable=http_ok):
    """Avvia l'applicazione del commit (oppure usa un indirizzo gia' attivo), esegue ZAP e valuta."""
    local_zap = bool(cfg.get("zap_cmd"))
    report_dir = cfg["reports_dir"] / candidate["sha"]
    report_dir.mkdir(parents=True, exist_ok=True)
    if not local_zap:
        os.chmod(report_dir, 0o777)  # ZAP in Docker scrive nel volume come utente 1000
    for name in ("zap.json", "zap.html"):
        if (report_dir / name).exists():
            (report_dir / name).unlink()
    target = cfg["target_url"] or cfg["target"]
    zap = ["docker", "run", "--rm"]
    compose = None
    try:
        if not cfg["target_url"]:
            source = prepare_source(candidate, cfg, run)
            compose = ["docker", "compose", "-p", "dast-agent", "-f", cfg["compose_file"]]
            if local_zap:
                override, service, port = publish_override(cfg)
                compose += ["-f", override]
            log("  Avvio dell'applicazione del commit in Docker")
            run(compose + ["up", "-d", "--build", "--wait"], cwd=source, timeout=900)
            if local_zap:
                published = run(compose + ["port", service, port], cwd=source, timeout=60).stdout.strip()
                if not re.fullmatch(r"127\.0\.0\.1:\d+", published):
                    raise ScanError(f"porta pubblicata non riconosciuta: {published!r}")
                target = f"http://{published}"
            for attempt in range(25):
                if local_zap:
                    healthy = reachable(target.rstrip("/") + cfg["health_path"])
                else:
                    healthy = run(["docker", "run", "--rm", "--network", cfg["network"], CURL_IMAGE,
                                   "-fsS", target.rstrip("/") + cfg["health_path"]],
                                  check=False, timeout=60).returncode == 0
                if healthy:
                    break
                sleep(2)
            else:
                raise ScanError("l'applicazione non risponde al controllo di salute")
            zap += ["--network", cfg["network"]]
        if local_zap:
            log(f"  Scansione passiva di {target} con lo ZAP installato ({cfg['zap_cmd']})")
            run_local_zap(target, report_dir, cfg, run)
        else:
            log(f"  Scansione ZAP Baseline di {target}")
            run(zap + ["-v", f"{report_dir}:/zap/wrk:rw", cfg["zap_image"], "zap-baseline.py",
                       "-t", target, "-m", "1", "-I", "-T", "5", "-J", "zap.json", "-r", "zap.html"],
                check=False, timeout=1500)
    finally:
        if compose:
            try:
                run(compose + ["down", "--volumes", "--remove-orphans"], cwd=cfg["work_dir"] / "source",
                    check=False, timeout=300)
            except ScanError as error:
                log(f"  Arresto dei container non riuscito: {error}")
    report_file = report_dir / "zap.json"
    if not report_file.is_file() or report_file.stat().st_size == 0:
        raise ScanError("ZAP non ha prodotto il report JSON")
    try:
        summary = evaluate(json.loads(report_file.read_text(encoding="utf-8")), target)
    except (ValueError, TypeError) as error:
        raise ScanError(f"report ZAP non valido: {error}") from None
    summary.update(commit=candidate["sha"], source=candidate["label"], report_dir=str(report_dir),
                   zap="installato" if local_zap else "docker")
    (report_dir / "dast-external-gate.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


# Alert del report ZAP reale del test C (12 novembre 2026): base del report sintetico.
SIMULATED_ALERTS = (
    ("10055-13", "10055", 2, 3, "CSP: Failure to Define Directive with No Fallback"),
    ("90004-1", "90004", 1, 2, "Cross-Origin-Resource-Policy Header Missing or Invalid"),
    ("90004-2", "90004", 1, 2, "Cross-Origin-Embedder-Policy Header Missing or Invalid"),
    ("90004-3", "90004", 1, 2, "Cross-Origin-Opener-Policy Header Missing or Invalid"),
    ("10063-1", "10063", 1, 2, "Permissions Policy Header Not Set"),
    ("10021", "10021", 1, 2, "X-Content-Type-Options Header Missing"),
    ("10049-3", "10049", 0, 2, "Storable and Cacheable Content"),
)
SIMULATED_CSP_OFF = (
    ("10038-1", "10038", 2, 3, "Content Security Policy (CSP) Header Not Set"),
    ("10020-1", "10020", 2, 2, "Missing Anti-clickjacking Header"),
)


def synthetic_report(csp_disabled, target):
    """Report nel formato di ZAP costruito senza eseguire ZAP: serve solo alla simulazione."""
    rows = list(SIMULATED_ALERTS)
    if csp_disabled:
        rows = list(SIMULATED_CSP_OFF) + [row for row in rows if row[0] != "10055-13"]
    alerts = [{"alertRef": ref, "pluginid": plugin, "riskcode": str(risk), "confidence": str(confidence),
               "name": name, "instances": [{"uri": target.rstrip("/") + "/"}]}
              for ref, plugin, risk, confidence, name in rows]
    return {"@simulated": True, "@note": "Report sintetico: ZAP non e' stato eseguito",
            "site": [{"@name": target, "alerts": alerts}]}


def simulate_scan(candidate, cfg, run=run_cmd):
    """Simulazione senza Docker e senza ZAP.

    Scarica davvero il commit e legge il file Compose: se l'header CSP risulta disattivato
    produce un report sintetico con la CSP mancante, altrimenti uno conforme. Polling,
    attesa del SAST e scrittura dello stato su GitHub restano reali.
    """
    report_dir = cfg["reports_dir"] / candidate["sha"]
    report_dir.mkdir(parents=True, exist_ok=True)
    source = prepare_source(candidate, cfg, run)
    try:
        compose_text = (source / cfg["compose_file"]).read_text(encoding="utf-8")
    except OSError as error:
        raise ScanError(f"file Compose non leggibile: {error}") from None
    csp_disabled = re.search(r"ENABLE_CSP:\s*['\"]?false", compose_text) is not None
    log(f"  SIMULAZIONE: nessuna scansione reale; header CSP nel commit: "
        f"{'disattivato' if csp_disabled else 'attivo'}")
    report = synthetic_report(csp_disabled, cfg["target"])
    (report_dir / "zap.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    summary = evaluate(report, cfg["target"])
    summary.update(simulated=True, commit=candidate["sha"], source=candidate["label"], report_dir=str(report_dir))
    (report_dir / "dast-external-gate.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


# ------------------------------------------------------------ PT agentico

def evaluate_pentest(findings):
    """Score ed esito dai finding di Strix (contenuto di vulnerabilities.json).

    Stessa formula del DAST: ogni finding pesa secondo la severita'; High e Critical
    bloccano. Un elenco illeggibile o una severita' sconosciuta sollevano ValueError:
    non producono mai un PASS.
    """
    if not isinstance(findings, list):
        raise ValueError("l'elenco dei finding non e' una lista")
    counts = {severity: 0 for severity in WEIGHTS}
    blocking = []
    for item in findings:
        if not isinstance(item, dict):
            raise ValueError("un finding non e' un oggetto JSON")
        severity = str(item.get("severity") or "").strip().lower()
        severity = "info" if severity == "none" else severity
        if severity not in WEIGHTS:
            raise ValueError(f"severita' del finding non riconosciuta: {item.get('severity')!r}")
        counts[severity] += 1
        if severity in BLOCKING_SEVERITIES:
            blocking.append({"id": str(item.get("id") or ""), "title": " ".join(str(item.get("title") or "").split())[:160],
                             "severity": severity, "reason": "severita' bloccante"})
    score = max(0, 100 - sum(WEIGHTS[severity] * number for severity, number in counts.items()))
    status = "PASS" if score > THRESHOLD and not blocking else "FAIL"
    return {"gate": "pt-agentico", "tool": "strix", "status": status, "score": score, "threshold": THRESHOLD,
            "counts": counts, "blocking": blocking, "findings": len(findings)}


def describe_pentest(summary):
    prefix = SIMULATED_PREFIX if summary.get("simulated") else ""
    text = (f"{prefix}PT agentico: {summary['status']} - score {summary['score']}/100 "
            f"(soglia {summary['threshold']}), bloccanti {len(summary['blocking'])}, finding {summary['findings']}")
    return text[:DESCRIPTION_MAX]


def save_pentest_summary(summary, candidate, cfg, **extra):
    report_dir = cfg["reports_dir"] / candidate["sha"]
    report_dir.mkdir(parents=True, exist_ok=True)
    summary.update(commit=candidate["sha"], source=candidate["label"], report_dir=str(report_dir), **extra)
    (report_dir / "pentest-gate.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def pentest_source_copy(candidate, cfg, copy, run):
    """Copia usa e getta del commit, per l'analisi a scatola aperta.

    Strix monta la cartella in scrittura: lavorando sulla copia, nulla di cio' che vi
    lascia puo' entrare nelle build DAST dei commit successivi.
    """
    source = prepare_source(candidate, cfg, run)
    run(["git", "worktree", "prune"], cwd=source, check=False)
    if copy.exists():
        shutil.rmtree(copy)
    run(["git", "worktree", "add", "--force", "--detach", copy, candidate["sha"]], cwd=source, timeout=300)
    head = run(["git", "rev-parse", "HEAD"], cwd=copy).stdout.strip()
    if head != candidate["sha"]:
        raise ScanError(f"copia del sorgente sul commit {head[:7]}, atteso {candidate['sha'][:7]}")
    return source


def read_strix_run(runs_dir, returncode):
    """Finding di una esecuzione conclusa di Strix. ScanError se l'esecuzione non e' completa."""
    run_dirs = sorted(item for item in runs_dir.iterdir() if item.is_dir()) if runs_dir.is_dir() else []
    if len(run_dirs) != 1:
        raise ScanError(f"attesa una cartella di risultati di Strix, trovate {len(run_dirs)}")
    run_dir = run_dirs[0]
    try:
        record = json.loads((run_dir / STRIX_RUN_RECORD).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise ScanError(f"{STRIX_RUN_RECORD} di Strix assente o illeggibile") from None
    status = record.get("status") if isinstance(record, dict) else None
    if status != STRIX_COMPLETED:
        raise ScanError(f"scansione di Strix non completata (stato: {status or 'sconosciuto'})")
    findings_file = run_dir / "vulnerabilities.json"
    if findings_file.is_file():
        try:
            return run_dir, json.loads(findings_file.read_text(encoding="utf-8"))
        except ValueError as error:
            raise ScanError(f"vulnerabilities.json non valido: {error}") from None
    if returncode == 2:
        raise ScanError("Strix segnala finding ma vulnerabilities.json manca")
    return run_dir, []  # Strix scrive il file solo quando ci sono finding


def run_pentest(candidate, cfg, run=run_cmd):
    """Esegue Strix senza interfaccia sul bersaglio e ne valuta i finding.

    Bersaglio: l'indirizzo di --target-url (test a scatola chiusa) oppure una copia usa e
    getta del sorgente al commit (analisi a scatola aperta nel sandbox di Strix).
    Strix termina con 0 o 2 anche quando la scansione non e' completa: l'esito vale solo
    se run.json riporta lo stato "completed".
    """
    stage_dir = cfg["reports_dir"] / candidate["sha"] / "pentest"
    runs_dir = stage_dir / STRIX_RUNS_DIR
    if runs_dir.exists():
        shutil.rmtree(runs_dir)  # i risultati di un'esecuzione precedente non devono essere riletti
    stage_dir.mkdir(parents=True, exist_ok=True)
    mode = cfg.get("pentest_mode") or PENTEST_MODES[0]
    copy, source = stage_dir / "source", None
    try:
        if cfg.get("target_url"):
            target = label = cfg["target_url"]
            cmd = [cfg["pentest_cmd"], "-n", "-t", target, "--scan-mode", mode]
        else:
            source = pentest_source_copy(candidate, cfg, copy, run)
            target, label = str(copy), "sorgente del commit (copia temporanea)"
            # full: tutto il commit, non solo le righe cambiate.
            cmd = [cfg["pentest_cmd"], "-n", "-t", target, "--scan-mode", mode, "--scope-mode", "full"]
        if cfg.get("pentest_budget"):
            cmd += ["--max-budget-usd", str(cfg["pentest_budget"])]
        env = {key: value for key, value in os.environ.items() if key not in SECRET_ENV}
        env.setdefault("STRIX_TELEMETRY", "0")
        log(f"  PT agentico con Strix su {label} (modalita' {mode})")
        proc = run(cmd, cwd=stage_dir, env=env, timeout=int(cfg.get("pentest_timeout") or 60) * 60, check=False)
    finally:
        if source is not None or copy.exists():
            shutil.rmtree(copy, ignore_errors=True)
        if source is not None:
            try:
                run(["git", "worktree", "prune"], cwd=source, check=False)
            except ScanError as error:
                log(f"  Pulizia della copia del sorgente non riuscita: {error}")
    if proc.returncode not in (0, 2):
        tail = "; ".join((proc.stdout or "").strip().splitlines()[-2:])
        raise ScanError(f"Strix terminato con codice {proc.returncode}" + (f": {tail}" if tail else ""))
    run_dir, findings = read_strix_run(runs_dir, proc.returncode)
    try:
        summary = evaluate_pentest(findings)
    except ValueError as error:
        raise ScanError(f"report di Strix non valido: {error}") from None
    return save_pentest_summary(summary, candidate, cfg, target=label, mode=mode, run_dir=str(run_dir))


def simulate_pentest(candidate, cfg, run=run_cmd):
    """Simulazione: Strix non viene eseguito; esito senza finding con dicitura [SIMULATO]."""
    log("  SIMULAZIONE: nessun penetration test reale")
    summary = evaluate_pentest([])
    summary["simulated"] = True
    target = cfg.get("target_url") or cfg.get("target")
    return save_pentest_summary(summary, candidate, cfg, target=target, mode=cfg.get("pentest_mode") or PENTEST_MODES[0])


def process_pentest(gh, candidate, cfg, pentest=run_pentest):
    """Esegue il PT agentico su un commit e scrive l'esito su GitHub. Restituisce lo stato scritto."""
    sha = candidate["sha"]
    log(f"PT agentico sul commit {sha[:7]} ({candidate['label']})")
    gh.set_status(sha, "pending", "PT agentico in corso sulla macchina esterna", context=PT_CONTEXT)
    try:
        summary = pentest(candidate, cfg)
    except (ScanError, ValueError, OSError) as error:
        reason = (str(error).splitlines() or ["errore"])[0]
        log(f"  PT agentico non completato: {error}")
        gh.set_status(sha, "error", f"PT agentico non completato: {reason}", context=PT_CONTEXT)
        return "error"
    state = "success" if summary["status"] == "PASS" else "failure"
    log(f"  Esito: {describe_pentest(summary)}")
    for item in summary["blocking"]:
        log(f"    bloccante: {item['id']} - {item['title']} ({item['severity']})")
    log(f"  Report salvati in {summary.get('report_dir')}")
    gh.set_status(sha, state, describe_pentest(summary), context=PT_CONTEXT)
    return state


def process(gh, candidate, cfg, scan=scan_commit):
    """Scansiona un commit e scrive l'esito su GitHub. Restituisce lo stato scritto."""
    sha = candidate["sha"]
    log(f"Nuovo commit da controllare: {sha[:7]} ({candidate['label']})")
    gh.set_status(sha, "pending", "Scansione ZAP in corso sulla macchina esterna")
    try:
        summary = scan(candidate, cfg)
    except (ScanError, ValueError, OSError) as error:
        reason = str(error).splitlines()[0]
        log(f"  Scansione non completata: {error}")
        gh.set_status(sha, "error", f"DAST esterno non completato: {reason}")
        return "error"
    state = "success" if summary["status"] == "PASS" else "failure"
    log(f"  Esito: {describe(summary)}")
    for item in summary["blocking"]:
        log(f"    bloccante: {item['id']} - {item['title']} ({item['reason']})")
    log(f"  Report salvati in {summary['report_dir']}")
    gh.set_status(sha, state, describe(summary))
    return state


def required_names(cfg):
    required = cfg.get("require_check")
    return [required] if isinstance(required, str) else list(required or [])


def dast_stage(gh, candidate, cfg, scan, done):
    """Stadio DAST di un commit senza esito definitivo.

    Restituisce lo stato definitivo scritto, oppure None se il commit resta in attesa
    (controlli precedenti non conclusi) o se l'agente e' in modalita' di prova.
    """
    sha, label = candidate["sha"], candidate["label"]
    names = required_names(cfg)
    if names:
        # Il DAST parte solo dopo i controlli precedenti: se uno e' fallito non si scansiona.
        previous, name = required_checks_state(gh, sha, names)
        if previous == "pending":
            if sha not in cfg.setdefault("waiting", set()):
                cfg["waiting"].add(sha)
                log(f"{sha[:7]} ({label}): in attesa di '{name}'")
            return None
        if previous != "success":
            log(f"{sha[:7]} ({label}): '{name}' non superato ({previous}), DAST non eseguito")
            if cfg["dry_run"]:
                cfg["seen_dry"].add(sha)
                return None
            gh.set_status(sha, "failure", f"DAST esterno non eseguito: '{name}' non superato ({previous})")
            done.append((sha, "not-run"))
            return "failure"
    if cfg["dry_run"]:
        then = "; poi il PT agentico se il DAST e' superato" if cfg.get("pentest_cmd") else ""
        log(f"[prova] scansionerei {sha[:7]} ({label}){then}; nessuna azione eseguita")
        cfg["seen_dry"].add(sha)
        done.append((sha, "dry-run"))
        return None
    state = process(gh, candidate, cfg, scan)
    done.append((sha, state))
    return state


def pentest_stage(gh, candidate, cfg, pentest, dast, done, simulated_dast=False):
    """Stadio PT di un commit con DAST definitivo e PT senza esito definitivo."""
    sha, label = candidate["sha"], candidate["label"]
    # Il PT parte solo dopo un DAST superato; un DAST simulato non autorizza un PT reale.
    reason = None
    if dast != "success":
        reason = f"DAST esterno non superato ({dast})"
    elif simulated_dast and not cfg.get("simulate"):
        reason = "il DAST esterno era simulato"
    if cfg["dry_run"]:
        action = "segnerei come non eseguito il PT agentico di" if reason else "eseguirei il PT agentico su"
        log(f"[prova] {action} {sha[:7]} ({label}); nessuna azione eseguita")
        cfg["seen_dry"].add(sha)
        done.append((sha, "dry-run-pt"))
    elif reason:
        log(f"{sha[:7]} ({label}): {reason}, PT agentico non eseguito")
        gh.set_status(sha, "failure", f"PT agentico non eseguito: {reason}", context=PT_CONTEXT)
        done.append((sha, "pt-not-run"))
    else:
        done.append((sha, "pt-" + process_pentest(gh, candidate, cfg, pentest)))


def poll_once(gh, cfg, scan=scan_commit, pentest=run_pentest):
    """Un giro di controllo. Restituisce l'elenco di (sha, stato) degli stadi trattati.

    Per ogni commit: prima il DAST, se non ha gia' un esito definitivo; poi, solo con
    --pentest-cmd, il PT agentico, se il DAST e' definitivo e il PT non lo e' ancora.
    Gli stati del PT sono riportati con il prefisso "pt-".
    """
    done = []
    for candidate in candidates(gh, cfg):
        sha = candidate["sha"]
        if sha in cfg.setdefault("seen_dry", set()):
            continue
        statuses = stage_statuses(gh, sha)
        previous = statuses.get(CONTEXT) or {}
        dast = previous.get("state")
        simulated_dast = str(previous.get("description") or "").startswith(SIMULATED_PREFIX)
        if dast not in FINAL_STATES:
            dast = dast_stage(gh, candidate, cfg, scan, done)
            simulated_dast = bool(cfg.get("simulate"))
        if not cfg.get("pentest_cmd") or dast not in FINAL_STATES:
            continue
        if (statuses.get(PT_CONTEXT) or {}).get("state") not in FINAL_STATES:
            pentest_stage(gh, candidate, cfg, pentest, dast, done, simulated_dast)
    return done


def build_config(args, token):
    home = Path(args.work_dir).expanduser().resolve()
    return {
        "pentest_cmd": args.pentest_cmd, "pentest_mode": args.pentest_mode,
        "pentest_budget": args.pentest_budget, "pentest_timeout": args.pentest_timeout,
        "slug": args.repo, "token": token, "mode": "branch" if args.branch else "pr",
        "base": args.base, "branch": args.branch, "dry_run": args.dry_run,
        "work_dir": home, "reports_dir": home / "reports",
        "compose_file": args.compose_file, "network": args.network, "target": args.target,
        "target_url": args.target_url, "health_path": args.health_path, "zap_image": args.zap_image,
        "require_check": args.require_check, "simulate": args.simulate,
        "zap_cmd": args.zap_cmd,
        "zap_home": Path(args.zap_home).expanduser().resolve() if args.zap_home else home / "zap-home",
    }


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description="Agente esterno: ZAP e PT agentico su macchina interna, esito su GitHub.")
    parser.add_argument("--repo", required=True, help="repository GitHub, nella forma owner/nome")
    parser.add_argument("--base", default="main", help="controlla le pull request aperte verso questo branch (default: main)")
    parser.add_argument("--branch", help="in alternativa: controlla la testa di questo branch (per esempio test)")
    parser.add_argument("--require-check", metavar="NOME", action="append",
                        help="scansiona solo i commit su cui questo check di GitHub e' superato "
                             "(per esempio \"01 SAST - CodeQL and High gate\"); ripetibile: "
                             "devono essere superati tutti")
    parser.add_argument("--pentest-cmd", metavar="COMANDO",
                        help="abilita il PT agentico dopo un DAST superato, con questo comando di Strix "
                             "(per esempio strix); scrive lo stato \"PT AGENTICO (STRIX)\"")
    parser.add_argument("--pentest-authorized", action="store_true",
                        help="dichiaro di avere l'autorizzazione scritta a eseguire test attivi sul bersaglio; "
                             "obbligatoria con --pentest-cmd")
    parser.add_argument("--pentest-mode", choices=PENTEST_MODES, default=PENTEST_MODES[0],
                        help="profondita' del PT (default: quick)")
    parser.add_argument("--pentest-budget", type=float, metavar="USD",
                        help="spesa massima per esecuzione verso il modello, in dollari")
    parser.add_argument("--pentest-timeout", type=int, default=60, metavar="MINUTI",
                        help="tempo massimo di una esecuzione del PT (default: 60)")
    parser.add_argument("--interval", type=int, default=30, help="secondi tra un controllo e l'altro (default: 30)")
    parser.add_argument("--once", action="store_true", help="un solo controllo, poi termina")
    parser.add_argument("--dry-run", action="store_true", help="mostra cosa farebbe, senza scansioni ne' scritture")
    parser.add_argument("--simulate", action="store_true",
                        help="simulazione: nessun Docker e nessuno ZAP, esito ricavato dal commit; lo stato su GitHub e' reale")
    parser.add_argument("--work-dir", default="~/appsec-dast-agent", help="cartella di lavoro e dei report")
    parser.add_argument("--target-url", help="scansiona un'applicazione gia' attiva a questo indirizzo, senza costruirla")
    parser.add_argument("--compose-file", default="compose.test.yml", help="file Compose del repository (default: compose.test.yml)")
    parser.add_argument("--network", default="appsec-unified-ci", help="rete Docker creata dal file Compose")
    parser.add_argument("--target", default="http://app:3000", help="indirizzo dell'applicazione nella rete Docker")
    parser.add_argument("--health-path", default="/health", help="percorso del controllo di salute")
    parser.add_argument("--zap-image", default=ZAP_IMAGE, help="immagine Docker di ZAP")
    parser.add_argument("--zap-cmd", metavar="COMANDO",
                        help="usa lo ZAP installato sulla macchina (per esempio /usr/local/bin/zap) "
                             "invece dell'immagine Docker; scansione solo passiva")
    parser.add_argument("--zap-home", metavar="CARTELLA",
                        help="cartella dati di ZAP usata dall'agente con --zap-cmd "
                             "(default: zap-home nella cartella di lavoro)")
    args = parser.parse_args(argv)
    if args.repo.count("/") != 1:
        parser.error("--repo deve avere la forma owner/nome")
    if args.pentest_budget is not None and args.pentest_budget <= 0:
        parser.error("--pentest-budget deve essere maggiore di zero")
    if args.pentest_timeout <= 0:
        parser.error("--pentest-timeout deve essere maggiore di zero")
    if args.pentest_cmd and not (args.pentest_authorized or args.dry_run or args.simulate):
        parser.error("--pentest-cmd esegue test attivi: aggiungi --pentest-authorized solo se hai "
                     "l'autorizzazione scritta a testare il bersaglio")
    return args


def main(argv=None):
    args = parse_args(argv)

    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if not token and not args.dry_run:
        token = getpass.getpass("Token GitHub (non viene mostrato): ").strip()
        if not token:
            print("ERRORE: token mancante.")
            return 1
    cfg = build_config(args, token)
    gh = GitHub(args.repo, token)

    watched = f"branch {args.branch}" if args.branch else f"pull request aperte verso {args.base}"
    log(f"Agente DAST esterno avviato su {args.repo}: {watched}")
    log(f"Stato scritto su GitHub: '{CONTEXT}'; soglia score: maggiore di {THRESHOLD}")
    if args.require_check:
        log("Il DAST parte solo dopo i check superati: " + ", ".join(f"'{name}'" for name in args.require_check))
    if args.zap_cmd and not args.simulate:
        log(f"ZAP installato sulla macchina: {args.zap_cmd}; cartella dati dedicata: {cfg['zap_home']}")
    if args.pentest_cmd:
        where = args.target_url or "sorgente del commit (scatola aperta)"
        log(f"PT agentico abilitato: stato '{PT_CONTEXT}', comando {args.pentest_cmd}, "
            f"modalita' {args.pentest_mode}, bersaglio {where}")
        if not (args.simulate or args.dry_run or os.environ.get("STRIX_LLM")):
            log("ATTENZIONE: STRIX_LLM non e' impostata; Strix usera' la propria configurazione salvata, se esiste")
    if args.simulate:
        log("SIMULAZIONE: ZAP e Strix non vengono eseguiti; gli stati scritti su GitHub portano la dicitura [SIMULATO]")
    if args.dry_run:
        log("Modalita' di prova: nessuna scansione e nessuna scrittura su GitHub")
    scan = simulate_scan if args.simulate else scan_commit
    pentest = simulate_pentest if args.simulate else run_pentest
    while True:
        try:
            poll_once(gh, cfg, scan, pentest)
        except ApiError as error:
            log(f"Controllo saltato: {error}")
            if args.once:
                return 1
        if args.once:
            return 0
        time.sleep(args.interval)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nAgente fermato.")
        sys.exit(130)
