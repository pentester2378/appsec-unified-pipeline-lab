#!/usr/bin/env python3
"""Fail a CI job if CodeQL SARIF contains any high/critical security finding.

This PoC gate reads the *same run's SARIF*, not the GitHub alert dashboard.
Production: integrate baseline/accepted-risk decisions, PR-new-alert logic,
and the organisation's native Code Scanning merge protection ruleset.
"""
import argparse
import json
import sys
from pathlib import Path

HIGH_CVSS = 7.0


def find_blocking(sarif):
    if sarif.get('version') != '2.1.0' or not sarif.get('runs'):
        raise ValueError('Missing SARIF v2.1.0 runs')
    blocked = []
    for run in sarif['runs']:
        tool = run.get('tool', {})
        if not tool.get('driver'):
            raise ValueError('SARIF run has no tool.driver')
        rules = {}
        for group in [tool.get('driver', {}), *tool.get('extensions', [])]:
            for rule in group.get('rules', []):
                if rule.get('id'):
                    rules[rule['id']] = rule
        for result in run.get('results', []):
            rule_id = result.get('ruleId')
            if not rule_id:
                raise ValueError('Result without ruleId; cannot evaluate severity')
            rule = rules.get(rule_id)
            if not rule:
                raise ValueError(f'Result rule not declared in SARIF: {rule_id}')
            props = rule.get('properties', {})
            raw = props.get('security-severity')
            if raw is None:
                # Non-security warnings are not blocked by this security policy.
                continue
            try:
                severity = float(raw)
            except (ValueError, TypeError):
                raise ValueError(f'Invalid security-severity for {rule_id}: {raw}') from None
            if severity >= HIGH_CVSS:
                blocked.append({'rule': rule_id, 'security_severity': severity,
                                'message': result.get('message', {}).get('text', '')[:240]})
    return blocked


def run(path):
    files = [path] if path.is_file() else sorted(path.rglob('*.sarif'))
    if not files:
        raise ValueError(f'No SARIF files found at {path}; cannot report PASS')
    all_blocking = []
    for f in files:
        all_blocking.extend(find_blocking(json.loads(f.read_text(encoding='utf-8'))))
    return {'status': 'FAIL' if all_blocking else 'PASS', 'sarif_files': len(files),
            'blocking': all_blocking, 'threshold_cvss': HIGH_CVSS}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--sarif', required=True, type=Path, help='Directory or file emitted by CodeQL analyze')
    ap.add_argument('--summary', type=Path, default=Path('reports/sast-gate.json'))
    args = ap.parse_args()
    try:
        result = run(args.sarif)
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
        print(f'SAST GATE: {result["status"]}; blocking High/Critical: {len(result["blocking"])}')
        for entry in result['blocking']:
            print(f'::error::CodeQL {entry["rule"]}: {entry["security_severity"]} CVSS')
        return 2 if result['blocking'] else 0
    except (ValueError, OSError, TypeError, KeyError, json.JSONDecodeError) as ex:
        print(f'::error::SAST gate INVALID: {ex}')
        return 3


if __name__ == '__main__':
    sys.exit(main())
