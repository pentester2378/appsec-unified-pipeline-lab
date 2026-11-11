#!/usr/bin/env python3
"""Evaluate same-run ZAP traditional JSON report for the unified PoC.

A missing-CSP alert (10038-1) is deliberately blocking for this demo even
though its native severity is Medium. High alerts at Medium+ confidence block.
This is a lab policy, not an enterprise release policy.
"""
import argparse
import json
import sys
from pathlib import Path
from urllib.parse import urlsplit


def origin(url):
    p = urlsplit(url)
    if p.scheme not in ('http', 'https') or not p.netloc:
        raise ValueError(f'Invalid report URL: {url}')
    return f'{p.scheme}://{p.netloc.lower()}'


def evaluate(report, expected_origin):
    expected = origin(expected_origin)
    if not isinstance(report, dict):
        raise ValueError('ZAP report must be an object')
    sites = report.get('site')
    if not isinstance(sites, list) or not sites:
        raise ValueError('No site in ZAP report; incomplete scan must not PASS')
    blocking = []
    counted = 0
    for site in sites:
        site_name = site.get('@name', '')
        if origin(site_name) != expected:
            raise ValueError(f'Out-of-scope site: {site_name}')
        for a in site.get('alerts', []):
            counted += 1
            plugin_id = str(a.get('pluginid') or '')
            alert_ref = str(a.get('alertRef') or '')
            title = str(a.get('name') or a.get('alert') or '')
            risk = int(a.get('riskcode', -1))
            confidence = int(a.get('confidence', -1))
            if risk not in range(0, 5):
                raise ValueError(f'Invalid ZAP risk code: {risk}')
            # A CSP alert can be 10038-1, -2, or -3: block only missing CSP.
            missing_csp = (alert_ref == '10038-1' or
                           (plugin_id == '10038' and 'Header Not Set' in title))
            high_verified = risk >= 3 and confidence >= 2
            for instance in a.get('instances', []):
                uri = instance.get('uri')
                if uri and origin(uri) != expected:
                    raise ValueError(f'Out-of-scope instance: {uri}')
            if missing_csp or high_verified:
                blocking.append({'plugin': plugin_id, 'alertRef': alert_ref,
                                 'title': title, 'riskcode': risk,
                                 'reason': 'CSP lab policy' if missing_csp else 'High+ at Medium+ confidence'})
    return {'status': 'FAIL' if blocking else 'PASS', 'site_count': len(sites),
            'alert_rules': counted, 'blocking': blocking, 'expected_origin': expected}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--report', required=True, type=Path)
    ap.add_argument('--expected-origin', required=True)
    ap.add_argument('--summary', type=Path, default=Path('reports/dast-gate.json'))
    a = ap.parse_args()
    try:
        r = evaluate(json.loads(a.report.read_text(encoding='utf-8')), a.expected_origin)
        a.summary.parent.mkdir(parents=True, exist_ok=True)
        a.summary.write_text(json.dumps(r, indent=2) + '\n', encoding='utf-8')
        print(f'DAST GATE: {r["status"]}; blocking: {len(r["blocking"])}; alert rules: {r["alert_rules"]}')
        for entry in r['blocking']:
            print(f'::error::ZAP {entry["alertRef"] or entry["plugin"]}: {entry["title"]}')
        return 2 if r['blocking'] else 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError) as e:
        print(f'::error::DAST gate INVALID: {e}')
        return 3


if __name__ == '__main__':
    sys.exit(main())
