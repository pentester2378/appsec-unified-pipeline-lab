#!/usr/bin/env python3
"""Change the committed PoC files for one of the three GitHub PR test cases.

Scenario A intentionally creates an SQL injection in a private test branch.
Scenario B disables CSP at runtime via Docker Compose.
Scenario C returns the two components to a safe state.

This script itself does not launch an attack. No separate vulnerable JS file
is checked into the repository, so CodeQL will not scan an unused test fixture.
"""
from pathlib import Path
import argparse

ROOT = Path(__file__).resolve().parents[1]
JS = ROOT / 'src/app.js'
COMPOSE = ROOT / 'compose.test.yml'

SAFE = '''    const result = await pool.query(
      'SELECT item, price FROM product WHERE item_category = $1',
      [req.params.category]
    );'''
VULNERABLE = '''    const sql = "SELECT item, price FROM product WHERE item_category = '" +
      req.params.category + "'";
    const result = await pool.query(sql);'''


def main():
    p = argparse.ArgumentParser()
    p.add_argument('scenario', choices=['a', 'b', 'c'])
    a = p.parse_args()
    js = JS.read_text(encoding='utf-8')
    compose = COMPOSE.read_text(encoding='utf-8')
    if SAFE not in js and VULNERABLE not in js:
        raise SystemExit('src/app.js has changed: refusing to overwrite unknown SQL source')
    js = js.replace(VULNERABLE, SAFE)
    if a.scenario == 'a':
        js = js.replace(SAFE, VULNERABLE)
    if "ENABLE_CSP: 'true'" not in compose and "ENABLE_CSP: 'false'" not in compose:
        raise SystemExit('Unexpected ENABLE_CSP in compose.test.yml: refusing to modify')
    compose = compose.replace("ENABLE_CSP: 'false'", "ENABLE_CSP: 'true'")
    if a.scenario == 'b':
        compose = compose.replace("ENABLE_CSP: 'true'", "ENABLE_CSP: 'false'")
    JS.write_text(js, encoding='utf-8')
    COMPOSE.write_text(compose, encoding='utf-8')
    print({
        'a': 'A: intentionally unsafe SQL -> expect SAST FAIL, Docker/ZAP SKIP',
        'b': 'B: parameterized SQL, missing CSP -> expect SAST PASS, DAST FAIL',
        'c': 'C: parameterized SQL, CSP enabled -> expect SAST PASS, DAST PASS',
    }[a.scenario])


if __name__ == '__main__':
    main()
