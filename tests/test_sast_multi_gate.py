"""Test del gate SAST aggregato (scripts/sast_multi_gate.py).

Le fixture di CodeQL e Semgrep sono report reali ridotti (CodeQL 2.27.4 del test A del
12 novembre 2026; Semgrep 1.186.0 eseguito il 19 novembre 2026 sul codice di main e sullo
scenario A). Le fixture di Gitleaks e Trivy sono sintetiche.
"""
import contextlib
import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import sast_multi_gate as gate

F = ROOT / 'tests' / 'fixtures' / 'sast-multi'
ALL_TOOLS = ('codeql', 'semgrep', 'gitleaks', 'trivy')
SCENARIO_A = ('codeql-scenario-a', 'semgrep-scenario-a', 'gitleaks-clean', 'trivy-clean')
SCENARIO_C = ('codeql-clean', 'semgrep-scenario-c', 'gitleaks-clean', 'trivy-clean')


def sarif(tool, results, rules=None):
    return {'version': '2.1.0', 'runs': [{'tool': {'driver': {'name': tool, 'rules': rules or []}}, 'results': results}]}


def result(rule, uri='src/a.js', line=1, level=None):
    item = {'ruleId': rule, 'message': {'text': rule},
            'locations': [{'physicalLocation': {'artifactLocation': {'uri': uri}, 'region': {'startLine': line}}}]}
    if level:
        item['level'] = level
    return item


def rule(rule_id, level=None, severity=None, tags=None, precision=None):
    item = {'id': rule_id, 'properties': {}}
    if level:
        item['defaultConfiguration'] = {'level': level}
    if severity is not None:
        item['properties']['security-severity'] = severity
    if tags is not None:
        item['properties']['tags'] = tags
    if precision:
        item['properties']['precision'] = precision
    return item


class GateCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    def folder(self, names=(), extra=None):
        target = self.tmp / 'sarif'
        target.mkdir(exist_ok=True)
        for name in names:
            shutil.copy(F / f'{name}.sarif', target / f'{name}.sarif')
        for name, data in (extra or {}).items():
            (target / name).write_text(json.dumps(data), encoding='utf-8')
        return target

    def summary(self, names=(), extra=None, expected=ALL_TOOLS):
        runs = gate.load_runs(self.folder(names, extra))
        return gate.evaluate(gate.normalize(runs), [gate.tool_name(run) for _, run in runs], expected)

    def run_main(self, names=(), extra=None, expect='codeql,semgrep,gitleaks,trivy', jobs=()):
        folder = self.folder(names, extra)
        out = io.StringIO()
        argv = ['--sarif-dir', str(folder), '--summary', str(self.tmp / 'out' / 'gate.json'),
                '--markdown', str(self.tmp / 'out' / 'gate.md')]
        if expect:
            argv += ['--expect', expect]
        for job in jobs:
            argv += ['--job-result', job]
        with contextlib.redirect_stdout(out):
            code = gate.main(argv)
        return code, out.getvalue()


class RealScenarioTests(GateCase):
    def test_scenario_a_merges_sql_injection_from_two_tools(self):
        summary = self.summary(SCENARIO_A)
        self.assertEqual(summary['status'], 'FAIL')
        self.assertEqual(summary['score'], 77)
        self.assertEqual(len(summary['blocking']), 1)
        self.assertEqual(summary['blocking'][0]['tools'], ['codeql', 'semgrep'])
        self.assertEqual(summary['blocking'][0]['path'], 'src/app.js')
        self.assertEqual(summary['merged_duplicates'], 1)

    def test_scenario_a_exit_code_and_annotation(self):
        code, out = self.run_main(SCENARIO_A)
        self.assertEqual(code, 2)
        self.assertIn('SAST MULTI GATE: FAIL', out)
        self.assertIn('::error file=src/app.js', out)

    def test_scenario_c_passes_with_97(self):
        summary = self.summary(SCENARIO_C)
        self.assertEqual((summary['status'], summary['score'], summary['blocking']), ('PASS', 97, []))
        code, out = self.run_main(SCENARIO_C)
        self.assertEqual(code, 0)
        self.assertIn('SAST MULTI GATE: PASS', out)

    def test_semgrep_error_without_security_severity_is_high(self):
        results = gate.normalize(gate.load_runs(self.folder(['semgrep-scenario-a'])))
        sqli = [item for item in results if item['rule'].endswith('tainted-sql-string')]
        self.assertEqual(len(sqli), 1)
        self.assertEqual((sqli[0]['severity'], sqli[0]['tool'], sqli[0]['line']), ('high', 'semgrep', 40))
        self.assertIn(89, sqli[0]['cwes'])

    def test_repeated_rule_in_same_file_counts_once(self):
        summary = self.summary(SCENARIO_C)
        self.assertEqual(summary['tools']['semgrep']['results'], 9)
        self.assertEqual(summary['counts']['medium'], 1)

    def test_summary_reports_every_tool(self):
        summary = self.summary(SCENARIO_A)
        self.assertEqual(sorted(summary['tools']), sorted(ALL_TOOLS))
        self.assertEqual(summary['tools']['codeql']['results'], 1)
        self.assertEqual(summary['tools']['gitleaks']['results'], 0)
        self.assertEqual(summary['tools']['semgrep']['informational'], 2)
        self.assertEqual(summary['excluded_low_confidence'], 1)

    def test_main_writes_json_and_markdown(self):
        self.run_main(SCENARIO_A)
        written = json.loads((self.tmp / 'out' / 'gate.json').read_text())
        self.assertEqual((written['gate'], written['score'], written['threshold']), ('sast-multi', 77, 90))
        markdown = (self.tmp / 'out' / 'gate.md').read_text()
        for tool in ALL_TOOLS:
            self.assertIn(tool, markdown)
        self.assertIn('77', markdown)


class SyntheticToolTests(GateCase):
    def test_trivy_low_and_medium_pass_with_93(self):
        summary = self.summary(('codeql-clean', 'semgrep-scenario-c', 'gitleaks-clean', 'trivy-low-medium'))
        self.assertEqual((summary['status'], summary['score']), ('PASS', 93))

    def test_trivy_high_blocks(self):
        summary = self.summary(('codeql-clean', 'semgrep-scenario-c', 'gitleaks-clean', 'trivy-high'))
        self.assertEqual((summary['status'], summary['score'], len(summary['blocking'])), ('FAIL', 77, 1))
        self.assertEqual(summary['blocking'][0]['tools'], ['trivy'])

    def test_gitleaks_secret_is_high_and_blocks(self):
        summary = self.summary(('codeql-clean', 'semgrep-scenario-c', 'gitleaks-secret', 'trivy-clean'))
        self.assertEqual((summary['status'], summary['score'], len(summary['blocking'])), ('FAIL', 77, 1))
        self.assertEqual(summary['blocking'][0]['severity'], 'high')
        self.assertEqual(summary['blocking'][0]['tools'], ['gitleaks'])


class InvalidInputTests(GateCase):
    def test_missing_expected_tool_is_invalid(self):
        code, out = self.run_main(('codeql-clean', 'semgrep-scenario-c', 'gitleaks-clean'))
        self.assertEqual(code, 3)
        self.assertIn('trivy', out)

    def test_empty_folder_is_invalid(self):
        code, out = self.run_main(())
        self.assertEqual(code, 3)
        self.assertIn('INVALID', out)

    def test_missing_folder_is_invalid(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gate.main(['--sarif-dir', str(self.tmp / 'assente'), '--expect', 'codeql',
                              '--summary', str(self.tmp / 'gate.json')])
        self.assertEqual(code, 3)

    def test_expect_is_mandatory(self):
        code, out = self.run_main(SCENARIO_C, expect='')
        self.assertEqual(code, 3)
        self.assertIn('--expect', out)
        self.assertFalse((self.tmp / 'out' / 'gate.json').exists())

    def test_failed_or_missing_tool_job_is_invalid_even_with_a_report(self):
        ok = ['codeql=success', 'semgrep=success', 'gitleaks=success', 'trivy=success']
        self.assertEqual(self.run_main(SCENARIO_C, jobs=ok)[0], 0)
        for bad in ('failure', 'cancelled', 'skipped', ''):
            code, out = self.run_main(SCENARIO_C, jobs=ok[:3] + [f'trivy={bad}'])
            self.assertEqual(code, 3, bad)
            self.assertIn('trivy', out)
        code, out = self.run_main(SCENARIO_C, jobs=ok[:3])
        self.assertEqual(code, 3)
        self.assertIn('trivy', out)
        self.assertEqual(self.run_main(SCENARIO_C, jobs=ok[:3] + ['trivy'])[0], 3)

    def test_unsuccessful_tool_execution_is_invalid(self):
        data = sarif('Trivy', [])
        data['runs'][0]['invocations'] = [{'executionSuccessful': False}]
        code, out = self.run_main((), {'x.sarif': data}, expect='trivy')
        self.assertEqual(code, 3)
        data['runs'][0]['invocations'] = [{'executionSuccessful': True}]
        self.assertEqual(self.run_main((), {'x.sarif': data}, expect='trivy')[0], 0)

    def test_result_without_rule_id_or_with_undeclared_rule_is_invalid(self):
        for tool in ('CodeQL', 'Semgrep OSS', 'Trivy', 'gitleaks'):
            undeclared = sarif(tool, [result('fantasma')], [rule('altra', 'error', '8.8')])
            self.assertEqual(self.run_main((), {'x.sarif': undeclared}, expect=gate.tool_name(undeclared['runs'][0]))[0], 3, tool)
            item = result('r')
            del item['ruleId']
            missing = sarif(tool, [item], [rule('r', 'error', '8.8')])
            self.assertEqual(self.run_main((), {'x.sarif': missing}, expect=gate.tool_name(missing['runs'][0]))[0], 3, tool)

    def test_rules_declared_in_extensions_are_found(self):
        data = sarif('CodeQL', [result('js/x')])
        data['runs'][0]['tool']['extensions'] = [{'name': 'codeql/javascript-queries',
                                                  'rules': [rule('js/x', 'error', '8.8', ['security'])]}]
        summary = self.summary((), {'x.sarif': data}, expected=('codeql',))
        self.assertEqual((summary['status'], len(summary['blocking'])), ('FAIL', 1))

    def test_security_severity_out_of_range_is_invalid(self):
        for value in ('-1', '10.1', 'nan'):
            data = sarif('Trivy', [result('r')], [rule('r', 'error', value)])
            self.assertEqual(self.run_main((), {'x.sarif': data}, expect='trivy')[0], 3, value)

    def test_non_numeric_security_severity_is_invalid(self):
        data = sarif('CodeQL', [result('r1')], [rule('r1', 'error', 'alta')])
        code, _ = self.run_main((), {'x.sarif': data}, expect='codeql')
        self.assertEqual(code, 3)

    def test_wrong_sarif_version_and_missing_driver_are_invalid(self):
        self.assertEqual(self.run_main((), {'x.sarif': {'version': '2.0.0', 'runs': [{}]}}, expect='codeql')[0], 3)
        self.assertEqual(self.run_main((), {'x.sarif': {'version': '2.1.0', 'runs': [{'tool': {}}]}}, expect='codeql')[0], 3)

    def test_malformed_json_is_invalid(self):
        folder = self.folder()
        (folder / 'x.sarif').write_text('{non json', encoding='utf-8')
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gate.main(['--sarif-dir', str(folder), '--expect', 'codeql', '--summary', str(self.tmp / 'gate.json')])
        self.assertEqual(code, 3)


class PolicyTests(GateCase):
    def evaluate(self, data, expected=()):
        return self.summary((), data, expected)

    def mediums(self, number):
        rules = [rule(f'm{i}', 'warning', tags=['security']) for i in range(number)]
        return sarif('Semgrep OSS', [result(f'm{i}', f'src/f{i}.js') for i in range(number)], rules)

    def test_threshold_is_strict(self):
        self.assertEqual(self.evaluate({'x.sarif': self.mediums(3)})['score'], 91)
        self.assertEqual(self.evaluate({'x.sarif': self.mediums(3)})['status'], 'PASS')
        rules = [rule(f'l{i}', 'note', tags=['security']) for i in range(10)]
        ten_low = sarif('Semgrep OSS', [result(f'l{i}', f'src/f{i}.js') for i in range(10)], rules)
        summary = self.evaluate({'x.sarif': ten_low})
        self.assertEqual((summary['score'], summary['status'], summary['blocking']), (90, 'FAIL', []))

    def test_fail_without_blocking_returns_exit_code_2(self):
        code, _ = self.run_main((), {'x.sarif': self.mediums(4)}, expect='semgrep')
        self.assertEqual(code, 2)

    def test_non_security_result_weighs_zero(self):
        data = sarif('Semgrep OSS', [result('style')], [rule('style', 'error')])
        summary = self.evaluate({'x.sarif': data})
        self.assertEqual((summary['score'], summary['status'], summary['informational']), (100, 'PASS', 1))

    def test_low_confidence_excluded_unless_blocking(self):
        rules = [rule('low', 'note', tags=['security', 'LOW CONFIDENCE']),
                 rule('high', 'error', tags=['security', 'LOW CONFIDENCE'])]
        only_low = self.evaluate({'x.sarif': sarif('Semgrep OSS', [result('low')], rules)})
        self.assertEqual((only_low['score'], only_low['excluded_low_confidence']), (100, 1))
        with_high = self.evaluate({'x.sarif': sarif('Semgrep OSS', [result('low'), result('high')], rules)})
        self.assertEqual((with_high['status'], len(with_high['blocking'])), ('FAIL', 1))

    def test_codeql_low_precision_is_low_confidence(self):
        data = sarif('CodeQL', [result('r')], [rule('r', 'warning', '5.0', ['security'], precision='low')])
        self.assertEqual(self.evaluate({'x.sarif': data})['excluded_low_confidence'], 1)

    def test_security_severity_bands(self):
        rules = [rule('c', severity='9.0'), rule('h', severity='7.0'), rule('m', severity='4.0'),
                 rule('l', severity='0.1'), rule('i', severity='0')]
        results = [result(key, f'src/{key}.js') for key in 'chmli']
        counts = self.evaluate({'x.sarif': sarif('Trivy', results, rules)})['counts']
        self.assertEqual(counts, {'critical': 1, 'high': 1, 'medium': 1, 'low': 1, 'info': 1})

    def test_same_cwe_six_lines_apart_is_not_merged(self):
        a = sarif('CodeQL', [result('q', 'src/app.js', 10)], [rule('q', 'error', '8.8', ['security', 'external/cwe/cwe-089'])])
        b = sarif('Semgrep OSS', [result('s', 'src/app.js', 16)], [rule('s', 'error', tags=['security', 'CWE-89: SQL Injection'])])
        summary = self.evaluate({'a.sarif': a, 'b.sarif': b})
        self.assertEqual((len(summary['blocking']), summary['merged_duplicates'], summary['score']), (2, 0, 60))

    def test_same_tool_is_never_merged_with_itself(self):
        rules = [rule('q1', 'error', '8.8', ['external/cwe/cwe-089']), rule('q2', 'error', '8.8', ['external/cwe/cwe-089'])]
        data = sarif('CodeQL', [result('q1', 'src/app.js', 10), result('q2', 'src/app.js', 11)], rules)
        self.assertEqual(len(self.evaluate({'a.sarif': data})['blocking']), 2)

    def test_merged_finding_keeps_highest_severity(self):
        a = sarif('CodeQL', [result('q', 'src/app.js', 10)], [rule('q', 'warning', '5.0', ['external/cwe/cwe-079'])])
        b = sarif('Semgrep OSS', [result('s', 'src/app.js', 12)], [rule('s', 'error', tags=['security', 'CWE-79: XSS'])])
        summary = self.evaluate({'a.sarif': a, 'b.sarif': b})
        self.assertEqual((len(summary['blocking']), summary['blocking'][0]['severity'], summary['score']), (1, 'high', 80))


class ReviewFocusTests(GateCase):
    def evaluate(self, data, expected=()):
        return self.summary((), data, expected)

    def test_rule_without_level_or_severity_counts_as_medium(self):
        summary = self.evaluate({'x.sarif': sarif('Trivy', [result('r')], [rule('r')])})
        self.assertEqual((summary['counts']['medium'], summary['score']), (1, 97))

    def test_profile_severity_wins_over_sarif_level(self):
        data = sarif('gitleaks', [result('generic-api-key', level='note')], [rule('generic-api-key', 'note')])
        self.assertEqual(self.evaluate({'x.sarif': data})['blocking'][0]['severity'], 'high')

    def test_suppressed_results_are_not_counted_but_are_listed(self):
        rules = [rule('q', 'error', '8.8', ['security'])]
        item = result('q', 'src/app.js', 10)
        item['suppressions'] = [{'kind': 'inSource'}]
        summary = self.evaluate({'x.sarif': sarif('CodeQL', [item], rules)})
        self.assertEqual((summary['status'], summary['score'], summary['blocking']), ('PASS', 100, []))
        self.assertEqual(summary['tools']['codeql']['suppressed'], 1)
        self.assertEqual([(s['id'], s['severity'], s['path'], s['line']) for s in summary['suppressed']],
                         [('q', 'high', 'src/app.js', 10)])
        markdown = gate.to_markdown(summary)
        self.assertIn('Soppressi nel codice', markdown)
        self.assertIn('src/app.js', markdown)

    def test_rejected_or_pending_suppressions_do_not_hide_a_finding(self):
        rules = [rule('q', 'error', '8.8', ['security'])]
        for status in ('rejected', 'underReview'):
            item = result('q', 'src/app.js', 10)
            item['suppressions'] = [{'kind': 'external', 'status': status}]
            summary = self.evaluate({'x.sarif': sarif('CodeQL', [item], rules)})
            self.assertEqual((len(summary['blocking']), summary['suppressed']), (1, []), status)

    def test_main_reports_suppressed_findings(self):
        item = result('q', 'src/app.js', 10)
        item['suppressions'] = [{'kind': 'inSource'}]
        code, out = self.run_main((), {'x.sarif': sarif('CodeQL', [item], [rule('q', 'error', '8.8', ['security'])])},
                                  expect='codeql')
        self.assertEqual(code, 0)
        self.assertIn('soppressi nel codice: 1', out)

    def test_absolute_and_file_uri_paths_are_normalized(self):
        a = sarif('CodeQL', [result('q', 'file:///github/workspace/src/app.js', 10)],
                  [rule('q', 'error', '8.8', ['external/cwe/cwe-089'])])
        b = sarif('Semgrep OSS', [result('s', './src/app.js', 11)], [rule('s', 'error', tags=['CWE-89'])])
        summary = self.evaluate({'a.sarif': a, 'b.sarif': b})
        self.assertEqual((len(summary['blocking']), summary['blocking'][0]['path']), (1, 'src/app.js'))

    def test_two_files_from_same_tool_are_both_read(self):
        one = sarif('Trivy', [result('a', 'Dockerfile')], [rule('a', 'warning', '5.0')])
        two = sarif('Trivy', [result('b', 'compose.yml')], [rule('b', 'warning', '5.0')])
        summary = self.evaluate({'one.sarif': one, 'sub.sarif': two}, expected=('trivy',))
        self.assertEqual((summary['tools']['trivy']['results'], summary['score']), (2, 94))


if __name__ == '__main__':
    unittest.main()
