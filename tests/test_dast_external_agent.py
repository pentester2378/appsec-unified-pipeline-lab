import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
import zipfile
from unittest import mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
import dast_external_agent as agent  # noqa: E402

ORIGIN = 'http://app:3000'
SLUG = 'owner/repo'


def alert(ref, risk, confidence=2, name='Alert', plugin=None):
    return {'alertRef': ref, 'pluginid': plugin or ref.split('-')[0], 'name': name,
            'riskcode': str(risk), 'confidence': str(confidence),
            'instances': [{'uri': ORIGIN + '/'}]}


def report(*alerts, site=ORIGIN):
    return {'site': [{'@name': site, 'alerts': list(alerts)}]}


# Stessa composizione del report ZAP reale del test C del 12 novembre 2026.
REAL_TEST_C = report(alert('10055-13', 2, 3), alert('90004-1', 1), alert('90004-2', 1),
                     alert('90004-3', 1), alert('10063-1', 1), alert('10021', 1), alert('10049-3', 0))
CSP_MISSING = alert('10038-1', 2, name='Content Security Policy (CSP) Header Not Set', plugin='10038')


class FakeGitHub:
    def __init__(self, pulls=(), statuses=None, head='f' * 40, checks=None):
        self.slug = SLUG
        self.pulls, self._statuses, self.head = list(pulls), dict(statuses or {}), head
        self.checks = dict(checks or {})
        self.written = []      # stati DAST scritti: (sha, stato, descrizione)
        self.pt_written = []   # stati PT scritti

    def check_runs(self, sha):
        return self.checks.get(sha, [])

    def open_pulls(self, base):
        return self.pulls

    def branch_head(self, branch):
        return self.head

    def statuses(self, sha):
        return self._statuses.get(sha, [])

    def set_status(self, sha, state, description, context=None):
        context = context or agent.CONTEXT
        (self.written if context == agent.CONTEXT else self.pt_written).append((sha, state, description))
        self._statuses[sha] = ([{'context': context, 'state': state, 'description': description}]
                               + self._statuses.get(sha, []))


def pull(number, sha, repo=SLUG):
    return {'number': number, 'head': {'sha': sha, 'repo': {'full_name': repo}}}


def config(tmp, **extra):
    cfg = {'slug': SLUG, 'token': None, 'mode': 'pr', 'base': 'main', 'branch': None, 'dry_run': False,
           'work_dir': Path(tmp), 'reports_dir': Path(tmp) / 'reports', 'compose_file': 'compose.test.yml',
           'network': 'appsec-unified-ci', 'target': ORIGIN, 'target_url': None, 'health_path': '/health',
           'zap_image': agent.ZAP_IMAGE}
    cfg.update(extra)
    return cfg


class PolicyTests(unittest.TestCase):
    def test_real_test_c_composition_passes_with_92(self):
        result = agent.evaluate(REAL_TEST_C, ORIGIN)
        self.assertEqual((result['status'], result['score'], result['blocking']), ('PASS', 92, []))
        self.assertEqual(result['counts'], {'critical': 0, 'high': 0, 'medium': 1, 'low': 5, 'info': 1})

    def test_missing_csp_blocks_even_with_good_score(self):
        result = agent.evaluate(report(CSP_MISSING), ORIGIN)
        self.assertEqual((result['status'], result['score'], len(result['blocking'])), ('FAIL', 97, 1))

    def test_missing_csp_blocks_at_low_confidence(self):
        low = dict(CSP_MISSING, confidence='1')
        self.assertEqual(agent.evaluate(report(low), ORIGIN)['status'], 'FAIL')

    def test_threshold_is_strict(self):
        nine_low = report(*[alert(f'9000{i}', 1) for i in range(9)])
        ten_low = report(*[alert(f'9000{i}', 1) for i in range(10)])
        self.assertEqual(agent.evaluate(nine_low, ORIGIN)['score'], 91)
        self.assertEqual(agent.evaluate(nine_low, ORIGIN)['status'], 'PASS')
        result = agent.evaluate(ten_low, ORIGIN)
        self.assertEqual((result['score'], result['status'], result['blocking']), (90, 'FAIL', []))

    def test_high_blocks_and_low_confidence_high_is_not_counted(self):
        self.assertEqual(agent.evaluate(report(alert('40018', 3)), ORIGIN)['status'], 'FAIL')
        result = agent.evaluate(report(alert('40018', 3, confidence=1)), ORIGIN)
        self.assertEqual((result['status'], result['score']), ('PASS', 100))

    def test_repeated_rule_counts_once(self):
        result = agent.evaluate(report(alert('10021', 1), alert('10021', 1)), ORIGIN)
        self.assertEqual((result['score'], result['alert_rules']), (99, 1))

    def test_invalid_reports_never_pass(self):
        for bad in ({'site': []}, [], report(alert('1', 7)), report(alert('1', 1), site='https://example.org')):
            with self.assertRaises(ValueError):
                agent.evaluate(bad, ORIGIN)

    def test_description_fits_github_limit(self):
        text = agent.describe(agent.evaluate(REAL_TEST_C, ORIGIN))
        self.assertIn('PASS - score 92/100', text)
        self.assertLessEqual(len(text), agent.DESCRIPTION_MAX)


class SelectionTests(unittest.TestCase):
    def test_fork_pull_requests_are_ignored(self):
        gh = FakeGitHub(pulls=[pull(1, 'a' * 40), pull(2, 'b' * 40, repo='stranger/repo')])
        found = agent.candidates(gh, {'mode': 'pr', 'base': 'main'})
        self.assertEqual([c['sha'] for c in found], ['a' * 40])
        self.assertEqual(found[0]['fetch_ref'], 'refs/pull/1/head')

    def test_branch_mode_uses_branch_head(self):
        gh = FakeGitHub(head='c' * 40)
        found = agent.candidates(gh, {'mode': 'branch', 'branch': 'test'})
        self.assertEqual((found[0]['sha'], found[0]['fetch_ref']), ('c' * 40, 'test'))

    def test_needs_scan_rules(self):
        other = [{'context': '03 APPSEC UNIFIED GATE', 'state': 'success'}]
        gh = FakeGitHub(statuses={
            'none': other,
            'done': [{'context': agent.CONTEXT, 'state': 'failure'}],
            'stale': [{'context': agent.CONTEXT, 'state': 'pending'}],
            'redo': [{'context': agent.CONTEXT, 'state': 'success'}, {'context': agent.CONTEXT, 'state': 'pending'}]})
        self.assertTrue(agent.needs_scan(gh, 'none'))
        self.assertFalse(agent.needs_scan(gh, 'done'))
        self.assertTrue(agent.needs_scan(gh, 'stale'))
        self.assertFalse(agent.needs_scan(gh, 'redo'))


class FlowTests(unittest.TestCase):
    def test_pass_writes_pending_then_success_and_is_not_rescanned(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = FakeGitHub(pulls=[pull(1, 'a' * 40)])
            calls = []

            def scan(candidate, cfg):
                calls.append(candidate['sha'])
                return dict(agent.evaluate(REAL_TEST_C, ORIGIN), report_dir=tmp)

            cfg = config(tmp)
            self.assertEqual(agent.poll_once(gh, cfg, scan), [('a' * 40, 'success')])
            self.assertEqual([w[1] for w in gh.written], ['pending', 'success'])
            self.assertEqual(agent.poll_once(gh, cfg, scan), [])
            self.assertEqual(len(calls), 1)

    def test_fail_writes_failure_with_score(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = FakeGitHub(pulls=[pull(1, 'a' * 40)])
            scan = lambda candidate, cfg: dict(agent.evaluate(report(CSP_MISSING), ORIGIN), report_dir=tmp)
            self.assertEqual(agent.poll_once(gh, config(tmp), scan), [('a' * 40, 'failure')])
            self.assertIn('FAIL - score 97/100', gh.written[-1][2])

    def test_scan_error_writes_error_state_never_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = FakeGitHub(pulls=[pull(1, 'a' * 40)])

            def scan(candidate, cfg):
                raise agent.ScanError('docker terminato con codice 1\ndettaglio')

            self.assertEqual(agent.poll_once(gh, config(tmp), scan), [('a' * 40, 'error')])
            self.assertEqual(gh.written[-1][1], 'error')
            self.assertNotIn('\n', gh.written[-1][2])

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = FakeGitHub(pulls=[pull(1, 'a' * 40)])
            cfg = config(tmp, dry_run=True)
            self.assertEqual(agent.poll_once(gh, cfg, None), [('a' * 40, 'dry-run')])
            self.assertEqual(agent.poll_once(gh, cfg, None), [])
            self.assertEqual(gh.written, [])


SAST = '01 SAST - CodeQL and High gate'


def check(conclusion, status='completed', run_id=1, name=SAST):
    return {'id': run_id, 'name': name, 'status': status, 'conclusion': conclusion}


class RequiredCheckTests(unittest.TestCase):
    SHA = 'a' * 40

    def poll(self, checks, tmp, scan):
        gh = FakeGitHub(pulls=[pull(1, self.SHA)], checks={self.SHA: checks})
        return gh, agent.poll_once(gh, config(tmp, require_check=SAST), scan)

    def test_waits_while_required_check_is_missing_or_running(self):
        with tempfile.TemporaryDirectory() as tmp:
            for checks in ([], [check(None, status='in_progress')], [check('success', name='altro check')]):
                gh, done = self.poll(checks, tmp, None)
                self.assertEqual((done, gh.written), ([], []))

    def test_failed_required_check_means_dast_is_not_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh, done = self.poll([check('failure')], tmp, None)
            self.assertEqual(done, [(self.SHA, 'not-run')])
            self.assertEqual(gh.written[-1][1], 'failure')
            self.assertIn('non eseguito', gh.written[-1][2])
            self.assertFalse(agent.needs_scan(gh, self.SHA))

    def test_passed_required_check_starts_the_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan = lambda candidate, cfg: dict(agent.evaluate(REAL_TEST_C, ORIGIN), report_dir=tmp)
            gh, done = self.poll([check('failure', run_id=1), check('success', run_id=2)], tmp, scan)
            self.assertEqual(done, [(self.SHA, 'success')])


class FakeProc:
    def __init__(self, returncode=0, stdout=''):
        self.returncode, self.stdout = returncode, stdout


class ScanTests(unittest.TestCase):
    SHA = 'd' * 40

    def runner(self, zap_report, commands, health_failures=0):
        state = {'health': 0}

        def run(cmd, cwd=None, env=None, timeout=None, check=True):
            cmd = [str(part) for part in cmd]
            commands.append(cmd)
            if cmd[:2] == ['git', 'rev-parse']:
                return FakeProc(stdout=self.SHA + '\n')
            if agent.CURL_IMAGE in cmd:
                state['health'] += 1
                return FakeProc(returncode=1 if state['health'] <= health_failures else 0)
            if 'zap-baseline.py' in cmd and zap_report is not None:
                mount = cmd[cmd.index('-v') + 1].split(':')[0]
                Path(mount, 'zap.json').write_text(json.dumps(zap_report), encoding='utf-8')
            return FakeProc()

        return run

    def test_build_scan_and_shutdown_sequence(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            candidate = {'sha': self.SHA, 'fetch_ref': 'refs/pull/1/head', 'label': 'PR #1'}
            summary = agent.scan_commit(candidate, config(tmp), run=self.runner(REAL_TEST_C, commands, 2),
                                        sleep=lambda seconds: None)
            self.assertEqual((summary['status'], summary['score'], summary['commit']), ('PASS', 92, self.SHA))
            flat = [' '.join(cmd) for cmd in commands]
            order = [next(i for i, text in enumerate(flat) if marker in text)
                     for marker in ('clone', 'fetch origin refs/pull/1/head', 'checkout --force --detach',
                                    'up -d --build --wait', 'zap-baseline.py', 'down --volumes')]
            self.assertEqual(order, sorted(order))
            self.assertTrue((Path(tmp) / 'reports' / self.SHA / 'dast-external-gate.json').is_file())

    def test_missing_zap_report_is_an_error_and_containers_are_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            candidate = {'sha': self.SHA, 'fetch_ref': 'test', 'label': 'branch test'}
            with self.assertRaises(agent.ScanError):
                agent.scan_commit(candidate, config(tmp), run=self.runner(None, commands), sleep=lambda s: None)
            self.assertTrue(any('down' in cmd for cmd in commands))

    def test_target_url_mode_does_not_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            url = 'https://app.tst.example'
            zap_report = {'site': [{'@name': url, 'alerts': []}]}
            candidate = {'sha': self.SHA, 'fetch_ref': 'test', 'label': 'branch test'}
            summary = agent.scan_commit(candidate, config(tmp, target_url=url),
                                        run=self.runner(zap_report, commands), sleep=lambda s: None)
            self.assertEqual((summary['status'], summary['score']), ('PASS', 100))
            self.assertFalse(any(cmd[0] == 'git' or 'compose' in cmd for cmd in commands))


class SimulationTests(unittest.TestCase):
    SHA = 'e' * 40

    def simulate(self, tmp, csp_value):
        source = Path(tmp) / 'source'
        (source / '.git').mkdir(parents=True)
        (source / 'compose.test.yml').write_text(f"      ENABLE_CSP: '{csp_value}' # commento\n", encoding='utf-8')
        commands = []

        def run(cmd, cwd=None, env=None, timeout=None, check=True):
            cmd = [str(part) for part in cmd]
            commands.append(cmd)
            return FakeProc(stdout=self.SHA + '\n' if cmd[:2] == ['git', 'rev-parse'] else '')

        candidate = {'sha': self.SHA, 'fetch_ref': 'refs/pull/1/head', 'label': 'PR #1'}
        summary = agent.simulate_scan(candidate, config(tmp, simulate=True), run=run)
        self.assertFalse(any(cmd[0] == 'docker' for cmd in commands))
        return summary

    def test_csp_enabled_commit_passes_with_92(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = self.simulate(tmp, 'true')
            self.assertEqual((summary['status'], summary['score'], summary['simulated']), ('PASS', 92, True))
            self.assertTrue(agent.describe(summary).startswith('[SIMULATO] DAST esterno: PASS'))
            saved = json.loads((Path(tmp) / 'reports' / self.SHA / 'zap.json').read_text())
            self.assertTrue(saved['@simulated'])

    def test_csp_disabled_commit_fails_on_missing_csp(self):
        with tempfile.TemporaryDirectory() as tmp:
            summary = self.simulate(tmp, 'false')
            self.assertEqual(summary['status'], 'FAIL')
            self.assertIn('10038-1', [item['id'] for item in summary['blocking']])

    def test_missing_compose_file_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / 'source' / '.git').mkdir(parents=True)
            run = lambda cmd, **kw: FakeProc(stdout=self.SHA + '\n')
            with self.assertRaises(agent.ScanError):
                agent.simulate_scan({'sha': self.SHA, 'fetch_ref': 'x', 'label': 'PR #1'}, config(tmp), run=run)


class LocalZapTests(unittest.TestCase):
    """ZAP installato sulla macchina (--zap-cmd) al posto dell'immagine Docker."""
    SHA = 'e' * 40
    CANDIDATE = {'sha': SHA, 'fetch_ref': 'refs/pull/7/head', 'label': 'PR #7'}

    def install(self, tmp, addons=('pscanrules-release-70.zap', 'commonlib-release-1.39.0.zap'), corrupt=()):
        folder = Path(tmp) / 'zap-install'
        (folder / 'plugin').mkdir(parents=True)
        command = folder / 'zap.sh'
        command.write_text('#!/bin/sh\n', encoding='utf-8')
        command.chmod(0o755)
        for name in addons:
            if name in corrupt:
                (folder / 'plugin' / name).write_bytes(b'download interrotto')
            else:
                with zipfile.ZipFile(folder / 'plugin' / name, 'w') as archive:
                    archive.writestr('ZapAddOn.xml', '<zapaddon/>')
        return str(command)

    def local_config(self, tmp, command, **extra):
        return config(tmp, zap_cmd=command, zap_home=Path(tmp) / 'zap-home', **extra)

    def runner(self, commands, alerts=(), published='127.0.0.1:49153\n'):
        def run(cmd, cwd=None, env=None, timeout=None, check=True):
            cmd = [str(part) for part in cmd]
            commands.append(cmd)
            if cmd[:2] == ['git', 'rev-parse']:
                return FakeProc(stdout=self.SHA + '\n')
            if 'port' in cmd and 'compose' in cmd:
                return FakeProc(stdout=published)
            if '-autorun' in cmd:
                plan = json.loads(Path(cmd[cmd.index('-autorun') + 1]).read_text(encoding='utf-8'))
                target = plan['env']['contexts'][0]['urls'][0]
                folder = plan['jobs'][-2]['parameters']['reportDir']
                found = [dict(item, instances=[{'uri': target + '/'}]) for item in alerts]
                Path(folder, 'zap.json').write_text(json.dumps({'site': [{'@name': target, 'alerts': found}]}),
                                                    encoding='utf-8')
            return FakeProc()

        return run

    def test_plan_has_only_passive_jobs_and_stays_on_the_target(self):
        plan = agent.zap_plan('http://127.0.0.1:49153', Path('/tmp/reports'))
        self.assertEqual(tuple(job['type'] for job in plan['jobs']), agent.LOCAL_ZAP_JOBS)
        self.assertFalse(any('active' in job['type'].lower() for job in plan['jobs']))
        context = plan['env']['contexts'][0]
        self.assertEqual(context['includePaths'], [r'http://127\.0\.0\.1:49153.*'])
        self.assertTrue(plan['jobs'][0]['parameters']['scanOnlyInScope'])

    def test_target_url_with_installed_zap_uses_no_docker_and_no_git(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands, url = [], 'https://app.tst.example'
            cfg = self.local_config(tmp, self.install(tmp), target_url=url)
            summary = agent.scan_commit(self.CANDIDATE, cfg, run=self.runner(commands, REAL_TEST_C['site'][0]['alerts']),
                                        sleep=lambda s: None, reachable=lambda u: True)
            self.assertEqual((summary['status'], summary['score'], summary['zap']), ('PASS', 92, 'installato'))
            self.assertEqual(len(commands), 1)
            zap = commands[0]
            self.assertEqual(zap[1:5], ['-cmd', '-silent', '-dir', str(Path(tmp) / 'zap-home')])
            self.assertNotIn('docker', zap)

    def test_compose_app_is_published_on_loopback_and_scanned_there(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands, probed = [], []
            cfg = self.local_config(tmp, self.install(tmp))
            summary = agent.scan_commit(self.CANDIDATE, cfg, run=self.runner(commands, [CSP_MISSING]),
                                        sleep=lambda s: None, reachable=lambda u: probed.append(u) or True)
            self.assertEqual(summary['status'], 'FAIL')
            self.assertEqual(summary['expected_origin'], 'http://127.0.0.1:49153')
            self.assertEqual(probed, ['http://127.0.0.1:49153/health'])
            override = json.loads((Path(tmp) / 'compose.dast-agent.json').read_text(encoding='utf-8'))
            self.assertEqual(override, {'services': {'app': {'ports': ['127.0.0.1::3000']}}})
            flat = [' '.join(cmd) for cmd in commands]
            order = [next(i for i, text in enumerate(flat) if marker in text)
                     for marker in ('up -d --build --wait', 'port app 3000', '-autorun', 'down --volumes')]
            self.assertEqual(order, sorted(order))
            self.assertFalse(any(agent.ZAP_IMAGE in cmd or agent.CURL_IMAGE in cmd for cmd in commands))

    def test_unrecognised_published_port_is_an_error_and_containers_are_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            cfg = self.local_config(tmp, self.install(tmp))
            with self.assertRaises(agent.ScanError):
                agent.scan_commit(self.CANDIDATE, cfg, run=self.runner(commands, published='0.0.0.0:3000\n'),
                                  sleep=lambda s: None, reachable=lambda u: True)
            self.assertFalse(any('-autorun' in cmd for cmd in commands))
            self.assertTrue(any('down' in cmd for cmd in commands))

    def test_unreachable_app_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            cfg = self.local_config(tmp, self.install(tmp))
            with self.assertRaises(agent.ScanError):
                agent.scan_commit(self.CANDIDATE, cfg, run=self.runner(commands),
                                  sleep=lambda s: None, reachable=lambda u: False)
            self.assertFalse(any('-autorun' in cmd for cmd in commands))

    def test_missing_passive_rules_are_an_error_before_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            command = self.install(tmp, addons=('commonlib-release-1.39.0.zap',))
            cfg = self.local_config(tmp, command, target_url='https://app.tst.example')
            with self.assertRaises(agent.ScanError) as raised:
                agent.scan_commit(self.CANDIDATE, cfg, run=self.runner(commands), sleep=lambda s: None)
            self.assertIn('pscanrules', str(raised.exception))
            self.assertEqual(commands, [])

    def test_corrupt_addon_in_zap_home_is_an_error_before_scanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            cfg = self.local_config(tmp, self.install(tmp), target_url='https://app.tst.example')
            plugin = Path(tmp) / 'zap-home' / 'plugin'
            plugin.mkdir(parents=True)
            (plugin / 'commonlib-release-1.44.0.zap').write_bytes(b'zip END header not found')
            with self.assertRaises(agent.ScanError) as raised:
                agent.scan_commit(self.CANDIDATE, cfg, run=self.runner(commands), sleep=lambda s: None)
            self.assertIn('corrotto', str(raised.exception))
            self.assertEqual(commands, [])

    def test_missing_zap_command_is_an_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self.local_config(tmp, str(Path(tmp) / 'assente' / 'zap.sh'), target_url='https://app.tst.example')
            with self.assertRaises(agent.ScanError):
                agent.scan_commit(self.CANDIDATE, cfg, run=self.runner([]), sleep=lambda s: None)

    def test_error_state_is_written_when_rules_are_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            command = self.install(tmp, addons=('commonlib-release-1.39.0.zap',))
            cfg = self.local_config(tmp, command, target_url='https://app.tst.example')
            gh = FakeGitHub(pulls=[pull(7, self.SHA)])
            scan = lambda candidate, cfg: agent.scan_commit(candidate, cfg, run=self.runner([]), sleep=lambda s: None)
            self.assertEqual(agent.poll_once(gh, cfg, scan), [(self.SHA, 'error')])
            self.assertEqual([state for _, state, _ in gh.written], ['pending', 'error'])


class MultipleRequiredCheckTests(unittest.TestCase):
    SHA = 'a' * 40
    BOTH = [SAST, 'SAST AGGREGATO']

    def poll(self, checks, tmp, scan, required=None):
        gh = FakeGitHub(pulls=[pull(1, self.SHA)], checks={self.SHA: checks})
        return gh, agent.poll_once(gh, config(tmp, require_check=required or self.BOTH), scan)

    def test_scan_starts_only_when_all_checks_passed(self):
        with tempfile.TemporaryDirectory() as tmp:
            scan = lambda candidate, cfg: dict(agent.evaluate(REAL_TEST_C, ORIGIN), report_dir=tmp)
            checks = [check('success'), check('success', name='SAST AGGREGATO', run_id=2)]
            gh, done = self.poll(checks, tmp, scan)
            self.assertEqual(done, [(self.SHA, 'success')])

    def test_waits_while_one_check_is_still_running_or_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            for checks in ([check('success')],
                           [check('success'), check(None, status='in_progress', name='SAST AGGREGATO')]):
                gh, done = self.poll(checks, tmp, None)
                self.assertEqual((done, gh.written), ([], []))

    def test_one_failed_check_means_dast_is_not_run_and_is_named(self):
        with tempfile.TemporaryDirectory() as tmp:
            checks = [check('success'), check('failure', name='SAST AGGREGATO', run_id=2)]
            gh, done = self.poll(checks, tmp, None)
            self.assertEqual(done, [(self.SHA, 'not-run')])
            self.assertEqual(gh.written[-1][1], 'failure')
            self.assertIn('non eseguito', gh.written[-1][2])
            self.assertIn('SAST AGGREGATO', gh.written[-1][2])

    def test_failure_wins_over_a_check_still_running(self):
        gh = FakeGitHub(checks={self.SHA: [check(None, status='in_progress'),
                                           check('failure', name='SAST AGGREGATO', run_id=2)]})
        self.assertEqual(agent.required_checks_state(gh, self.SHA, self.BOTH), ('failure', 'SAST AGGREGATO'))

    def test_state_of_all_checks(self):
        gh = FakeGitHub(checks={self.SHA: [check('success'), check('success', name='SAST AGGREGATO')]})
        self.assertEqual(agent.required_checks_state(gh, self.SHA, self.BOTH), ('success', None))
        self.assertEqual(agent.required_checks_state(gh, self.SHA, self.BOTH + ['altro']), ('pending', 'altro'))

    def test_option_can_be_repeated(self):
        args = agent.parse_args(['--repo', SLUG, '--require-check', SAST, '--require-check', 'SAST AGGREGATO'])
        self.assertEqual(agent.build_config(args, None)['require_check'], self.BOTH)
        self.assertIsNone(agent.build_config(agent.parse_args(['--repo', SLUG]), None)['require_check'])


def finding(severity, title='Finding', ident='vuln-0001'):
    return {'id': ident, 'title': title, 'severity': severity, 'timestamp': '2026-11-19T10:00:00Z'}


class PentestPolicyTests(unittest.TestCase):
    def test_no_findings_passes_with_100(self):
        summary = agent.evaluate_pentest([])
        self.assertEqual((summary['gate'], summary['tool'], summary['status'], summary['score'], summary['findings']),
                         ('pt-agentico', 'strix', 'PASS', 100, 0))

    def test_high_blocks(self):
        summary = agent.evaluate_pentest([finding('HIGH', 'SQL injection')])
        self.assertEqual((summary['status'], summary['score'], len(summary['blocking'])), ('FAIL', 80, 1))
        self.assertEqual(summary['blocking'][0]['title'], 'SQL injection')

    def test_threshold_is_strict_without_blocking(self):
        three = agent.evaluate_pentest([finding('medium', ident=f'v{i}') for i in range(3)])
        four = agent.evaluate_pentest([finding('medium', ident=f'v{i}') for i in range(4)])
        self.assertEqual((three['score'], three['status']), (91, 'PASS'))
        self.assertEqual((four['score'], four['status'], four['blocking']), (88, 'FAIL', []))

    def test_none_severity_is_info(self):
        summary = agent.evaluate_pentest([finding('none'), finding('info'), finding('low')])
        self.assertEqual((summary['counts']['info'], summary['counts']['low'], summary['score']), (2, 1, 99))

    def test_unreadable_findings_never_pass(self):
        for bad in ({'vulnerabilities': []}, ['testo'], [{'title': 'senza severita'}], [finding('gravissima')], None):
            with self.assertRaises(ValueError):
                agent.evaluate_pentest(bad)

    def test_description_fits_github_limit(self):
        text = agent.describe_pentest(agent.evaluate_pentest([finding('critical')]))
        self.assertLessEqual(len(text), agent.DESCRIPTION_MAX)
        self.assertIn('PT agentico: FAIL - score 60/100', text)


class PentestRunTests(unittest.TestCase):
    SHA = 'e' * 40
    URL = 'https://app.tst.example'

    def candidate(self):
        return {'sha': self.SHA, 'fetch_ref': 'refs/pull/1/head', 'label': 'PR #1'}

    def cfg(self, tmp, **extra):
        values = {'pentest_cmd': 'strix', 'pentest_mode': 'quick', 'pentest_budget': None, 'pentest_timeout': 60,
                  'target_url': self.URL}
        values.update(extra)
        return config(tmp, **values)

    def runner(self, commands, code=0, findings=None, status='completed', runs=1, record=None):
        def run(cmd, cwd=None, env=None, timeout=None, check=True):
            cmd = [str(part) for part in cmd]
            commands.append({'cmd': cmd, 'cwd': cwd, 'env': env, 'timeout': timeout, 'check': check})
            if cmd[:2] == ['git', 'rev-parse']:
                return FakeProc(stdout=self.SHA + '\n')
            if cmd[:3] == ['git', 'worktree', 'add']:
                Path(cmd[-2]).mkdir(parents=True)
                (Path(cmd[-2]) / 'lasciato-da-strix.txt').write_text('x')
            if cmd[0] == 'strix':
                for index in range(runs):
                    run_dir = Path(cwd) / 'strix_runs' / f'run-{index}'
                    run_dir.mkdir(parents=True)
                    (run_dir / 'findings.sarif').write_text('{}', encoding='utf-8')
                    if record is not None:
                        (run_dir / 'run.json').write_text(record, encoding='utf-8')
                    elif status:
                        (run_dir / 'run.json').write_text(json.dumps({'status': status}), encoding='utf-8')
                    if findings is not None:
                        (run_dir / 'vulnerabilities.json').write_text(json.dumps(findings), encoding='utf-8')
                return FakeProc(returncode=code)
            return FakeProc()
        return run

    def test_black_box_command_on_target_url(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            summary = agent.run_pentest(self.candidate(), self.cfg(tmp), run=self.runner(commands))
            self.assertEqual(len(commands), 1)
            stage = Path(tmp) / 'reports' / self.SHA / 'pentest'
            self.assertEqual(commands[0]['cmd'], ['strix', '-n', '-t', self.URL, '--scan-mode', 'quick'])
            self.assertEqual(Path(commands[0]['cwd']), stage)
            self.assertEqual((commands[0]['timeout'], commands[0]['check']), (3600, False))
            self.assertEqual((summary['status'], summary['score'], summary['target'], summary['mode']),
                             ('PASS', 100, self.URL, 'quick'))
            written = json.loads((Path(tmp) / 'reports' / self.SHA / 'pentest-gate.json').read_text())
            self.assertEqual((written['commit'], written['status']), (self.SHA, 'PASS'))

    def test_github_token_is_not_passed_to_strix(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            secrets = {'GH_TOKEN': 'segreto-1', 'GITHUB_TOKEN': 'segreto-2', 'STRIX_LLM': 'locale/modello'}
            with mock.patch.dict(os.environ, secrets):
                agent.run_pentest(self.candidate(), self.cfg(tmp), run=self.runner(commands))
            env = commands[0]['env']
            self.assertEqual(env.get('STRIX_LLM'), 'locale/modello')
            self.assertNotIn('GH_TOKEN', env)
            self.assertNotIn('GITHUB_TOKEN', env)
            self.assertNotIn('segreto-1', ' '.join(commands[0]['cmd']))

    def test_telemetry_is_off_unless_the_operator_enables_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            with mock.patch.dict(os.environ):
                os.environ.pop('STRIX_TELEMETRY', None)
                agent.run_pentest(self.candidate(), self.cfg(tmp), run=self.runner(commands))
            with mock.patch.dict(os.environ, {'STRIX_TELEMETRY': '1'}):
                agent.run_pentest(self.candidate(), self.cfg(tmp), run=self.runner(commands))
            self.assertEqual([item['env']['STRIX_TELEMETRY'] for item in commands], ['0', '1'])

    def test_budget_and_mode(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            cfg = self.cfg(tmp, pentest_mode='deep', pentest_budget=5.0, pentest_timeout=10)
            agent.run_pentest(self.candidate(), cfg, run=self.runner(commands))
            self.assertEqual(commands[0]['cmd'][-4:], ['--scan-mode', 'deep', '--max-budget-usd', '5.0'])
            self.assertEqual(commands[0]['timeout'], 600)

    def test_white_box_on_the_checked_out_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            summary = agent.run_pentest(self.candidate(), self.cfg(tmp, target_url=None), run=self.runner(commands))
            flat = [' '.join(item['cmd']) for item in commands]
            copy = Path(tmp) / 'reports' / self.SHA / 'pentest' / 'source'
            order = [next(i for i, text in enumerate(flat) if marker in text)
                     for marker in ('fetch origin refs/pull/1/head', f'worktree add --force --detach {copy} {self.SHA}',
                                    f'strix -n -t {copy} --scan-mode quick --scope-mode full')]
            self.assertEqual(order, sorted(order))
            self.assertEqual(summary['target'], 'sorgente del commit (copia temporanea)')
            # La copia usata da Strix (che puo' scriverci) viene eliminata: non entra nelle build successive.
            self.assertFalse(copy.exists())
            self.assertIn('worktree prune', flat[-1])

    def test_copy_of_the_commit_is_verified_and_removed_even_on_failure(self):
        with tempfile.TemporaryDirectory() as tmp:
            copy = Path(tmp) / 'reports' / self.SHA / 'pentest' / 'source'
            with self.assertRaises(agent.ScanError):
                agent.run_pentest(self.candidate(), self.cfg(tmp, target_url=None), run=self.runner([], code=1))
            self.assertFalse(copy.exists())

            def wrong_commit(cmd, cwd=None, env=None, timeout=None, check=True):
                cmd = [str(part) for part in cmd]
                if cmd[:2] == ['git', 'rev-parse']:
                    return FakeProc(stdout=(self.SHA if Path(cwd).name == 'source' and 'pentest' not in str(cwd)
                                            else 'f' * 40) + '\n')
                if cmd[0] == 'strix':
                    raise AssertionError('Strix non deve partire su un commit diverso')
                return FakeProc()

            with self.assertRaises(agent.ScanError):
                agent.run_pentest(self.candidate(), self.cfg(tmp, target_url=None), run=wrong_commit)

    def test_black_box_has_no_scope_option(self):
        with tempfile.TemporaryDirectory() as tmp:
            commands = []
            agent.run_pentest(self.candidate(), self.cfg(tmp), run=self.runner(commands))
            self.assertNotIn('--scope-mode', commands[0]['cmd'])

    def test_findings_are_scored(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.runner([], code=2, findings=[finding('high'), finding('low', ident='v2')])
            summary = agent.run_pentest(self.candidate(), self.cfg(tmp), run=run)
            self.assertEqual((summary['status'], summary['score'], summary['findings']), ('FAIL', 79, 2))

    def test_findings_are_read_even_with_exit_code_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            run = self.runner([], code=0, findings=[finding('critical')])
            self.assertEqual(agent.run_pentest(self.candidate(), self.cfg(tmp), run=run)['status'], 'FAIL')

    def test_incomplete_runs_are_errors(self):
        cases = ({'code': 1}, {'code': 137}, {'code': 0, 'runs': 0}, {'code': 0, 'status': None},
                 {'code': 2}, {'code': 0, 'runs': 2},
                 # Strix termina con 0 anche a budget esaurito o senza chiusura della scansione.
                 {'code': 0, 'status': 'stopped'}, {'code': 0, 'status': 'running'},
                 {'code': 0, 'status': 'failed'}, {'code': 0, 'status': 'interrupted'},
                 {'code': 2, 'status': 'stopped', 'findings': [finding('low')]},
                 {'code': 0, 'record': '{non json'}, {'code': 0, 'record': '["completed"]'},
                 {'code': 0, 'record': '{}'})
        for case in cases:
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises(agent.ScanError, msg=str(case)):
                    agent.run_pentest(self.candidate(), self.cfg(tmp), run=self.runner([], **case))

    def test_unreadable_findings_are_errors(self):
        for bad in ({'non': 'lista'}, [{'title': 'senza severita'}]):
            with tempfile.TemporaryDirectory() as tmp:
                with self.assertRaises((agent.ScanError, ValueError)):
                    agent.run_pentest(self.candidate(), self.cfg(tmp), run=self.runner([], code=2, findings=bad))
        with tempfile.TemporaryDirectory() as tmp:
            def run(cmd, cwd=None, env=None, timeout=None, check=True):
                run_dir = Path(cwd) / 'strix_runs' / 'run-0'
                run_dir.mkdir(parents=True)
                (run_dir / 'run.json').write_text('{"status": "completed"}')
                (run_dir / 'vulnerabilities.json').write_text('{non json')
                return FakeProc(returncode=2)
            with self.assertRaises(agent.ScanError):
                agent.run_pentest(self.candidate(), self.cfg(tmp), run=run)

    def test_results_of_a_previous_execution_are_not_reused(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = Path(tmp) / 'reports' / self.SHA / 'pentest' / 'strix_runs' / 'vecchio'
            old.mkdir(parents=True)
            (old / 'run.json').write_text('{"status": "completed"}')
            (old / 'vulnerabilities.json').write_text(json.dumps([finding('critical')]))
            summary = agent.run_pentest(self.candidate(), self.cfg(tmp), run=self.runner([]))
            self.assertEqual((summary['status'], summary['findings']), ('PASS', 0))
            self.assertFalse(old.exists())


class PentestFlowTests(unittest.TestCase):
    SHA = 'a' * 40

    def setUp(self):
        self.calls = []

    def gh(self, dast=None, pt=None, dast_description='DAST esterno: PASS - score 92/100'):
        statuses = []
        if pt:
            statuses.append({'context': agent.PT_CONTEXT, 'state': pt})
        if dast:
            statuses.append({'context': agent.CONTEXT, 'state': dast, 'description': dast_description})
        return FakeGitHub(pulls=[pull(1, self.SHA)], statuses={self.SHA: statuses})

    def pentest(self, findings=(), error=None):
        def run(candidate, cfg):
            self.calls.append(candidate['sha'])
            if error:
                raise error
            return dict(agent.evaluate_pentest(list(findings)), report_dir='x')
        return run

    def cfg(self, tmp, **extra):
        return config(tmp, pentest_cmd='strix', **extra)

    def test_pentest_runs_after_an_existing_dast_success_without_rescanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh(dast='success')
            done = agent.poll_once(gh, self.cfg(tmp), None, self.pentest())
            self.assertEqual(done, [(self.SHA, 'pt-success')])
            self.assertEqual([w[1] for w in gh.pt_written], ['pending', 'success'])
            self.assertIn('PT agentico: PASS - score 100/100', gh.pt_written[-1][2])
            self.assertEqual(gh.written, [])
            self.assertEqual(agent.poll_once(gh, self.cfg(tmp), None, self.pentest()), [])
            self.assertEqual(len(self.calls), 1)

    def test_dast_and_pentest_in_the_same_round(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh()
            scan = lambda candidate, cfg: dict(agent.evaluate(REAL_TEST_C, ORIGIN), report_dir=tmp)
            done = agent.poll_once(gh, self.cfg(tmp), scan, self.pentest())
            self.assertEqual(done, [(self.SHA, 'success'), (self.SHA, 'pt-success')])

    def test_high_finding_fails_the_pentest_state(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh(dast='success')
            done = agent.poll_once(gh, self.cfg(tmp), None, self.pentest([finding('high')]))
            self.assertEqual(done, [(self.SHA, 'pt-failure')])
            self.assertEqual(gh.pt_written[-1][1], 'failure')
            self.assertIn('bloccanti 1', gh.pt_written[-1][2])

    def test_pentest_is_not_run_when_dast_did_not_pass(self):
        for state in ('failure', 'error'):
            with tempfile.TemporaryDirectory() as tmp:
                gh = self.gh(dast=state)
                done = agent.poll_once(gh, self.cfg(tmp), None, self.pentest())
                self.assertEqual(done, [(self.SHA, 'pt-not-run')])
                self.assertEqual([w[1] for w in gh.pt_written], ['failure'])
                self.assertIn('non eseguito', gh.pt_written[-1][2])
        self.assertEqual(self.calls, [])

    def test_dast_failing_now_marks_the_pentest_as_not_run_in_the_same_round(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh()
            scan = lambda candidate, cfg: dict(agent.evaluate(report(CSP_MISSING), ORIGIN), report_dir=tmp)
            done = agent.poll_once(gh, self.cfg(tmp), scan, self.pentest())
            self.assertEqual(done, [(self.SHA, 'failure'), (self.SHA, 'pt-not-run')])
            self.assertEqual(self.calls, [])

    def test_stale_pending_pentest_is_resumed_without_rescanning(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh(dast='success', pt='pending')
            done = agent.poll_once(gh, self.cfg(tmp), None, self.pentest())
            self.assertEqual((done, gh.written, len(self.calls)), ([(self.SHA, 'pt-success')], [], 1))

    def test_final_pentest_state_is_left_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            for state in agent.FINAL_STATES:
                gh = self.gh(dast='success', pt=state)
                self.assertEqual(agent.poll_once(gh, self.cfg(tmp), None, self.pentest()), [])
                self.assertEqual(gh.pt_written, [])

    def test_pentest_error_writes_error_never_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            for error in (agent.ScanError('strix terminato con codice 1\ndettaglio'), ValueError('report non valido')):
                gh = self.gh(dast='success')
                done = agent.poll_once(gh, self.cfg(tmp), None, self.pentest(error=error))
                self.assertEqual(done, [(self.SHA, 'pt-error')])
                self.assertEqual([w[1] for w in gh.pt_written], ['pending', 'error'])
                self.assertNotIn('\n', gh.pt_written[-1][2])

    def test_pentest_waits_while_dast_waits_for_sast(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh()
            done = agent.poll_once(gh, self.cfg(tmp, require_check=SAST), None, self.pentest())
            self.assertEqual((done, gh.written, gh.pt_written, self.calls), ([], [], [], []))

    def test_without_pentest_option_nothing_is_written_or_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh(dast='success')
            self.assertEqual(agent.poll_once(gh, config(tmp), None, self.pentest()), [])
            self.assertEqual((gh.pt_written, self.calls), ([], []))

    def test_dry_run_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh(dast='success')
            cfg = self.cfg(tmp, dry_run=True)
            self.assertEqual(agent.poll_once(gh, cfg, None, self.pentest()), [(self.SHA, 'dry-run-pt')])
            self.assertEqual(agent.poll_once(gh, cfg, None, self.pentest()), [])
            self.assertEqual((gh.written, gh.pt_written, self.calls), ([], [], []))

    def test_real_pentest_does_not_run_on_a_simulated_dast(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh(dast='success', dast_description='[SIMULATO] DAST esterno: PASS - score 92/100')
            done = agent.poll_once(gh, self.cfg(tmp), None, self.pentest())
            self.assertEqual((done, self.calls), ([(self.SHA, 'pt-not-run')], []))
            self.assertEqual(gh.pt_written[-1][1], 'failure')
            self.assertIn('simulato', gh.pt_written[-1][2])

    def test_simulated_pentest_is_labelled_and_runs_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            gh = self.gh(dast='success', dast_description='[SIMULATO] DAST esterno: PASS - score 92/100')

            def forbidden(*args, **kwargs):
                raise AssertionError('nessun comando deve essere eseguito in simulazione')

            pentest = lambda candidate, cfg: agent.simulate_pentest(candidate, cfg, run=forbidden)
            done = agent.poll_once(gh, self.cfg(tmp, simulate=True), None, pentest)
            self.assertEqual(done, [(self.SHA, 'pt-success')])
            self.assertTrue(gh.pt_written[-1][2].startswith('[SIMULATO] '))


class RunCommandTests(unittest.TestCase):
    def test_timeout_sends_sigterm_before_killing(self):
        with tempfile.TemporaryDirectory() as tmp:
            marker = Path(tmp) / 'terminato'
            script = f'trap "echo ok > {marker}; exit 0" TERM; sleep 30 & wait'
            with self.assertRaises(agent.ScanError) as caught, contextlib.redirect_stdout(io.StringIO()):
                agent.run_cmd(['sh', '-c', script], timeout=1)
            self.assertIn('tempo massimo superato', str(caught.exception))
            self.assertTrue(marker.is_file())

    def test_output_exit_code_and_missing_command(self):
        with contextlib.redirect_stdout(io.StringIO()):
            proc = agent.run_cmd(['sh', '-c', 'echo fatto; exit 3'], check=False)
            self.assertEqual((proc.returncode, proc.stdout.strip()), (3, 'fatto'))
            with self.assertRaises(agent.ScanError):
                agent.run_cmd(['sh', '-c', 'exit 3'])
            with self.assertRaises(agent.ScanError):
                agent.run_cmd(['comando-che-non-esiste-xyz'])


class PentestCommandLineTests(unittest.TestCase):
    def quiet(self, argv):
        with self.assertRaises(SystemExit) as caught, contextlib.redirect_stderr(io.StringIO()):
            agent.parse_args(argv)
        return caught.exception.code

    def test_pentest_requires_explicit_authorization(self):
        self.assertEqual(self.quiet(['--repo', SLUG, '--pentest-cmd', 'strix']), 2)
        args = agent.parse_args(['--repo', SLUG, '--pentest-cmd', 'strix', '--pentest-authorized'])
        cfg = agent.build_config(args, None)
        self.assertEqual((cfg['pentest_cmd'], cfg['pentest_mode'], cfg['pentest_budget'], cfg['pentest_timeout']),
                         ('strix', 'quick', None, 60))

    def test_dry_run_and_simulation_do_not_require_authorization(self):
        for flag in ('--dry-run', '--simulate'):
            self.assertEqual(agent.parse_args(['--repo', SLUG, '--pentest-cmd', 'strix', flag]).pentest_cmd, 'strix')

    def test_pentest_is_off_by_default(self):
        self.assertIsNone(agent.build_config(agent.parse_args(['--repo', SLUG]), None)['pentest_cmd'])

    def test_invalid_pentest_values_are_rejected(self):
        base = ['--repo', SLUG, '--pentest-cmd', 'strix', '--pentest-authorized']
        self.assertEqual(self.quiet(base + ['--pentest-budget', '0']), 2)
        self.assertEqual(self.quiet(base + ['--pentest-timeout', '0']), 2)
        self.assertEqual(self.quiet(base + ['--pentest-mode', 'aggressivo']), 2)


class CommandLineTests(unittest.TestCase):
    def test_repo_must_be_owner_slash_name(self):
        with self.assertRaises(SystemExit):
            agent.main(['--repo', 'senza-barra', '--dry-run', '--once'])


if __name__ == '__main__':
    unittest.main()
