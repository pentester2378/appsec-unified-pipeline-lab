"""Controlli strutturali sul workflow SAST multi-strumento.

Leggono il file come testo, senza librerie YAML: la pipeline esistente esegue questi test
con il python3 di sistema del runner.
"""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / '.github' / 'workflows' / 'sast-multi.yml'
TOOLS = ('codeql', 'semgrep', 'gitleaks', 'trivy')
JOB_NAMES = ('S1 SAST - CodeQL', 'S2 SAST - Semgrep', 'S3 SECRETS - Gitleaks', 'S4 SCA-IAC - Trivy',
             'SAST AGGREGATO')
PINNED_ACTION = re.compile(r'^(actions|github)/[A-Za-z0-9_./-]+@[0-9a-f]{40}$')
PINNED_IMAGE = re.compile(r'^[a-z0-9./-]+:v?\d+\.\d+\.\d+$')


class WorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.text = WORKFLOW.read_text(encoding='utf-8')
        cls.lines = [line.split(' #')[0].rstrip() for line in cls.text.splitlines()]

    def values(self, key):
        found = []
        for line in self.lines:
            match = re.match(rf'^\s*(?:- )?{key}:\s*(\S.*)$', line)
            if match:
                found.append(match.group(1).strip().strip('\'"'))
        return found

    def test_job_names(self):
        self.assertEqual(self.values('name')[0], 'SAST multi-strumento')
        for name in JOB_NAMES:
            self.assertEqual(self.values('name').count(name), 1, name)

    def test_actions_are_first_party_and_pinned_to_a_commit(self):
        uses = self.values('uses')
        self.assertGreaterEqual(len(uses), 10)
        for value in uses:
            self.assertRegex(value, PINNED_ACTION)

    def test_tool_images_are_pinned_to_a_version(self):
        images = self.values('image') + re.findall(r'^\s+((?:ghcr\.io/|aquasec/)\S+)', self.text, re.MULTILINE)
        self.assertEqual(len(images), 3)
        for image in images:
            self.assertRegex(image.rstrip(' \\'), PINNED_IMAGE)

    def test_gate_expects_exactly_the_tool_jobs(self):
        expect = re.search(r'--expect (\S+)', self.text).group(1)
        self.assertEqual(tuple(expect.split(',')), TOOLS)
        for tool in TOOLS:
            self.assertEqual(self.values('name').count(f'sast-multi-{tool}'), 1, tool)
        needs = re.search(r'needs:\s*\[([^\]]+)\]', self.text).group(1)
        self.assertEqual(tuple(item.strip() for item in needs.split(',')), TOOLS)

    def test_gate_always_runs_and_evidence_does_not_match_the_download_pattern(self):
        gate = self.text.split('name: SAST AGGREGATO')[1]
        self.assertIn('if: always()', gate)
        self.assertIn('pattern: sast-multi-*', gate)
        self.assertIn('name: sast-aggregato-evidence', gate)
        self.assertIn('scripts/sast_multi_gate.py', gate)

    def test_gate_receives_the_result_of_every_tool_job(self):
        gate = self.text.split('name: SAST AGGREGATO')[1]
        for tool in TOOLS:
            self.assertIn(f'{tool.upper()}_RESULT: ${{{{ needs.{tool}.result }}}}', gate)
            self.assertIn(f'--job-result "{tool}=${tool.upper()}_RESULT"', gate)

    def test_triggers_and_permissions(self):
        self.assertIn('pull_request:', self.text)
        self.assertIn('workflow_dispatch:', self.text)
        self.assertNotIn('pull_request_target', self.text)
        top = self.text.split('jobs:')[0]
        self.assertRegex(top, r'permissions:\n  contents: read\n')
        self.assertNotIn('write', top)

    def test_no_untrusted_expression_in_scripts(self):
        self.assertNotIn('github.event.', self.text)
        self.assertNotIn('github.head_ref', self.text)

    def test_secrets_are_redacted_and_tools_do_not_fail_on_findings(self):
        self.assertIn('--redact', self.text)
        self.assertEqual(self.text.count('--exit-code 0'), 2)
        self.assertNotIn('--error', self.text)
        self.assertIn('upload: never', self.text)

    def test_code_scanning_upload_cannot_break_a_tool_job(self):
        blocks = self.text.split('github/codeql-action/upload-sarif@')
        self.assertEqual(len(blocks), 4)
        for block in blocks[:-1]:
            self.assertIn('continue-on-error: true', block.split('- name:')[-1])


if __name__ == '__main__':
    unittest.main()
