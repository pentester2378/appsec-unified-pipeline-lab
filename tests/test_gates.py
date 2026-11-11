import copy
import json
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'scripts'))
from sast_gate import find_blocking, run
from dast_gate import evaluate

F = ROOT / 'tests' / 'fixtures'


class SASTGateTests(unittest.TestCase):
    def test_block_high(self):
        self.assertEqual(len(find_blocking(json.loads((F / 'sast-high.sarif').read_text()))), 1)

    def test_allow_low(self):
        self.assertEqual(run(F / 'sast-good.sarif')['status'], 'PASS')

    def test_reject_empty(self):
        with self.assertRaises(ValueError):
            find_blocking({'version': '2.1.0', 'runs': []})

    def test_reject_missing_sarif(self):
        with tempfile.TemporaryDirectory() as td:
            with self.assertRaises(ValueError):
                run(Path(td))


class DASTGateTests(unittest.TestCase):
    def load(self, name):
        return json.loads((F / name).read_text())

    def test_block_missing_csp(self):
        self.assertEqual(evaluate(self.load('zap-csp-missing.json'), 'http://app:3000')['status'], 'FAIL')

    def test_allow_other_medium(self):
        self.assertEqual(evaluate(self.load('zap-good.json'), 'http://app:3000')['status'], 'PASS')

    def test_block_high_confident(self):
        self.assertEqual(evaluate(self.load('zap-high.json'), 'http://app:3000')['status'], 'FAIL')

    def test_invalid_no_sites(self):
        with self.assertRaises(ValueError):
            evaluate({'site': []}, 'http://app:3000')

    def test_out_of_scope(self):
        d = self.load('zap-good.json')
        d['site'][0]['@name'] = 'https://example.org'
        with self.assertRaises(ValueError):
            evaluate(d, 'http://app:3000')

    def test_low_confidence_high_not_auto_blocked_by_demo(self):
        d = self.load('zap-high.json')
        d['site'][0]['alerts'][0]['confidence'] = '1'
        self.assertEqual(evaluate(d, 'http://app:3000')['status'], 'PASS')


if __name__ == '__main__':
    unittest.main()
