"""Exercise the CA install step with isolated paths and a mock trust-store updater."""
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_auth import ROOT, extract_step


CERT_A = '-----BEGIN CERTIFICATE-----\nYQ==\n-----END CERTIFICATE-----\n'
CERT_B = '-----BEGIN CERTIFICATE-----\nYg==\n-----END CERTIFICATE-----\n'


class CorporateCATests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / 'source'
        self.target = self.root / 'target'
        self.source.mkdir()
        self.target.mkdir()
        self.script = extract_step(
            'Install corporate root CA certificate(s) into the system trust store'
        ).replace('/home/agent/corp-ca', str(self.source)).replace(
            '/usr/local/share/ca-certificates', str(self.target))
        updater = self.root / 'update-ca-certificates'
        updater.write_text('#!/bin/sh\necho update-ca-certificates-called\n')
        updater.chmod(0o755)
        self.env = {**os.environ, 'PATH': str(self.root) + ':' + os.environ['PATH']}
        self.env.pop('SNYK_CORP_CA_PEM', None)

    def run_step(self, pem=None):
        env = dict(self.env)
        if pem is not None:
            env['SNYK_CORP_CA_PEM'] = pem
        return subprocess.run(['sh', '-c', self.script], env=env,
                              capture_output=True, text=True)

    def test_v3_hook_declares_env_input(self):
        kit = (ROOT / 'snyk-evo-ads.yaml').read_text()
        self.assertTrue(kit.startswith('# syntax=docker/sandbox-kit:3\n'))
        lifecycle = kit.split('type: com.docker.sandbox/lifecycle@1', 1)[1]
        hook = lifecycle.split(
            'description: "Install corporate root CA certificate(s) into the system trust store"',
            1)[1].split('command: |', 1)[0]
        self.assertIn('env: [SNYK_CORP_CA_PEM]', hook)

    def test_unset_warns_and_continues(self):
        result = self.run_step()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('WARNING no .crt files found', result.stderr)
        self.assertNotIn('update-ca-certificates-called', result.stdout)

    def test_empty_warns_and_continues(self):
        result = self.run_step('')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('continuing without a corporate root CA', result.stderr)
        self.assertNotIn('update-ca-certificates-called', result.stdout)

    def test_single_env_cert(self):
        result = self.run_step(CERT_A.rstrip('\n'))
        self.assertEqual(result.returncode, 0, result.stderr)
        cert = self.target / 'corp-ca-env.crt'
        self.assertEqual(cert.read_text(), CERT_A)
        self.assertEqual(cert.stat().st_mode & 0o777, 0o644)
        self.assertIn('corp-ca: staged corp-ca-env.crt', result.stdout)
        self.assertIn('installed 1 certificate(s)', result.stdout)
        self.assertIn('update-ca-certificates-called', result.stdout)

    def test_multi_cert_splits_into_one_cert_per_file(self):
        result = self.run_step(CERT_A + '\n' + CERT_B)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.target / 'corp-ca-env.crt').read_text(), CERT_A)
        self.assertEqual((self.target / 'corp-ca-env-2.crt').read_text(), CERT_B)
        self.assertIn('staged corp-ca-env-2.crt', result.stdout)
        self.assertIn('installed 2 certificate(s)', result.stdout)

    def test_crlf_is_normalized(self):
        result = self.run_step(CERT_A.replace('\n', '\r\n'))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.target / 'corp-ca-env.crt').read_text(), CERT_A)

    def test_file_path_works_alone_and_with_env(self):
        (self.source / 'local.crt').write_text(CERT_B)
        (self.source / 'ignored.pem').write_text(CERT_A)
        for pem, count in ((None, 1), (CERT_A, 2)):
            with self.subTest(pem=pem):
                result = self.run_step(pem)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual((self.target / 'local.crt').read_text(), CERT_B)
                self.assertFalse((self.target / 'ignored.pem').exists())
                self.assertIn(f'installed {count} certificate(s)', result.stdout)
                self.assertNotIn('WARNING', result.stderr)

    def test_incomplete_or_non_pem_input_fails(self):
        for pem in ('not a PEM', CERT_A.split('-----END')[0],
                    '-----BEGIN CERTIFICATE-----\n' + CERT_A):
            with self.subTest(pem=pem):
                result = self.run_step(pem)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('must contain complete PEM certificates', result.stderr)
                self.assertNotIn('update-ca-certificates-called', result.stdout)


if __name__ == '__main__':
    unittest.main()
