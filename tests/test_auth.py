"""Exercise standalone and enterprise selection without real credentials or scans."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TENANT = "12345678-1234-1234-1234-123456789abc"


def install_script(kit):
    lines = (ROOT / kit / 'spec.yaml').read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if 'description: "Install Snyk security tools"' in line) + 3
    body = []
    for line in lines[start:]:
        if line.strip() and not line.startswith('        '):
            break
        body.append(line[8:])
    return '\n'.join(body)


class AuthTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        shutil.copytree(ROOT / 'snyk-ads/files/home/.snyk-kit', self.home / '.snyk-kit')
        self.bin = self.home / 'bin'
        self.bin.mkdir()
        self.env = {**os.environ, 'HOME': str(self.home), 'PATH': str(self.bin) + ':' + os.environ['PATH'],
                    'SNYK_TOKEN': 'test-token', 'SNYK_TENANT_ID': '', 'SNYK_ADS_PUSH_KEY': '',
                    'SANDBOX_NAME': 'test', 'SANDBOX_ID': '123', 'MOCK_ARCH': 'x86_64',
                    'MOCK_CURL_RC': '0', 'MOCK_SHA_RC': '0'}

    def executable(self, name, content):
        path = self.bin / name
        path.write_text('#!/bin/sh\n' + content)
        path.chmod(0o755)

    def test_auth_matrix(self):
        for tenant, key, token, expected in (
            ('', '', 'token', 'standalone'), ('invalid', '', 'token', 'standalone'),
            (TENANT, 'key', '', 'enterprise'), (TENANT, 'key', 'token', 'enterprise'),
            ('', 'key', 'token', None), ('invalid', 'key', '', None), (TENANT, '', '', None),
        ):
            with self.subTest(expected=expected):
                result = subprocess.run(['sh', str(self.home / '.snyk-kit/auth.sh')], env={
                    **self.env, 'SNYK_TENANT_ID': tenant, 'SNYK_ADS_PUSH_KEY': key, 'SNYK_TOKEN': token,
                }, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if expected else 1)
                if expected:
                    self.assertEqual(result.stdout.strip(), expected)

    def test_token_only_without_credential_defaults(self):
        kit = 'snyk-ads'
        spec = (ROOT / kit / 'spec.yaml').read_text()
        environment = spec.split('environment:\n', 1)[1].split('\npermissions:', 1)[0]
        for name in ('SNYK_TOKEN', 'SNYK_TENANT_ID', 'SNYK_ADS_PUSH_KEY'):
            self.assertNotIn(name + ':', environment)
        env = {k: v for k, v in self.env.items()
               if k not in ('SNYK_TENANT_ID', 'SNYK_ADS_PUSH_KEY')}
        result = subprocess.run(
            ['sh', str(ROOT / kit / 'files/home/.snyk-kit/auth.sh')],
            env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'standalone')

    def mock_download(self):
        self.executable('uname', 'echo "$MOCK_ARCH"\n')
        self.executable('curl', '''[ "$MOCK_CURL_RC" = 0 ] || exit "$MOCK_CURL_RC"
for arg in "$@"; do
  case "$arg" in
    https://github.com/snyk/agent-scan/releases/latest)
      echo "https://github.com/snyk/agent-scan/releases/tag/v0.9.7"; exit 0;;
    https://github.com/snyk/agent-scan/releases/download/*)
      url="$arg"; echo "$arg" >> "$HOME/downloads";;
    *downloads.snyk.io*) exit 99;; esac
done
while [ "$1" != -o ]; do shift; done
shift
case "$url" in */checksums.txt)
  printf '%s  %s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa agent-scan-0.9.7-linux-x86_64 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb agent-scan-0.9.7-linux-arm64 > "$1"
  exit 0;; esac
cat > "$1" <<'SCAN' 
#!/bin/sh
printf '%s\\n' "$*" >> "$HOME/scans"
[ "$SNYK_TOKEN" = test-token ]
SCAN
''')
        self.executable('sha256sum', 'cat > "$HOME/checksum"; exit "$MOCK_SHA_RC"\n')

    def test_standalone_install_bypasses_ads(self):
        self.mock_download()
        kit = 'snyk-ads'
        result = subprocess.run(['sh', '-c', install_script(kit)], env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('agent-scan-0.9.7-linux-x86_64', (self.home / 'downloads').read_text())
        self.assertIn('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', (self.home / 'checksum').read_text())
        self.assertFalse((self.home / 'scans').exists())
        self.assertFalse((self.home / '.snyk/ads-auth').exists())

    def test_arm64_asset(self):
        self.mock_download()
        result = subprocess.run(['sh', str(self.home / '.snyk-kit/install-agent-scan.sh')],
                                env={**self.env, 'MOCK_ARCH': 'aarch64'}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('linux-arm64', (self.home / 'downloads').read_text())
        self.assertIn('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', (self.home / 'checksum').read_text())

    def test_download_and_checksum_failures_stop_install(self):
        self.mock_download()
        for env in ({'MOCK_CURL_RC': '22'}, {'MOCK_SHA_RC': '1'}, {'MOCK_ARCH': 'unsupported'}):
            with self.subTest(env=env):
                result = subprocess.run(['sh', '-c', install_script('snyk-ads')],
                                        env={**self.env, **env}, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.home / '.local/share/snyk-agent-scan/agent-scan').exists())

    def test_component_inventory_and_scan_lookup(self):
        helper = str(self.home / '.snyk-kit/ads-components.sh')
        directory = self.home / '.ads-scan/bin'
        directory.mkdir(parents=True)
        self.executable('uname', 'echo "$MOCK_ARCH"\n')
        for arch in ('arm64', 'x86_64'):
            for mask in range(8):
                with self.subTest(arch=arch, components=mask):
                    for file in directory.iterdir():
                        file.unlink()
                    for index, component in enumerate(('scan', 'guard', 'studio-installer')):
                        if mask & (1 << index):
                            path = directory / f'snyk-{component}-linux-{arch}'
                            path.write_text('#!/bin/sh\nexit 0\n')
                            path.chmod(0o755)
                    env = {**self.env, 'MOCK_ARCH': arch, 'PATH': str(self.bin) + ':/usr/bin:/bin'}
                    report = subprocess.run(['sh', helper, 'report'], env=env, capture_output=True, text=True)
                    self.assertEqual(report.returncode, 0, report.stderr)
                    for index, label in enumerate(('Scan', 'Guard', 'Studio')):
                        expected = 'downloaded (' if mask & (1 << index) else 'not downloaded;'
                        self.assertIn(f'{label}: {expected}', report.stdout)
                    lookup = subprocess.run(['sh', helper, 'scan'], env=env, capture_output=True, text=True)
                    if mask & 1:
                        self.assertEqual(lookup.returncode, 0)
                        self.assertEqual(lookup.stdout.strip(), str(directory / f'snyk-scan-linux-{arch}'))
                    else:
                        self.assertNotEqual(lookup.returncode, 0)

    def test_recurring_scan_arguments(self):
        text = (ROOT / 'snyk-ads/spec.yaml').read_text()
        tail = text[text.index('          SCAN_ARGS=(scan'):]
        script = '\n'.join(line[10:] for line in tail.splitlines())
        for mode in ('standalone', 'enterprise'):
            prefix = '''SCAN=mock_scan
MACHINE_ID=docker-sbx:test:123
attempt=0
wait=0
mock_scan() { attempt=$((attempt+1)); echo "scan:$*"; [ "$attempt" -gt 1 ]; }
sleep() { [ "$1" = 900 ] || exit 99; wait=$((wait+1)); [ "$wait" -lt 2 ]; }
'''
            result = subprocess.run(['bash', '-c', prefix + script], env={**self.env, 'AUTH_MODE': mode,
                                    'SNYK_ADS_PUSH_KEY': 'test-key'}, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            scans = [line for line in result.stdout.splitlines() if line.startswith('scan:')]
            self.assertEqual(len(scans), 2)
            self.assertEqual('--push-key test-key' in scans[0], mode == 'enterprise')
            self.assertIn('exited non-zero', result.stdout)
            self.assertNotIn('test-token', result.stdout)


if __name__ == '__main__':
    unittest.main()
