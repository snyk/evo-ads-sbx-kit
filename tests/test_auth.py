"""Exercise component selection, credential validation, and installs without
real credentials, network access, or scans."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
KIT = 'snyk-ads'


def _dedent_block(after_pipe):
    """Dedent a YAML literal block scalar's body, starting right after its `|`."""
    lines = after_pipe.split('\n')
    base_indent = None
    body = []
    for line in lines:
        if base_indent is None:
            if line.strip() == '':
                continue
            base_indent = len(line) - len(line.lstrip(' '))
        if line.strip() == '':
            body.append('')
            continue
        indent = len(line) - len(line.lstrip(' '))
        if indent < base_indent:
            break
        body.append(line[base_indent:])
    return '\n'.join(body).rstrip('\n')


def extract_step(description):
    """Return the dedented `command` body of the install/startup step named `description`."""
    text = (ROOT / KIT / 'spec.yaml').read_text()
    marker = f'description: "{description}"\n'
    idx = text.index(marker)
    rest = text[idx + len(marker):]
    pipe_idx = rest.index('|\n')
    return _dedent_block(rest[pipe_idx + 2:])


class KitTestCase(unittest.TestCase):
    """Common sandbox: a fake $HOME with the kit's helper scripts and a mock PATH."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        shutil.copytree(ROOT / KIT / 'files/home/.snyk-kit', self.home / '.snyk-kit')
        self.bin = self.home / 'bin'
        self.bin.mkdir()
        self.env = {
            **os.environ, 'HOME': str(self.home), 'PATH': str(self.bin) + ':' + os.environ['PATH'],
            'SNYK_TOKEN': '', 'SNYK_TENANT_ID': '', 'SNYK_ADS_PUSH_KEY': '', 'SNYK_COMPONENTS': '',
            'SANDBOX_NAME': 'test', 'SANDBOX_ID': '123', 'MOCK_ARCH': 'x86_64',
            'MOCK_CURL_RC': '0', 'MOCK_SHA_RC': '0',
        }

    def executable(self, name, content):
        path = self.bin / name
        path.write_text('#!/bin/sh\n' + content)
        path.chmod(0o755)

    def resolve_components(self, **overrides):
        return subprocess.run(
            ['sh', str(self.home / '.snyk-kit/resolve-components.sh')],
            env={**self.env, **overrides}, capture_output=True, text=True)


class AuthShTests(KitTestCase):
    def test_classification(self):
        for tenant, key, token, expected in (
            ('', '', '', 'none'),
            ('', '', 'token', 'standalone'),
            ('', 'key', '', 'enterprise'),
            ('', 'key', 'token', 'enterprise'),
            # A push key selects enterprise regardless of tenant ID: guard install
            # runs headless and only needs SNYK_TENANT_ID for the interactive
            # push-key-minting flow this kit never uses.
            ('not-a-uuid', 'key', '', 'enterprise'),
            ('12345678-1234-1234-1234-123456789abc', 'key', '', 'enterprise'),
        ):
            with self.subTest(tenant=tenant, key=key, token=token):
                result = subprocess.run(['sh', str(self.home / '.snyk-kit/auth.sh')], env={
                    **self.env, 'SNYK_TENANT_ID': tenant, 'SNYK_ADS_PUSH_KEY': key, 'SNYK_TOKEN': token,
                }, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected)


class ResolveComponentsTests(KitTestCase):
    def test_defaults_to_scan_only(self):
        result = self.resolve_components(SNYK_TOKEN='token')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'scan=1 guard=0 studio=0 auth_mode=standalone')

    def test_explicit_selection_is_case_and_space_insensitive(self):
        result = self.resolve_components(SNYK_COMPONENTS=' Scan, GUARD ,studio', SNYK_ADS_PUSH_KEY='key')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'scan=1 guard=1 studio=1 auth_mode=enterprise')

    def test_studio_alone_needs_no_credentials(self):
        result = self.resolve_components(SNYK_COMPONENTS='studio')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'scan=0 guard=0 studio=1 auth_mode=none')

    def test_guard_without_push_key_fails(self):
        result = self.resolve_components(SNYK_COMPONENTS='guard', SNYK_TOKEN='token')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('guard requires SNYK_ADS_PUSH_KEY', result.stderr)

    def test_scan_without_any_credential_fails(self):
        result = self.resolve_components(SNYK_COMPONENTS='scan')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('scan requires SNYK_TOKEN or SNYK_ADS_PUSH_KEY', result.stderr)

    def test_scan_accepts_push_key_without_token(self):
        result = self.resolve_components(SNYK_COMPONENTS='scan', SNYK_ADS_PUSH_KEY='key')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'scan=1 guard=0 studio=0 auth_mode=enterprise')

    def test_unknown_component_fails(self):
        result = self.resolve_components(SNYK_COMPONENTS='scn', SNYK_TOKEN='token')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown component 'scn'", result.stderr)

    def test_components_that_parse_to_nothing_fail(self):
        # Whitespace/comma-only values pass the loop with zero iterations rather
        # than an unknown-component error, so this needs its own guard.
        for raw in (' ', ',', ' , , '):
            with self.subTest(raw=raw):
                result = self.resolve_components(SNYK_COMPONENTS=raw, SNYK_TOKEN='token')
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('resolved to no components', result.stderr)


class InstallAgentScanShTests(KitTestCase):
    """install-agent-scan.sh downloads the same binary used for both scan and guard."""

    def mock_github(self):
        self.executable('uname', 'echo "$MOCK_ARCH"\n')
        self.executable('curl', '''[ "$MOCK_CURL_RC" = 0 ] || exit "$MOCK_CURL_RC"
for arg in "$@"; do
  case "$arg" in
    https://github.com/snyk/agent-scan/releases/latest)
      echo "https://github.com/snyk/agent-scan/releases/tag/v0.9.7"; exit 0;;
    https://github.com/snyk/agent-scan/releases/download/*)
      url="$arg"; echo "$arg" >> "$HOME/downloads";;
  esac
done
while [ "$1" != -o ]; do shift; done
shift
case "$url" in */checksums.txt)
  printf '%s  %s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa agent-scan-0.9.7-linux-x86_64 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb agent-scan-0.9.7-linux-arm64 > "$1"
  exit 0;; esac
cat > "$1" <<'SCAN'
#!/bin/sh
printf '%s\\n' "$*" >> "$HOME/scans"
case "$1" in
  guard) exit 0 ;;
  *) [ "$SNYK_TOKEN" = test-token ] ;;
esac
SCAN
''')
        self.executable('sha256sum', 'cat > "$HOME/checksum"; exit "$MOCK_SHA_RC"\n')

    def test_downloads_and_verifies_binary(self):
        self.mock_github()
        result = subprocess.run(['sh', str(self.home / '.snyk-kit/install-agent-scan.sh')],
                                 env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('agent-scan-0.9.7-linux-x86_64', (self.home / 'downloads').read_text())
        self.assertIn('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                       (self.home / 'checksum').read_text())
        binary = self.home / '.local/share/snyk-agent-scan/agent-scan'
        self.assertTrue(binary.exists())
        self.assertTrue(os.access(binary, os.X_OK))

    def test_arm64_asset(self):
        self.mock_github()
        result = subprocess.run(['sh', str(self.home / '.snyk-kit/install-agent-scan.sh')],
                                 env={**self.env, 'MOCK_ARCH': 'aarch64'}, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('linux-arm64', (self.home / 'downloads').read_text())
        self.assertIn('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                       (self.home / 'checksum').read_text())

    def test_download_and_checksum_failures_stop_install(self):
        self.mock_github()
        for overrides in ({'MOCK_CURL_RC': '22'}, {'MOCK_SHA_RC': '1'}, {'MOCK_ARCH': 'unsupported'}):
            with self.subTest(overrides=overrides):
                result = subprocess.run(['sh', str(self.home / '.snyk-kit/install-agent-scan.sh')],
                                         env={**self.env, **overrides}, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.home / '.local/share/snyk-agent-scan/agent-scan').exists())


class InstallStudioShTests(KitTestCase):
    def mock_github(self):
        self.executable('uname', 'echo "$MOCK_ARCH"\n')
        self.executable('curl', '''[ "$MOCK_CURL_RC" = 0 ] || exit "$MOCK_CURL_RC"
for arg in "$@"; do
  case "$arg" in
    https://github.com/snyk/studio-recipes/releases/latest)
      echo "https://github.com/snyk/studio-recipes/releases/tag/v1.0.16"; exit 0;;
    https://github.com/snyk/studio-recipes/releases/download/*)
      url="$arg"; echo "$arg" >> "$HOME/downloads";;
  esac
done
while [ "$1" != -o ]; do shift; done
shift
case "$url" in */checksums.txt)
  printf '%s  %s\\n' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc snyk-studio-1.0.16-linux-x86_64 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd snyk-studio-1.0.16-linux-arm64 > "$1"
  exit 0;; esac
cat > "$1" <<'STUDIO'
#!/bin/sh
printf '%s\\n' "$*" >> "$HOME/studio-invocations"
STUDIO
''')
        self.executable('sha256sum', 'cat > "$HOME/checksum"; exit "$MOCK_SHA_RC"\n')

    def test_downloads_verifies_and_invokes_installer(self):
        self.mock_github()
        result = subprocess.run(['sh', str(self.home / '.snyk-kit/install-studio.sh')],
                                 env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('snyk-studio-1.0.16-linux-x86_64', (self.home / 'downloads').read_text())
        binary = self.home / '.local/share/snyk-studio/snyk-studio-installer'
        self.assertTrue(binary.exists())
        self.assertTrue(os.access(binary, os.X_OK))
        self.assertEqual((self.home / 'studio-invocations').read_text().strip(),
                          'install -y --no-latest-deps')

    def test_download_and_checksum_failures_stop_install(self):
        self.mock_github()
        for overrides in ({'MOCK_CURL_RC': '22'}, {'MOCK_SHA_RC': '1'}, {'MOCK_ARCH': 'unsupported'}):
            with self.subTest(overrides=overrides):
                result = subprocess.run(['sh', str(self.home / '.snyk-kit/install-studio.sh')],
                                         env={**self.env, **overrides}, capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.home / '.local/share/snyk-studio/snyk-studio-installer').exists())


class InstallScanAndGuardStepTests(KitTestCase):
    """spec.yaml's "Install AgentScan and/or Guard" step."""

    def setUp(self):
        super().setUp()
        self.script = extract_step('Install AgentScan and/or Guard')
        self.executable('uname', 'echo "$MOCK_ARCH"\n')
        self.executable('curl', '''[ "$MOCK_CURL_RC" = 0 ] || exit "$MOCK_CURL_RC"
for arg in "$@"; do
  case "$arg" in
    https://github.com/snyk/agent-scan/releases/latest)
      echo "https://github.com/snyk/agent-scan/releases/tag/v0.9.7"; exit 0;;
    https://github.com/snyk/agent-scan/releases/download/*) url="$arg";;
  esac
done
while [ "$1" != -o ]; do shift; done
shift
case "$url" in */checksums.txt)
  printf '%s  %s\\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa agent-scan-0.9.7-linux-x86_64 > "$1"
  exit 0;; esac
cat > "$1" <<'SCAN'
#!/bin/sh
printf '%s\\n' "$*" >> "$HOME/guard-invocations"
printf 'env PUSH_KEY=%s TENANT_ID=%s MACHINE_ID=%s\\n' "$PUSH_KEY" "$TENANT_ID" "$MACHINE_ID" >> "$HOME/guard-invocations"
exit 0
SCAN
''')
        self.executable('sha256sum', 'cat > "$HOME/checksum"; exit 0\n')

    def run_step(self, **overrides):
        return subprocess.run(['sh', '-c', self.script], env={**self.env, **overrides},
                               capture_output=True, text=True)

    def test_skips_when_neither_scan_nor_guard_requested(self):
        result = self.run_step(SNYK_COMPONENTS='studio')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('skipping AgentScan install', result.stdout)
        self.assertFalse((self.home / '.local/share/snyk-agent-scan/agent-scan').exists())

    def test_scan_only_installs_binary_without_guard_call(self):
        result = self.run_step(SNYK_COMPONENTS='scan', SNYK_TOKEN='token')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.home / '.local/share/snyk-agent-scan/agent-scan').exists())
        self.assertFalse((self.home / 'guard-invocations').exists())

    def test_guard_installs_binary_and_calls_guard_install_with_correct_identity(self):
        result = self.run_step(SNYK_COMPONENTS='scan,guard', SNYK_ADS_PUSH_KEY='push-key-value')
        self.assertEqual(result.returncode, 0, result.stderr)
        invocations = (self.home / 'guard-invocations').read_text()
        self.assertIn('guard install claude', invocations)
        self.assertIn('env PUSH_KEY=push-key-value TENANT_ID= MACHINE_ID=docker-sbx:test:123', invocations)

    def test_guard_forwards_tenant_id_when_supplied(self):
        result = self.run_step(SNYK_COMPONENTS='guard', SNYK_ADS_PUSH_KEY='push-key-value',
                                SNYK_TENANT_ID='12345678-1234-1234-1234-123456789abc')
        self.assertEqual(result.returncode, 0, result.stderr)
        invocations = (self.home / 'guard-invocations').read_text()
        self.assertIn('TENANT_ID=12345678-1234-1234-1234-123456789abc', invocations)

    def test_missing_credentials_abort_before_any_download(self):
        result = self.run_step(SNYK_COMPONENTS='guard', SNYK_TOKEN='token')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('guard requires SNYK_ADS_PUSH_KEY', result.stderr)
        self.assertFalse((self.home / '.local/share/snyk-agent-scan/agent-scan').exists())


class InstallStudioStepTests(KitTestCase):
    """spec.yaml's "Install Snyk Studio" step."""

    def setUp(self):
        super().setUp()
        self.script = extract_step('Install Snyk Studio')
        self.executable('uname', 'echo "$MOCK_ARCH"\n')
        self.executable('curl', '''[ "$MOCK_CURL_RC" = 0 ] || exit "$MOCK_CURL_RC"
for arg in "$@"; do
  case "$arg" in
    https://github.com/snyk/studio-recipes/releases/latest)
      echo "https://github.com/snyk/studio-recipes/releases/tag/v1.0.16"; exit 0;;
    https://github.com/snyk/studio-recipes/releases/download/*) url="$arg";;
  esac
done
while [ "$1" != -o ]; do shift; done
shift
case "$url" in */checksums.txt)
  printf '%s  %s\\n' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc snyk-studio-1.0.16-linux-x86_64 > "$1"
  exit 0;; esac
cat > "$1" <<'STUDIO'
#!/bin/sh
exit 0
STUDIO
''')
        self.executable('sha256sum', 'cat > "$HOME/checksum"; exit 0\n')

    def run_step(self, **overrides):
        return subprocess.run(['sh', '-c', self.script], env={**self.env, **overrides},
                               capture_output=True, text=True)

    def test_skips_when_not_requested(self):
        result = self.run_step(SNYK_COMPONENTS='scan', SNYK_TOKEN='token')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('studio not requested', result.stdout)
        self.assertFalse((self.home / '.local/share/snyk-studio/snyk-studio-installer').exists())

    def test_installs_when_requested_with_no_credentials(self):
        result = self.run_step(SNYK_COMPONENTS='studio')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue((self.home / '.local/share/snyk-studio/snyk-studio-installer').exists())


class RecurringScanArgumentsTests(KitTestCase):
    """The startup step's scan invocation, independent of its flock-guarded preamble
    (flock isn't available on every dev machine, matching the tail-only extraction below)."""

    def test_scan_args_and_retry_logging(self):
        text = extract_step('Upload Snyk agent-scan inventory every 15 minutes')
        tail = text[text.index('SCAN_ARGS=(scan'):]
        for mode, expects_push_key in (('standalone', False), ('enterprise', True)):
            with self.subTest(mode=mode):
                prefix = '''SCAN=mock_scan
MACHINE_ID=docker-sbx:test:123
attempt=0
wait=0
mock_scan() { attempt=$((attempt+1)); echo "scan:$*"; [ "$attempt" -gt 1 ]; }
sleep() { [ "$1" = 900 ] || exit 99; wait=$((wait+1)); [ "$wait" -lt 2 ]; }
'''
                result = subprocess.run(
                    ['bash', '-c', prefix + tail],
                    env={**self.env, 'auth_mode': mode, 'SNYK_ADS_PUSH_KEY': 'test-key'},
                    capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                scans = [line for line in result.stdout.splitlines() if line.startswith('scan:')]
                self.assertEqual(len(scans), 2)
                self.assertEqual('--push-key test-key' in scans[0], expects_push_key)
                self.assertIn('exited non-zero', result.stdout)


if __name__ == '__main__':
    unittest.main()
