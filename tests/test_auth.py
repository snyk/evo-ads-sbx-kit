"""Exercise component selection, credential-gated hooks, and installs without
real credentials, network access, or scans."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCAN_SHA = 'a' * 64
ARM_SHA = 'b' * 64


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
    """Return the command body of the install/startup step named `description`."""
    text = (ROOT / 'snyk-evo-ads.yaml').read_text()
    marker = f'description: "{description}"\n'
    idx = text.index(marker)
    rest = text[idx + len(marker):]
    pipe_idx = rest.index('|\n')
    return _dedent_block(rest[pipe_idx + 2:])


class KitTestCase(unittest.TestCase):
    """A fake $HOME with the kit's helper scripts and a mock PATH."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.home = Path(temporary.name)
        shutil.copytree(ROOT / 'files/home/.snyk-kit', self.home / '.snyk-kit')
        self.bin = self.home / 'bin'
        self.bin.mkdir()
        self.agent_scan = self.home / '.local/share/snyk-agent-scan/agent-scan'
        self.env = {
            **os.environ, 'HOME': str(self.home),
            'PATH': str(self.bin) + ':' + os.environ['PATH'],
            'SNYK_TOKEN': '', 'SNYK_TENANT_ID': '', 'SNYK_ADS_PUSH_KEY': '',
            'SNYK_COMPONENTS': '', 'SNYK_API': '',
            'SANDBOX_NAME': 'test', 'SANDBOX_ID': '123', 'MOCK_ARCH': 'x86_64',
            'MOCK_CURL_RC': '0', 'MOCK_SHA_RC': '0', 'MOCK_GUARD_RC': '0',
            'MOCK_SCAN_TAG': 'v0.9.7', 'MOCK_CURL_FAIL_FILE': '',
            'MOCK_SCAN_MANIFEST': (
                f'{SCAN_SHA}  agent-scan-0.9.7-linux-x86_64\n'
                f'{ARM_SHA}  agent-scan-0.9.7-linux-arm64\n'
            ),
        }

    def executable(self, name, content):
        path = self.bin / name
        path.write_text('#!/bin/sh\n' + content)
        path.chmod(0o755)

    def run_shell(self, script, shell='sh', **overrides):
        return subprocess.run(
            [shell, '-c', script], env={**self.env, **overrides},
            capture_output=True, text=True, timeout=15)

    def resolve_components(self, **overrides):
        return self.run_shell('sh "$HOME/.snyk-kit/resolve-components.sh"', **overrides)

    def mock_agent_scan(self):
        self.executable('uname', 'echo "$MOCK_ARCH"\n')
        self.executable('curl', r'''[ "$MOCK_CURL_RC" = 0 ] || exit "$MOCK_CURL_RC"
for arg in "$@"; do
  case "$arg" in
    https://github.com/snyk/agent-scan/releases/latest)
      echo "https://github.com/snyk/agent-scan/releases/tag/$MOCK_SCAN_TAG"; exit 0;;
    https://github.com/snyk/agent-scan/releases/download/*)
      url="$arg"; echo "$arg" >> "$HOME/downloads";;
  esac
done
[ "${url##*/}" != "$MOCK_CURL_FAIL_FILE" ] || exit 22
while [ "$1" != -o ]; do shift; done
shift
case "$url" in */checksums.txt)
  printf '%s\n' "$MOCK_SCAN_MANIFEST" > "$1"
  exit 0;; esac
cat > "$1" <<'SCAN'
#!/bin/sh
printf '%s\n' "$*" >> "$HOME/guard-invocations"
printf 'env PUSH_KEY=%s TENANT_ID=%s MACHINE_ID=%s\n' "$PUSH_KEY" "$TENANT_ID" "$MACHINE_ID" >> "$HOME/guard-invocations"
exit "$MOCK_GUARD_RC"
SCAN
''')
        self.executable('sha256sum', 'cat > "$HOME/checksum"; exit "$MOCK_SHA_RC"\n')

    def mock_studio(self):
        self.executable('uname', 'echo "$MOCK_ARCH"\n')
        self.executable('curl', r'''[ "$MOCK_CURL_RC" = 0 ] || exit "$MOCK_CURL_RC"
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
  printf '%s  %s\n' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc snyk-studio-1.0.16-linux-x86_64 dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd snyk-studio-1.0.16-linux-arm64 > "$1"
  exit 0;; esac
cat > "$1" <<'STUDIO'
#!/bin/sh
printf '%s\n' "$*" >> "$HOME/studio-invocations"
STUDIO
''')
        self.executable('sha256sum', 'cat > "$HOME/checksum"; exit "$MOCK_SHA_RC"\n')


class AuthShTests(KitTestCase):
    def test_classification(self):
        for tenant, key, token, expected in (
            ('', '', '', 'none'),
            ('', '', 'token', 'standalone'),
            ('', 'key', '', 'enterprise'),
            ('', 'key', 'token', 'enterprise'),
            # A push key selects enterprise regardless of tenant ID. The kit
            # never uses the interactive flow that requires a tenant ID.
            ('not-a-uuid', 'key', '', 'enterprise'),
            ('12345678-1234-1234-1234-123456789abc', 'key', '', 'enterprise'),
        ):
            with self.subTest(tenant=tenant, key=key, token=token):
                result = self.run_shell(
                    'sh "$HOME/.snyk-kit/auth.sh"', SNYK_TENANT_ID=tenant,
                    SNYK_ADS_PUSH_KEY=key, SNYK_TOKEN=token)
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

    def test_guard_without_push_key_resolves_in_standalone_mode(self):
        result = self.resolve_components(SNYK_COMPONENTS='guard', SNYK_TOKEN='token')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'scan=0 guard=1 studio=0 auth_mode=standalone')

    def test_missing_credentials_do_not_change_selected_components(self):
        for components, expected in (
            ('', 'scan=1 guard=0 studio=0'),
            ('scan', 'scan=1 guard=0 studio=0'),
            ('guard', 'scan=0 guard=1 studio=0'),
            ('scan,guard', 'scan=1 guard=1 studio=0'),
            ('scan,guard,studio', 'scan=1 guard=1 studio=1'),
        ):
            with self.subTest(components=components):
                result = self.resolve_components(SNYK_COMPONENTS=components)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), expected + ' auth_mode=none')
                self.assertEqual(result.stderr, '')

    def test_scan_accepts_push_key_without_token(self):
        result = self.resolve_components(SNYK_COMPONENTS='scan', SNYK_ADS_PUSH_KEY='key')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'scan=1 guard=0 studio=0 auth_mode=enterprise')

    def test_unknown_component_fails(self):
        result = self.resolve_components(SNYK_COMPONENTS='scn')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown component 'scn'", result.stderr)

    def test_components_that_parse_to_nothing_fail(self):
        for raw in (' ', ',', ' , , '):
            with self.subTest(raw=raw):
                result = self.resolve_components(SNYK_COMPONENTS=raw)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('resolved to no components', result.stderr)


class ResolveComponentsStepTests(KitTestCase):
    def test_no_credentials_logs_inactive_hooks_without_failing(self):
        result = self.run_shell(extract_step('Resolve requested Snyk components'),
                                SNYK_COMPONENTS='scan,guard')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('scan=1 guard=1 studio=0 (auth_mode=none)', result.stdout)
        self.assertIn('hooks stay inactive', result.stdout)
        self.assertIn('sandbox is recreated', result.stdout)


class InstallAgentScanShTests(KitTestCase):
    """Scan and Guard share a checksum-verified binary from one release."""

    def setUp(self):
        super().setUp()
        self.mock_agent_scan()

    def run_install(self, **overrides):
        return self.run_shell('sh "$HOME/.snyk-kit/install-agent-scan.sh"', **overrides)

    def test_downloads_and_verifies_binary(self):
        result = self.run_install()
        self.assertEqual(result.returncode, 0, result.stderr)
        base = 'https://github.com/snyk/agent-scan/releases/download/v0.9.7/'
        self.assertEqual((self.home / 'downloads').read_text().splitlines(),
                         [base + 'checksums.txt', base + 'agent-scan-0.9.7-linux-x86_64'])
        self.assertEqual((self.home / 'checksum').read_text().split()[0], SCAN_SHA)
        self.assertTrue(self.agent_scan.exists())
        self.assertTrue(os.access(self.agent_scan, os.X_OK))

    def test_arm64_asset(self):
        result = self.run_install(MOCK_ARCH='aarch64')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('linux-arm64', (self.home / 'downloads').read_text())
        self.assertEqual((self.home / 'checksum').read_text().split()[0], ARM_SHA)

    def test_asset_name_comes_from_manifest_not_release_tag(self):
        manifest = (f'{SCAN_SHA}  agent-scan-0.6.6-linux-x86_64\n'
                    f'{ARM_SHA}  agent-scan-0.6.6-linux-arm64\n'
                    f'{SCAN_SHA}  sbom-0.6.7.json\n')
        for arch, asset_arch, sha in (('x86_64', 'x86_64', SCAN_SHA), ('arm64', 'arm64', ARM_SHA)):
            with self.subTest(arch=arch):
                (self.home / 'downloads').write_text('')
                result = self.run_install(MOCK_ARCH=arch, MOCK_SCAN_TAG='v0.6.7',
                                          MOCK_SCAN_MANIFEST=manifest)
                self.assertEqual(result.returncode, 0, result.stderr)
                base = 'https://github.com/snyk/agent-scan/releases/download/v0.6.7/'
                asset = f'agent-scan-0.6.6-linux-{asset_arch}'
                self.assertEqual((self.home / 'downloads').read_text().splitlines(),
                                 [base + 'checksums.txt', base + asset])
                self.assertEqual((self.home / 'checksum').read_text().split()[0], sha)
                self.assertIn(f'{asset} installed from release v0.6.7', result.stdout)

    def test_four_part_release_version(self):
        result = self.run_install(MOCK_SCAN_TAG='v0.6.5.2', MOCK_SCAN_MANIFEST=
                                  f'{SCAN_SHA}  agent-scan-0.6.5.2-linux-x86_64\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('/v0.6.5.2/agent-scan-0.6.5.2-linux-x86_64',
                      (self.home / 'downloads').read_text())

    def test_binary_mode_checksum_manifest(self):
        result = self.run_install(MOCK_SCAN_MANIFEST=
                                  f'{SCAN_SHA} *agent-scan-0.9.7-linux-x86_64\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((self.home / 'checksum').read_text().split()[0], SCAN_SHA)

    def test_missing_ambiguous_or_unsafe_manifest_assets_stop_before_binary_download(self):
        for manifest, error in (
            ('', 'lists no linux-x86_64 asset'),
            (f'{ARM_SHA}  agent-scan-0.9.7-linux-arm64\n', 'lists no linux-x86_64 asset'),
            (f'{SCAN_SHA}  agent-scan-0.9.7-darwin-x86_64\n', 'lists no linux-x86_64 asset'),
            (f'{SCAN_SHA}  ../agent-scan-0.9.7-linux-x86_64\n', 'lists no linux-x86_64 asset'),
            (f'{SCAN_SHA}  agent-scan-0.9.7-linux-x86_64/evil\n', 'lists no linux-x86_64 asset'),
            (f'{SCAN_SHA}  agent-scan-0.9.7-linux-x86_64\n'
             f'{ARM_SHA}  agent-scan-0.9.6-linux-x86_64\n', 'lists more than one linux-x86_64 asset'),
        ):
            with self.subTest(manifest=manifest):
                (self.home / 'downloads').write_text('')
                result = self.run_install(MOCK_SCAN_MANIFEST=manifest)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(error, result.stderr)
                downloads = (self.home / 'downloads').read_text().splitlines()
                self.assertEqual(len(downloads), 1)
                self.assertTrue(downloads[0].endswith('/checksums.txt'))
                self.assertFalse(self.agent_scan.exists())
                self.assertFalse((self.home / 'checksum').exists())

    def test_invalid_checksum_stops_install(self):
        result = self.run_install(MOCK_SCAN_MANIFEST=
                                  f'{"a" * 63}  agent-scan-0.9.7-linux-x86_64\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('missing or invalid release checksum', result.stderr)
        self.assertFalse(self.agent_scan.exists())
        self.assertFalse((self.home / 'checksum').exists())

    def test_invalid_release_version_stops_before_downloads(self):
        for tag in ('v0.6.7-rc1', 'v0.6.7?bad', 'v0'):
            with self.subTest(tag=tag):
                result = self.run_install(MOCK_SCAN_TAG=tag)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unexpected release version', result.stderr)
                self.assertFalse((self.home / 'downloads').exists())
                self.assertFalse(self.agent_scan.exists())

    def test_download_and_checksum_failures_stop_install(self):
        for overrides in (
            {'MOCK_CURL_RC': '22'},
            {'MOCK_CURL_FAIL_FILE': 'checksums.txt'},
            {'MOCK_CURL_FAIL_FILE': 'agent-scan-0.9.7-linux-x86_64'},
            {'MOCK_SHA_RC': '1'},
            {'MOCK_ARCH': 'unsupported'},
        ):
            with self.subTest(overrides=overrides):
                result = self.run_install(**overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(self.agent_scan.exists())
                self.assertEqual(list(self.agent_scan.parent.glob('download.*')), [])


class InstallStudioShTests(KitTestCase):
    def setUp(self):
        super().setUp()
        self.mock_studio()

    def test_downloads_verifies_and_invokes_installer(self):
        result = self.run_shell('sh "$HOME/.snyk-kit/install-studio.sh"')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('snyk-studio-1.0.16-linux-x86_64', (self.home / 'downloads').read_text())
        binary = self.home / '.local/share/snyk-studio/snyk-studio-installer'
        self.assertTrue(binary.exists())
        self.assertTrue(os.access(binary, os.X_OK))
        self.assertEqual((self.home / 'studio-invocations').read_text().strip(),
                         'install -y --no-latest-deps')

    def test_download_and_checksum_failures_stop_install(self):
        for overrides in ({'MOCK_CURL_RC': '22'}, {'MOCK_SHA_RC': '1'}, {'MOCK_ARCH': 'unsupported'}):
            with self.subTest(overrides=overrides):
                result = self.run_shell('sh "$HOME/.snyk-kit/install-studio.sh"', **overrides)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((self.home / '.local/share/snyk-studio/snyk-studio-installer').exists())


class InstallScanAndGuardStepTests(KitTestCase):
    def setUp(self):
        super().setUp()
        self.script = extract_step('Install AgentScan and/or Guard')
        self.mock_agent_scan()

    def run_step(self, **overrides):
        return self.run_shell(self.script, **overrides)

    def test_skips_when_neither_scan_nor_guard_requested(self):
        result = self.run_step(SNYK_COMPONENTS='studio')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('skipping AgentScan install', result.stdout)
        self.assertFalse(self.agent_scan.exists())
        self.assertFalse((self.home / 'downloads').exists())

    def test_scan_only_installs_binary_without_guard_call(self):
        result = self.run_step(SNYK_COMPONENTS='scan', SNYK_TOKEN='token')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.agent_scan.exists())
        self.assertFalse((self.home / 'guard-invocations').exists())

    def test_missing_credentials_install_binary_without_hooks_or_identity(self):
        for components in ('scan', 'guard', 'scan,guard'):
            with self.subTest(components=components):
                self.agent_scan.unlink(missing_ok=True)
                result = self.run_step(SNYK_COMPONENTS=components, SANDBOX_NAME='', SANDBOX_ID='')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(os.access(self.agent_scan, os.X_OK))
                self.assertFalse((self.home / 'guard-invocations').exists())
                if 'guard' in components:
                    self.assertIn('skipping Guard hook installation', result.stdout)
                    self.assertIn('recreate the sandbox', result.stdout)

    def test_guard_with_token_only_installs_binary_without_guard_hooks(self):
        result = self.run_step(SNYK_COMPONENTS='scan,guard', SNYK_TOKEN='token')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(self.agent_scan.exists())
        self.assertIn('SNYK_ADS_PUSH_KEY is not set', result.stdout)
        self.assertFalse((self.home / 'guard-invocations').exists())

    def test_malformed_components_abort_before_any_download(self):
        result = self.run_step(SNYK_COMPONENTS='scn')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unknown component 'scn'", result.stderr)
        self.assertFalse(self.agent_scan.exists())
        self.assertFalse((self.home / 'downloads').exists())

    def test_guard_installs_binary_and_calls_guard_install_with_correct_identity(self):
        result = self.run_step(SNYK_COMPONENTS='scan,guard', SNYK_ADS_PUSH_KEY='push-key-value')
        self.assertEqual(result.returncode, 0, result.stderr)
        invocations = (self.home / 'guard-invocations').read_text()
        self.assertIn('guard install all', invocations)
        self.assertIn('env PUSH_KEY=push-key-value TENANT_ID= MACHINE_ID=docker-sbx:test:123', invocations)

    def test_guard_forwards_tenant_id_when_supplied(self):
        result = self.run_step(SNYK_COMPONENTS='guard', SNYK_ADS_PUSH_KEY='push-key-value',
                               SNYK_TENANT_ID='12345678-1234-1234-1234-123456789abc')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('TENANT_ID=12345678-1234-1234-1234-123456789abc',
                      (self.home / 'guard-invocations').read_text())

    def test_guard_forwards_custom_snyk_api_as_url_flag(self):
        result = self.run_step(SNYK_COMPONENTS='guard', SNYK_ADS_PUSH_KEY='push-key-value',
                               SNYK_API='https://api.example-region.snyk.io')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('guard install all --url https://api.example-region.snyk.io',
                      (self.home / 'guard-invocations').read_text())

    def test_guard_omits_url_flag_when_snyk_api_unset(self):
        result = self.run_step(SNYK_COMPONENTS='guard', SNYK_ADS_PUSH_KEY='push-key-value')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('--url', (self.home / 'guard-invocations').read_text())

    def test_guard_install_failure_with_custom_snyk_api_explains_test_event(self):
        result = self.run_step(SNYK_COMPONENTS='guard', SNYK_ADS_PUSH_KEY='push-key-value',
                               SNYK_API='https://api.pc01.my.snyk.io', MOCK_GUARD_RC='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('guard install failed', result.stderr)
        self.assertIn('https://api.pc01.my.snyk.io', result.stderr)
        self.assertIn('hidden/agent-monitor/hooks', result.stderr)

    def test_guard_install_failure_without_custom_snyk_api_is_terse(self):
        result = self.run_step(SNYK_COMPONENTS='guard', SNYK_ADS_PUSH_KEY='push-key-value',
                               MOCK_GUARD_RC='1')
        self.assertEqual(result.returncode, 1)
        self.assertIn('guard install failed', result.stderr)
        self.assertNotIn('hidden/agent-monitor/hooks', result.stderr)


class InstallStudioStepTests(KitTestCase):
    def setUp(self):
        super().setUp()
        self.script = extract_step('Install Snyk Studio')
        self.mock_studio()

    def test_skips_when_not_requested(self):
        result = self.run_shell(self.script, SNYK_COMPONENTS='scan')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('studio not requested', result.stdout)
        self.assertFalse((self.home / '.local/share/snyk-studio/snyk-studio-installer').exists())

    def test_installs_when_requested_with_no_credentials(self):
        for components in ('studio', 'scan,guard,studio'):
            with self.subTest(components=components):
                result = self.run_shell(self.script, SNYK_COMPONENTS=components)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue((self.home / '.local/share/snyk-studio/snyk-studio-installer').exists())


class RecurringScanGatingTests(KitTestCase):
    """Exercise real startup credential gates, omitting only logging and flock."""

    def setUp(self):
        super().setUp()
        text = extract_step('Upload Snyk agent-scan inventory every 15 minutes')
        self.script = text[text.index('COMPONENTS_OUTPUT='):]
        self.agent_scan.parent.mkdir(parents=True)
        self.agent_scan.write_text('#!/bin/sh\nprintf "%s\\n" "$*" >> "$HOME/scans"\n')
        self.agent_scan.chmod(0o755)
        self.executable('timeout', 'shift; exec "$@"\n')
        self.executable('sleep', 'exit 1\n')

    def test_no_credentials_skip_scan_even_with_binary_installed(self):
        for components in ('scan', 'scan,guard'):
            with self.subTest(components=components):
                result = self.run_shell(self.script, shell='bash', SNYK_COMPONENTS=components)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('SKIP no SNYK_TOKEN or SNYK_ADS_PUSH_KEY supplied', result.stdout)
                self.assertFalse((self.home / 'scans').exists())

    def test_malformed_components_skip_with_correct_reason(self):
        result = self.run_shell(self.script, shell='bash', SNYK_COMPONENTS='scn')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('malformed SNYK_COMPONENTS', result.stdout)
        self.assertFalse((self.home / 'scans').exists())

    def test_scan_not_selected_skips_even_with_credential(self):
        result = self.run_shell(self.script, shell='bash', SNYK_COMPONENTS='guard', SNYK_ADS_PUSH_KEY='key')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('SKIP scan not requested', result.stdout)
        self.assertFalse((self.home / 'scans').exists())

    def test_token_activates_scan_when_guard_has_no_push_key(self):
        result = self.run_shell(self.script, shell='bash', SNYK_COMPONENTS='scan,guard', SNYK_TOKEN='token')
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = (self.home / 'scans').read_text().splitlines()
        self.assertEqual(calls, ['help', 'scan --machine-id docker-sbx:test:123'])


class RecurringScanArgumentsTests(KitTestCase):
    """Scan arguments and retries, independent of the startup preamble."""

    def scan_tail(self):
        text = extract_step('Upload Snyk agent-scan inventory every 15 minutes')
        prefix = '''SCAN=mock_scan
MACHINE_ID=docker-sbx:test:123
attempt=0
wait=0
mock_scan() { attempt=$((attempt+1)); echo "scan:$*"; [ "$attempt" -gt 1 ]; }
sleep() { [ "$1" = 900 ] || exit 99; wait=$((wait+1)); [ "$wait" -lt 2 ]; }
'''
        return prefix + text[text.index('SCAN_ARGS=(scan'):]

    def test_scan_args_and_retry_logging(self):
        for mode, expects_push_key in (('standalone', False), ('enterprise', True)):
            with self.subTest(mode=mode):
                result = self.run_shell(self.scan_tail(), shell='bash',
                                        auth_mode=mode, SNYK_ADS_PUSH_KEY='test-key')
                self.assertEqual(result.returncode, 0, result.stderr)
                scans = [line for line in result.stdout.splitlines() if line.startswith('scan:')]
                self.assertEqual(len(scans), 2)
                self.assertEqual('--push-key test-key' in scans[0], expects_push_key)
                self.assertNotIn('--analysis-url', scans[0])
                self.assertIn('exited non-zero', result.stdout)

    def test_scan_forwards_custom_snyk_api_as_analysis_url(self):
        result = self.run_shell(self.scan_tail(), shell='bash', auth_mode='standalone',
                                SNYK_API='https://api.example-region.snyk.io')
        self.assertEqual(result.returncode, 0, result.stderr)
        scans = [line for line in result.stdout.splitlines() if line.startswith('scan:')]
        self.assertIn(
            '--analysis-url https://api.example-region.snyk.io/hidden/mcp-scan/analysis-machine?version=2026-07-10',
            scans[0])


if __name__ == '__main__':
    unittest.main()
