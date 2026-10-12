"""Real trust-store checks: python3 tests/corp_ca_container.py.

Requires Docker and a local docker/sandbox-templates:shell-docker image.
Uses no credentials or network; removes each test container in finally.
"""
import subprocess
import uuid

from test_auth import extract_step


IMAGE = 'docker/sandbox-templates:shell-docker'
STEP = extract_step('Install corporate root CA certificate(s) into the system trust store')


def docker(*args):
    result = subprocess.run(['docker', *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stdout + result.stderr)
    return result.stdout + result.stderr


def check(case):
    name = 'fm-sbxcertenv-' + uuid.uuid4().hex[:12]
    try:
        docker('run', '--detach', '--name', name, '--network', 'none', '--user', '0',
               '--entrypoint', 'sleep', IMAGE, 'infinity')
        certs = []
        for i in (1, 2):
            docker('exec', name, 'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
                   '-nodes', '-days', '1', '-subj', f'/CN=sbxcertenv-test-root-{i}',
                   '-addext', 'basicConstraints=critical,CA:TRUE',
                   '-keyout', f'/tmp/root-{i}.key', '-out', f'/tmp/root-{i}.crt')
            certs.append(docker('exec', name, 'cat', f'/tmp/root-{i}.crt'))
        args = ['exec', '-e', 'SNYK_TOKEN=', '-e', 'SNYK_ADS_PUSH_KEY=']
        expected = []
        if case in ('single', 'multi', 'combined'):
            expected = certs if case == 'multi' else certs[:1]
            args += ['-e', 'SNYK_CORP_CA_PEM=' + ''.join(expected).rstrip('\n')]
        elif case == 'empty':
            args += ['-e', 'SNYK_CORP_CA_PEM=']
        if case == 'combined':
            docker('exec', name, 'sh', '-c',
                   'mkdir -p /home/agent/corp-ca; cp /tmp/root-2.crt /home/agent/corp-ca/local.crt')
            expected = certs
        log = docker(*args, name, 'sh', '-c', STEP)
        print(f'=== {case} ===\n{log}', end='')
        bundle = docker('exec', name, 'cat', '/etc/ssl/certs/ca-certificates.crt')
        if expected:
            assert f'installed {len(expected)} certificate(s)' in log, log
            assert 'corp-ca: staged corp-ca-env.crt' in log, log
            if case == 'multi':
                assert 'corp-ca: staged corp-ca-env-2.crt' in log, log
            # rehash always skips the aggregate ca-certificates.crt bundle.
            assert not any('corp-ca-env' in line and 'skipping' in line
                           for line in log.splitlines()), log
            for i, cert in enumerate(expected, 1):
                assert cert.strip() in bundle, f'root {i} missing from system bundle'
                # Verify both the concatenated bundle and the hashed CA directory.
                for option, path in (('-CAfile', '/etc/ssl/certs/ca-certificates.crt'),
                                     ('-CApath', '/etc/ssl/certs')):
                    result = docker('exec', name, 'openssl', 'verify', option, path,
                                    f'/tmp/root-{i}.crt')
                    assert ': OK' in result, result
        else:
            assert 'WARNING no .crt files found' in log, log
            assert 'continuing without a corporate root CA' in log, log
            assert 'installed' not in log, log
            assert all(cert.strip() not in bundle for cert in certs)
        print(f'PASS: {case}')
    finally:
        docker('rm', '--force', name)


if __name__ == '__main__':
    for case in ('single', 'unset', 'empty', 'multi', 'combined'):
        check(case)
