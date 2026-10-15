#!/usr/bin/env python3
"""Install one foreground GitHub release runner; remove it when the session ends."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
import uuid

PINS = dict(line.split('=', 1) for line in Path(__file__).with_name('versions.env').read_text().splitlines()
            if line and not line.startswith('#') and '=' in line)
VERSION = PINS['GITHUB_RUNNER_VERSION']
ARCHIVES = {
    'osx-arm64': PINS['GITHUB_RUNNER_OSX_ARM64_SHA256'],
    'linux-arm64': PINS['GITHUB_RUNNER_LINUX_ARM64_SHA256'],
}


class RunnerError(Exception):
    pass


def github(endpoint, environment, method='GET'):
    command = ['gh', 'api', '--hostname', 'github.com', '--method', method, endpoint]
    if method == 'GET':
        command += ['--paginate', '--slurp']
    result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=60)
    if result.returncode:
        # API bodies and subprocess arguments can include credentials; do not echo them.
        raise RunnerError(f'GitHub API {method} failed; repository administration access is required')
    result = json.loads(result.stdout) if result.stdout.strip() else None
    return [runner for page in result for runner in page['runners']] if method == 'GET' else result


def execute(command, *, environment, cwd, timeout, quiet=False):
    process = subprocess.Popen(command, cwd=cwd, env=environment, start_new_session=True,
                               stdout=subprocess.DEVNULL if quiet else None,
                               stderr=subprocess.DEVNULL if quiet else None)
    try:
        return process.wait(timeout=timeout)
    finally:
        # Stop the whole process group, including any job children, before deleting files.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def interrupted(signum, _frame):
    raise RunnerError(f'interrupted by signal {signum}')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository', default='RogueKernelApps/cdm', help='trusted OWNER/REPO to accept jobs from')
    parser.add_argument('--github-user', help='gh account with repository administration access')
    parser.add_argument('--timeout', type=int, default=21600, help='maximum runner wait plus job seconds (default: 21600)')
    args = parser.parse_args(argv)
    if sys.version_info < (3, 12):
        parser.error('Python 3.12 or newer is required for safe runner archive extraction')
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', args.repository) or args.timeout < 1:
        parser.error('provide OWNER/REPO and a positive timeout')
    system, machine = platform.system(), platform.machine()
    if machine not in ('arm64', 'aarch64') or system not in ('Darwin', 'Linux'):
        parser.error('temporary release runners require Apple silicon or Linux ARM64')
    asset = 'osx-arm64' if system == 'Darwin' else 'linux-arm64'
    labels = 'self-hosted,' + ('macOS' if system == 'Darwin' else 'Linux') + ',ARM64,cdm-release'
    name = 'cdm-on-demand-' + uuid.uuid4().hex
    endpoint = f'repos/{args.repository}/actions/runners'
    environment = dict(os.environ)
    root = None
    attempted_registration = False
    status = 0
    handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)}
    try:
        if args.github_user:
            token = subprocess.run(['gh', 'auth', 'token', '--hostname', 'github.com', '--user', args.github_user],
                                   text=True, capture_output=True, timeout=30, env=environment)
            if token.returncode or not token.stdout.strip():
                raise RunnerError('could not obtain credentials for the selected gh account')
            environment['GH_TOKEN'] = token.stdout.strip()
        # Check access before downloading or installing anything.
        github(endpoint, environment)
        root = Path(tempfile.mkdtemp(prefix='cdm-release-runner-', dir=os.environ.get('TMPDIR', '/tmp')))
        archive = root / 'runner.tar.gz'
        url = f'https://github.com/actions/runner/releases/download/v{VERSION}/actions-runner-{asset}-{VERSION}.tar.gz'
        print(f'Downloading verified runner {VERSION}; temporary files: {root}', flush=True)
        with urllib.request.urlopen(url, timeout=60) as response, archive.open('wb') as output:
            shutil.copyfileobj(response, output)
        digest = hashlib.sha256()
        with archive.open('rb') as source:
            for block in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(block)
        if digest.hexdigest() != ARCHIVES[asset]:
            raise RunnerError('runner archive checksum mismatch')
        install = root / 'runner'
        install.mkdir(mode=0o700)
        with tarfile.open(archive) as bundle:
            # Python 3.12+ data filter rejects archive traversal and escaping links.
            bundle.extractall(install, filter='data')
        archive.unlink()
        home = root / 'home'
        home.mkdir(mode=0o700)
        temporary = root / 'tmp'
        temporary.mkdir(mode=0o700)
        child_environment = {key: environment[key] for key in ('PATH', 'LANG', 'USER', 'LOGNAME', 'SHELL') if key in environment}
        child_environment.update(HOME=str(home), TMPDIR=str(temporary),
                                 CARGO_HOME=str(home / '.cargo'), RUSTUP_HOME=str(home / '.rustup'))
        attempted_registration = True
        registration = github(endpoint + '/registration-token', environment, 'POST')
        configuration_environment = dict(child_environment, ACTIONS_RUNNER_INPUT_TOKEN=registration['token'])
        del registration
        code = execute([str(install / 'config.sh'), '--unattended', '--ephemeral',
                        '--url', f'https://github.com/{args.repository}', '--name', name,
                        '--labels', labels, '--work', '_work'], environment=configuration_environment,
                       cwd=install, timeout=120, quiet=True)
        del configuration_environment
        if code:
            raise RunnerError('ephemeral runner registration failed')
        print(f'Ready: {name}. Start the trusted release workflow now; this runner accepts one job.', flush=True)
        print('No login service is installed. Ctrl-C cancels and removes this runner.', flush=True)
        code = execute([str(install / 'run.sh')], environment=child_environment, cwd=install, timeout=args.timeout)
        if code:
            raise RunnerError(f'runner exited with status {code}; check the GitHub job result')
    except (RunnerError, OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        print(f'cdm release runner: {error}', file=sys.stderr)
        status = 1
    finally:
        # A second Ctrl-C must not interrupt deregistration or filesystem cleanup.
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        if attempted_registration:
            try:
                for registration in github(endpoint, environment):
                    if registration['name'] == name:
                        github(endpoint + '/' + str(int(registration['id'])), environment, 'DELETE')
            except (RunnerError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
                print(f'cdm release runner: cleanup incomplete; remove {name} from GitHub: {error}', file=sys.stderr)
                status = 1
        if root is not None:
            try:
                # A cancelled macOS job may not reach its own keychain cleanup step.
                keychain = root / 'runner/_work/_temp/cdm-signing.keychain-db'
                if system == 'Darwin' and keychain.exists():
                    result = subprocess.run(['/usr/bin/security', 'delete-keychain', str(keychain)],
                                            capture_output=True, timeout=30)
                    if result.returncode:
                        raise RunnerError('could not remove the temporary signing keychain')
                shutil.rmtree(root)
            except (RunnerError, OSError, subprocess.SubprocessError) as error:
                print(f'cdm release runner: cleanup incomplete at {root}: {error}', file=sys.stderr)
                status = 1
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
