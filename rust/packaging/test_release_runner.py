"""Exercise the foreground runner command with a local runner distribution and GitHub API double."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location('release_runner', Path(__file__).with_name('release-runner.py'))
runner = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runner)


class RunnerLifecycle(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cdm-runner-test-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.registrations = []
        self.deleted = []
        self.contents = io.BytesIO()
        self.script = '#!/bin/sh\ntest -z "${GH_TOKEN:-}" || exit 21\ntest -z "${ACTIONS_RUNNER_INPUT_TOKEN:-}" || exit 22\nexit 0\n'

    def archive(self):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode='w:gz') as archive:
            for name, script in [('config.sh', '#!/bin/sh\ntest "$ACTIONS_RUNNER_INPUT_TOKEN" = registration-secret\n'), ('run.sh', self.script)]:
                member = tarfile.TarInfo(name)
                member.mode = 0o700
                body = script.encode()
                member.size = len(body)
                archive.addfile(member, io.BytesIO(body))
        return data.getvalue()

    def github(self, command, **kwargs):
        self.assertEqual(command[0], 'gh')
        endpoint = next((s for s in command if s.startswith('repos/')), '')
        if endpoint.endswith('/registration-token'):
            result = {'token': 'registration-secret'}
        elif 'DELETE' in command:
            self.deleted.append(42)
            self.registrations = []
            result = None
        elif endpoint.endswith('/runners'):
            self.assertNotIn('--jq', command)
            result = [{'runners': self.registrations}]
        else:
            raise AssertionError(command)
        return subprocess.CompletedProcess(command, 0, json.dumps(result), '')

    def invoke(self, timeout='5'):
        blob = self.archive()
        original_popen = subprocess.Popen
        def popen(command, **kwargs):
            if command[0].endswith('config.sh'):
                self.current_name = command[command.index('--name') + 1]
                self.registrations.append({'id': 42, 'name': self.current_name})
                self.assertIn('--ephemeral', command)
                self.assertNotIn('registration-secret', command)
            return original_popen(command, **kwargs)
        with patch.dict(runner.ARCHIVES, {'osx-arm64': hashlib.sha256(blob).hexdigest()}), \
             patch.object(runner.platform, 'system', return_value='Darwin'), \
             patch.object(runner.platform, 'machine', return_value='arm64'), \
             patch.object(runner.urllib.request, 'urlopen', return_value=io.BytesIO(blob + (b'corrupt' if getattr(self, 'corrupt_download', False) else b''))), \
             patch.object(runner.subprocess, 'run', side_effect=self.github), \
             patch.object(runner.subprocess, 'Popen', side_effect=popen), \
             patch.dict(os.environ, {'TMPDIR': str(self.root), 'GH_TOKEN': 'host-secret'}), \
             contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return runner.main(['--timeout', timeout])

    def test_one_job_removes_registration_and_installation(self):
        self.assertEqual(self.invoke(), 0)
        self.assertEqual(self.deleted, [42])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_corrupted_download_never_registers_and_is_removed(self):
        self.corrupt_download = True
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.registrations, [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_interrupt_removes_registration_and_installation(self):
        self.script = '#!/bin/sh\nkill -INT "$PPID"\nsleep 60\n'
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.deleted, [42])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_job_still_removes_runner(self):
        self.script = '#!/bin/sh\nexit 17\n'
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.deleted, [42])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_timeout_stops_process_and_removes_runner(self):
        self.script = '#!/bin/sh\nsleep 60\n'
        self.assertEqual(self.invoke(timeout='1'), 1)
        self.assertEqual(self.deleted, [42])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_api_cleanup_failure_is_reported_and_local_install_removed(self):
        original = self.github
        def api(command, **kwargs):
            if 'DELETE' in command:
                return subprocess.CompletedProcess(command, 1, '', 'denied')
            return original(command, **kwargs)
        self.github = api
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_failed_configuration_removes_partial_registration(self):
        original = self.archive
        def archive():
            blob = original()
            data = io.BytesIO()
            with tarfile.open(fileobj=io.BytesIO(blob)) as source, tarfile.open(fileobj=data, mode='w:gz') as target:
                for member in source:
                    body = source.extractfile(member).read()
                    if member.name == 'config.sh':
                        body = b'#!/bin/sh\nexit 1\n'
                        member.size = len(body)
                    target.addfile(member, io.BytesIO(body))
            return data.getvalue()
        self.archive = archive
        self.assertEqual(self.invoke(), 1)
        self.assertEqual(self.deleted, [42])
        self.assertEqual(list(self.root.iterdir()), [])


if __name__ == '__main__':
    unittest.main()
