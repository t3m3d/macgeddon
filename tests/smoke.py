#!/usr/bin/env python3
"""Offline integration tests. No radio capture, password search or SSH."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
CLI = ROOT / 'bin/macgeddon'
APP = ROOT / 'bin/Macgeddon.app'


def run(args, expected=0, *, env, cwd='/tmp'):
    result = subprocess.run([str(CLI), *args], cwd=cwd, env=env,
                            input='', text=True, capture_output=True, timeout=45)
    assert result.returncode == expected, (args, result.returncode, result.stdout, result.stderr)
    assert '\x1b' not in result.stdout, 'NO_COLOR was ignored'
    return result.stdout + result.stderr


with tempfile.TemporaryDirectory(prefix='macgeddon-smoke-') as folder:
    temp = Path(folder)
    env = dict(os.environ, MACGEDDON_HOME=str(temp / "private state $literal's"), NO_COLOR='1')
    assert 'macgeddon 0.1.0' in run(['version'], env=env)
    run(['not-a-command'], 2, env=env)
    run(['scan', '--file'], 2, env=env)
    run(['scan', '--unknown'], 2, env=env)
    run(['scan', '--host', 'do-not-connect'], 2, env=env)
    run(['capture', '--secs', '2;false'], 2, env=env)
    run(['capture', '--secs', '0'], 2, env=env)
    run(['capture', '--secs', '3601'], 2, env=env)
    run(['capture', '--explain'], env=env)
    run(['scan', '--file', '/no/such/scan.txt'], 3, env=env)
    run(['report', '--out', str(temp / 'absent' / 'report.json')], 3, env=env)
    marker = temp / 'must-not-exist'
    hostile = temp / ('$(touch ' + str(marker).replace('/', '_') + ') `false` \'scan.txt')
    shutil.copy(ROOT / 'tests/fixtures/profiler.txt', hostile)
    run(['scan', '--file=' + str(hostile), '--save'], env=env)
    report = temp / 'saved report.json'
    run(['report', '--out', str(report)], env=env)
    body = json.loads(report.read_text())
    assert len(body['targets']) == 3, body
    assert body['targets'][0]['ssid'] == 'HarborNet-5G', body
    state = Path(env['MACGEDDON_HOME']) / 'sessions'
    assert len(json.loads((state / 'last.json').read_text())['targets']) == 3
    assert state.stat().st_mode & 0o077 == 0, 'state directory must be private'
    assert not marker.exists()
    run(['scan', '--file', str(ROOT / 'tests/fixtures/airport_s.txt')], env=env)
    run(['menu'], env=env)  # EOF must exit instead of looping.
    # Fake optional tools test error/result handling without running a search.
    tools = temp / 'tools'
    tools.mkdir()
    hashcat = tools / 'hashcat'
    hashcat.write_text('''#!/bin/sh
if [ "$FAKE_HASHCAT_MODE" = error ]; then echo 'backend failed'; exit 255; fi
case " $* " in
  *" --show "*)
    if [ "$FAKE_HASHCAT_MODE" = match ]; then echo 'fixture:password,with punctuation'; fi
    exit 0;;
esac
echo 'diagnostic is not a password'
exit 1
''')
    hashcat.chmod(0o700)
    fake = dict(env, PATH=str(tools) + os.pathsep + env['PATH'])
    source = temp / 'fixture.22000'
    source.write_text('synthetic fixture; not a real hash\n')
    words = temp / 'words.txt'
    words.write_text('synthetic\n')
    args = ['crack', '--hash', str(source), '--wordlist', str(words)]
    fake['FAKE_HASHCAT_MODE'] = 'error'
    assert 'KEY FOUND' not in run(args, 3, env=fake)
    fake['FAKE_HASHCAT_MODE'] = 'empty'
    assert 'KEY FOUND' not in run(args, 1, env=fake)
    fake['FAKE_HASHCAT_MODE'] = 'match'
    assert 'fixture:password,with punctuation' in run(args, env=fake)
    # Verify the idle-capture watchdog with mocked tools, never a real radio.
    fake_id = tools / 'id'
    fake_id.write_text('#!/bin/sh\nif [ "$1" = -u ]; then echo 0; else exec /usr/bin/id "$@"; fi\n')
    fake_id.chmod(0o700)
    tcpdump = tools / 'tcpdump'
    tcpdump.write_text('#!' + sys.executable + '\n' + """import signal, sys, time
from pathlib import Path
signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
Path(sys.argv[sys.argv.index('-w') + 1]).write_bytes(b'fixture capture')
while True: time.sleep(0.1)
""")
    tcpdump.chmod(0o700)
    captured = temp / 'idle managed.pcap'
    started = time.monotonic()
    run(['capture', '--iface', 'mock0', '--secs', '1', '--out', str(captured)], env=fake)
    assert time.monotonic() - started < 10, 'idle capture exceeded wall-clock bound'
    assert captured.read_bytes() == b'fixture capture'
    run(['capture', '--iface', 'mock0', '--out', str(captured)], 3, env=fake)
    # Exercise a moved bundle from an unrelated CWD, including shell metacharacters.
    moved = temp / "Portable Macgeddon's $app.app"
    shutil.copytree(APP, moved)
    subprocess.run(['/usr/bin/codesign', '--verify', '--deep', '--strict', str(moved)], check=True)
    gui = moved / 'Contents/MacOS/macgeddon-gui'
    check = subprocess.run([str(gui), '--smoke-test'], cwd='/tmp', env=env,
                           text=True, capture_output=True, timeout=20)
    assert check.returncode == 0 and 'macgeddon 0.1.0' in check.stdout, check
print('CLI validation, saved scans, JSON persistence, tool failures, and relocated bundle passed')
