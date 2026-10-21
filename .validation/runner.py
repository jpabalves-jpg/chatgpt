"""Generic native-Windows CI transport. Only ciphertext enters the repository.

The ephemeral decryption key stays on the runner. Results are encrypted to the
requester's public key before artifact upload; private files never enter logs.
"""
import base64
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(os.environ['RUNNER_TEMP']) / 'confidential-windows-validation'
RUN = os.environ['GITHUB_RUN_ID']
OAEP = padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def prepare():
    if sys.platform != 'win32' or os.environ.get('RUNNER_OS') != 'Windows':
        raise SystemExit('Native Windows is required.')
    ROOT.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    (ROOT / 'private.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')
    (ROOT / 'public.json').write_text(json.dumps({'run_id': RUN, 'public_key': public,
        'platform': platform.platform(), 'python': sys.version}), encoding='utf-8')
    print('Native Windows ready; ephemeral public key prepared.')


def seal(data, public, aad):
    key = AESGCM.generate_key(bit_length=256)
    nonce = os.urandom(12)
    return {'run_id': RUN, 'key': base64.b64encode(public.encrypt(key, OAEP)).decode(),
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(AESGCM(key).encrypt(nonce, data, aad)).decode()}


def execute():
    private = serialization.load_pem_private_key((ROOT / 'private.pem').read_bytes(), password=None)
    repo = os.environ['GITHUB_REPOSITORY']
    branch = os.environ['VALIDATION_BRANCH']
    path = '.validation/payload-' + RUN + '.json'
    url = 'https://api.github.com/repos/' + repo + '/contents/' + path + '?ref=' + urllib.parse.quote(branch, safe='')
    headers = {'Authorization': 'Bearer ' + os.environ['GH_READ_TOKEN'],
        'Accept': 'application/vnd.github.raw+json', 'User-Agent': 'native-windows-validation'}
    deadline = time.monotonic() + 1800
    envelope = None
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=30) as response:
                envelope = json.load(response)
            break
        except urllib.error.HTTPError as exc:
            if exc.code != 404:
                raise SystemExit('Encrypted request unavailable; HTTP ' + str(exc.code)) from None
        time.sleep(10)
    if envelope is None:
        raise SystemExit('Encrypted request timeout.')
    if str(envelope['run_id']) != RUN:
        raise SystemExit('Encrypted request belongs to another runner.')
    key = private.decrypt(base64.b64decode(envelope['key']), OAEP)
    plain = AESGCM(key).decrypt(base64.b64decode(envelope['nonce']),
        base64.b64decode(envelope['ciphertext']), RUN.encode())
    work = ROOT / 'Workspace com espacos'
    work.mkdir()
    with zipfile.ZipFile(io.BytesIO(plain)) as archive:
        for name in archive.namelist():
            target = (work / name).resolve()
            if not target.is_relative_to(work.resolve()):
                raise SystemExit('Invalid request archive path.')
        archive.extractall(work)
    del plain, key
    request = json.loads((work / 'ci_workload.json').read_text(encoding='utf-8'))
    reports = work / 'ci_reports'
    reports.mkdir()
    results = {'platform': platform.platform(), 'python': sys.version,
        'run_id': RUN, 'native_windows': True, 'commands': []}
    env = dict(os.environ, PYTHONUTF8='1', PYTHONIOENCODING='utf-8', PYTHONUNBUFFERED='1')
    # Workloads receive no repository token or Actions credentials.
    for name in list(env):
        if name.startswith(('GH_', 'GITHUB_TOKEN', 'ACTIONS_')):
            env.pop(name, None)
    for index, command in enumerate(request['commands']):
        started = time.monotonic()
        log = reports / ('command-' + str(index) + '.log')
        args = [sys.executable if x == '{python}' else x for x in command['args']]
        status = None
        try:
            with log.open('w', encoding='utf-8') as stream:
                status = subprocess.run(args, cwd=work / request['source'], env=env,
                    stdout=stream, stderr=subprocess.STDOUT, timeout=command.get('timeout', 600)).returncode
        except subprocess.TimeoutExpired:
            status = 'timeout'
        except BaseException as exc:
            log.write_text(type(exc).__name__ + ': ' + str(exc), encoding='utf-8')
            status = 'runner_error'
        results['commands'].append({'name': command['name'], 'status': status,
            'elapsed_s': round(time.monotonic() - started, 3)})
        print('Validation stage ' + str(index + 1) + ': ' + ('PASS' if status == 0 else 'FAIL'))
        if status != 0 and command.get('required', False):
            break
    (reports / 'summary.json').write_text(json.dumps(results, indent=2), encoding='utf-8')
    public = serialization.load_pem_public_key(request['result_public_key'].encode())
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', zipfile.ZIP_DEFLATED) as archive:
        for folder in [reports, work / request['source'] / 'ci_reports']:
            if folder.exists():
                for item in folder.rglob('*'):
                    if item.is_file():
                        archive.write(item, str(item.relative_to(work)))
    (ROOT / 'result.json').write_text(json.dumps(seal(buffer.getvalue(), public,
        (RUN + ':result').encode())), encoding='utf-8')
    (ROOT / 'private.pem').unlink()
    print('Results encrypted; no source or private report was published.')


if __name__ == '__main__':
    {'prepare': prepare, 'execute': execute}[sys.argv[1]]()
