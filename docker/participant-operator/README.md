# Optional participant operator environment

This lock is for the **host-side operator SSH/SFTP tools only**. It is separate
from the CPU inference image and includes no Torch or Transformers packages. It
does not install or run workers, prove a secure route, or satisfy a research
phase gate.

The supported environment is 64-bit CPython 3.12 or 3.14 on Windows or Linux
x86_64 using the standard GIL-enabled build. The [lock file](requirements.lock)
pins Paramiko 3.5.1 and its six-package default dependency
closure. SHA-256 hashes come from the official PyPI JSON metadata for the exact
wheel files; Linux glibc/musl and Windows x86_64 wheels are listed where
available. Source distributions are intentionally excluded. Optional Paramiko
extras (GSSAPI, invoke, and `all`) are not installed.

## Create an isolated environment

From the repository root, create a virtual environment and install only
hash-verified wheels. On Windows PowerShell:

```powershell
py -3.12 -m venv .venv-operator
.\.venv-operator\Scripts\python.exe -m pip install --only-binary=:all: --require-hashes -r docker/participant-operator/requirements.lock
.\.venv-operator\Scripts\python.exe docker/participant-operator/verify_environment.py --root .venv-operator
```

On Linux:

```sh
python3.12 -m venv .venv-operator
.venv-operator/bin/python -m pip install --only-binary=:all: --require-hashes -r docker/participant-operator/requirements.lock
.venv-operator/bin/python docker/participant-operator/verify_environment.py --root .venv-operator
```

Use `py -3.14` or `python3.14` instead to select CPython 3.14. The
[`verify_environment.py`](verify_environment.py) checker’s `--root` is
optional; when supplied, the verifier checks that each imported dependency's
module file resolves beneath that install root, preventing silent fallback to a
global package. The verifier checks the interpreter/platform and the exact six
imported package versions. It does not read credentials, use the network, open
SSH connections, or import model/runtime packages.

## Offline Paramiko deadline check

With the isolated environment active and the repository root as the working
directory, run the [explicit check](../../tests/paramiko_deadline_check.py):

```sh
python -c "import runpy; runpy.run_path('tests/paramiko_deadline_check.py', run_name='__main__')"
```

That explicit check asserts Paramiko 3.5.1 and exercises actual Paramiko channel
request-event waits using a fake transport; it makes no network connection.
It is intentionally named outside the `test_*.py` pattern so ordinary
dependency-light test discovery does not import the optional host SSH package.
