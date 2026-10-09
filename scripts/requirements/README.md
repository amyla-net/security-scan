# Python tool locks

`semgrep.txt` and `pyyaml.txt` pin every runtime dependency and its SHA-256
distribution hashes. The installer uses these files with `--require-hashes`,
`--only-binary=:all:`, and the explicit `https://pypi.org/simple` index. It disables
pip configuration files and inherited pip options. Source builds are forbidden.

The `.in` files contain the requested tool versions. Keep them in sync with
`VERSIONS` and `PYYAML_VERSION` in `../install_tools.py`. Locks were generated
with uv 0.8.22 for Python 3.11 and newer; environment markers preserve conditional
dependencies across Python versions. Ubuntu x64 is the supported runtime.

From the repository root, regenerate each lock with:

```sh
uv pip compile scripts/requirements/semgrep.in --python-version 3.11 --universal --only-binary :all: --generate-hashes --default-index https://pypi.org/simple --no-config --no-python-downloads --output-file scripts/requirements/semgrep.txt
uv pip compile scripts/requirements/pyyaml.in --python-version 3.11 --universal --only-binary :all: --generate-hashes --default-index https://pypi.org/simple --no-config --no-python-downloads --output-file scripts/requirements/pyyaml.txt
```

Review the package/version changes before accepting a regenerated lock. uv keeps
existing pins unless `--upgrade` or `--upgrade-package` is supplied. Verify a clean
installation, `pip check`, and a fixture scan with the supported Python versions.
The hashes make future installations use the reviewed artifacts; they do not
establish that a dependency is free of vulnerabilities.
