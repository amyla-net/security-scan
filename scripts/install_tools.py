"""Pinned scanner installation, isolated from the scanned repository."""

import hashlib
import io
import platform
import subprocess
import tarfile
import urllib.request
from pathlib import Path


VERSIONS = {"gitleaks": "8.30.1", "semgrep": "1.179.0", "trivy": "0.75.0"}
BINARY_RELEASES = {
    "gitleaks": (
        "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    ),
    "trivy": (
        "https://github.com/aquasecurity/trivy/releases/download/v0.75.0/trivy_0.75.0_Linux-64bit.tar.gz",
        "c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f",
    ),
}


def install(name: str, directory: Path, environment: dict[str, str]) -> str:
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "amd64"}:
        raise ValueError("This release supports Ubuntu x64 runners only.")
    directory.mkdir(parents=True, exist_ok=True)
    if name == "semgrep":
        venv = directory / "semgrep-venv"
        subprocess.run(
            ["python3", "-m", "venv", str(venv)], env=environment,
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120,
        )
        subprocess.run(
            [str(venv / "bin/python"), "-m", "pip", "install", "--disable-pip-version-check",
             "--no-input", "--quiet", f"semgrep=={VERSIONS[name]}"],
            env=environment, check=True, stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, timeout=600,
        )
        return str(venv / "bin/semgrep")

    url, expected_digest = BINARY_RELEASES[name]
    request = urllib.request.Request(url, headers={"User-Agent": "amyla-security-scan"})
    with urllib.request.urlopen(request, timeout=120) as response:
        archive_bytes = response.read(150 * 1024 * 1024 + 1)
    if len(archive_bytes) > 150 * 1024 * 1024:
        raise ValueError("Scanner release archive is too large.")
    if hashlib.sha256(archive_bytes).hexdigest() != expected_digest:
        raise ValueError("Scanner release checksum does not match the pinned checksum.")
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as archive:
        member = archive.getmember(name)
        if not member.isfile():
            raise ValueError("Scanner release does not contain a regular executable.")
        stream = archive.extractfile(member)
        if stream is None:
            raise ValueError("Scanner executable is missing.")
        executable = directory / name
        executable.write_bytes(stream.read())
    executable.chmod(0o700)
    return str(executable)
