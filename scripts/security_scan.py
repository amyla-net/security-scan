"""Standalone scan orchestration, raw-report upload, and final CI gate."""

import argparse
import hashlib
import html
import http.client
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib

from install_tools import VERSIONS, install


SCANNERS = ("gitleaks", "semgrep", "trivy", "composer_audit", "npm_audit", "phpstan")
PROFILE_EXCLUDES = {
    "general": ["vendor", "node_modules", ".git"],
    "php": ["vendor", "node_modules", ".git", "var/cache", "cache"],
    "laravel": ["vendor", "node_modules", ".git", "storage", "bootstrap/cache", "public/vendor"],
    "kirby": ["vendor", "node_modules", ".git", "storage", "media", "public/media"],
}
PROFILE_RULES = {
    "general": ["p/default", "p/security-audit", "p/ci"],
    "php": ["p/default", "p/phpcs-security-audit", "p/security-audit", "p/php", "p/ci"],
    "kirby": ["p/default", "p/phpcs-security-audit", "p/security-audit", "p/owasp-top-ten", "p/php", "p/javascript", "p/ci"],
    "laravel": ["p/default", "p/phpcs-security-audit", "p/security-audit", "p/owasp-top-ten", "p/php", "p/php-laravel", "p/javascript", "p/ci"],
}


def split_items(value: str) -> list[str]:
    return list(dict.fromkeys(item.strip() for item in value.replace(",", "\n").splitlines() if item.strip()))


def flag(value: str, default: bool) -> bool:
    if value in {"", "auto"}:
        return default
    if value in {"true", "false"}:
        return value == "true"
    raise ValueError("Boolean inputs must be auto, true, or false.")


def input_value(name: str, default: str = "") -> str:
    return os.environ.get("SCAN_" + name.upper().replace("-", "_"), default).strip()


def safe_path(root: Path, value: str, *, directory: bool = False) -> Path:
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or value.startswith("-"):
        raise ValueError("Paths must be relative to the scanned repository directory.")
    candidate = (root / relative).resolve(strict=True)
    if not candidate.is_relative_to(root.resolve()):
        raise ValueError("Paths and symlinks must stay inside the scanned repository directory.")
    if directory and not candidate.is_dir():
        raise ValueError("Expected a repository directory.")
    if not directory and not candidate.is_file():
        raise ValueError("Expected a repository configuration file.")
    return candidate


def profile_for(root: Path, selected: str) -> str:
    if selected != "auto":
        if selected not in PROFILE_RULES:
            raise ValueError("profile must be auto, laravel, kirby, php, or general.")
        return selected
    manifest = root / "composer.json"
    if manifest.is_file():
        payload = json.loads(manifest.read_text())
        requirements = {**payload.get("require", {}), **payload.get("require-dev", {})}
        if "laravel/framework" in requirements:
            return "laravel"
        if "getkirby/cms" in requirements:
            return "kirby"
        return "php"
    return "general"


def selected_gitleaks_config(root: Path) -> Path | None:
    explicit = input_value("gitleaks-config")
    if explicit:
        return safe_path(root, explicit)
    for path in (".github/.gitleaks.toml", ".gitleaks.toml"):
        if (root / path).exists():
            return safe_path(root, path)
    return None


def gitleaks_config_files(root: Path, config: Path) -> list[str]:
    files = []
    while config is not None:
        if str(config) in files:
            raise ValueError("Gitleaks configuration contains a circular extension.")
        files.append(str(config))
        extension = tomllib.loads(config.read_text()).get("extend", {}).get("path")
        config = safe_path(root, extension) if extension else None
    return files


def semgrep_ignore_files(root: Path) -> list[str]:
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", str(root))).resolve()
    files = []
    directory = root
    while directory.is_relative_to(workspace):
        for filename in (".gitignore", ".semgrepignore"):
            if (directory / filename).exists():
                files.append(str(directory / filename))
        if directory == workspace:
            break
        directory = directory.parent
    for directory, directories, filenames in os.walk(root):
        directories[:] = sorted(name for name in directories if name not in {".git", "node_modules", "vendor"})
        for filename in (".gitignore", ".semgrepignore"):
            if filename in filenames:
                files.append(str(Path(directory) / filename))
    exclude = workspace / ".git/info/exclude"
    if exclude.is_file():
        files.append(str(exclude))
    for filename in list(files):
        if Path(filename).name == ".semgrepignore":
            files.extend(semgrep_include_files(workspace, Path(filename)))
    return list(dict.fromkeys(files))


def semgrep_include_files(workspace: Path, ignore_file: Path) -> list[str]:
    files = []
    visiting = set()
    def visit(candidate: Path) -> None:
        candidate = candidate.resolve(strict=True)
        if not candidate.is_relative_to(workspace) or not candidate.is_file():
            raise ValueError("Semgrep ignore includes must stay inside the checked-out repository.")
        if candidate in visiting:
            raise ValueError("Semgrep ignore configuration contains a circular include.")
        if str(candidate) in files:
            return
        visiting.add(candidate)
        files.append(str(candidate))
        for line in candidate.read_text().splitlines():
            directive = re.match(r"^\s*:include\s+(.+?)\s*$", line)
            if directive:
                included = Path(directive[1])
                if included.is_absolute():
                    raise ValueError("Semgrep ignore includes must use local relative paths.")
                visit(candidate.parent / included)
        visiting.remove(candidate)
    visit(ignore_file)
    return files


def assert_full_git_history(root: Path, environment: dict[str, str]) -> None:
    completed = subprocess.run(["git", "rev-parse", "--is-shallow-repository"], cwd=root,
                               env=environment, capture_output=True, text=True, timeout=30)
    if completed.returncode != 0 or completed.stdout.strip() != "false":
        raise ValueError("Gitleaks git mode requires a full checkout with fetch-depth: 0.")


def neon_without_comment(line: str) -> str:
    # Consume NEON strings and literals as tokens: a hash inside a literal
    # belongs to the path, whereas a hash at a token boundary starts a comment.
    token = re.compile(r"""
        '(?:''|[^'\n])*' | "(?:\\.|[^"\\\n])*" |
        (?:[^#"',:=[\]{}()\n\t `-]|(?<!["'])[:-][^"',=[\]{}()\n\t ])
        (?:[^,:=\]})(\n\t ]+|:(?![\n\t ,\]})]|$)|[ \t]+[^#,:=\]})(\n\t ])*
        """, re.VERBOSE)
    index = 0
    while index < len(line):
        if line[index] == "#":
            return line[:index]
        matched = token.match(line, index)
        index = matched.end() if matched else index + 1
    return line


def phpstan_config_files(root: Path, config: Path) -> list[str]:
    files = []
    queue = [config]
    while queue:
        candidate = queue.pop()
        if str(candidate) in files:
            continue
        if not (candidate.name.endswith(".neon") or candidate.name.endswith(".neon.dist") or candidate.name.endswith(".dist.neon")):
            raise ValueError("This release supports static NEON PHPStan configuration only.")
        files.append(str(candidate))
        lines = candidate.read_text().splitlines()
        included = []
        inside = False
        includes_indent = 0
        for line in lines:
            line = neon_without_comment(line)
            if re.match(r"^\s*includes:", line):
                inside = True
                includes_indent = len(line) - len(line.lstrip())
                inline = line.partition(":")[2].strip()
                if inline:
                    if not (inline.startswith("[") and inline.endswith("]")):
                        raise ValueError("PHPStan includes must use a static NEON list.")
                    included.extend(split_items(inline[1:-1]))
                continue
            indent = len(line) - len(line.lstrip())
            if inside and line.strip() and indent <= includes_indent:
                inside = False
            if inside and line.strip():
                if not line.lstrip().startswith("- "):
                    raise ValueError("PHPStan includes must use a static NEON list.")
                included.append(line.lstrip()[2:].strip())
        for name in included:
            name = name.strip("\"'")
            if "%" in name or Path(name).is_absolute():
                raise ValueError("Dynamic PHPStan configuration includes are unsupported.")
            resolved = (candidate.parent / name).resolve(strict=True)
            if not resolved.is_relative_to(root) or not resolved.is_file():
                raise ValueError("PHPStan included configs must stay inside the repository directory.")
            queue.append(resolved)
    return files


def trivy_config_files(root: Path, tools: Path, environment: dict[str, str]) -> list[str]:
    files = []
    ignorefile = ".trivyignore"
    explicit_ignore = False
    if (root / "trivy.yaml").exists() or (root / "trivy.yaml").is_symlink():
        config = safe_path(root, "trivy.yaml")
        files.append(str(config))
        python = install("pyyaml", tools, environment)
        # Use a safe YAML loader in an isolated interpreter so repository modules
        # cannot shadow the parser. Emit only the setting we need, never the config.
        parser = """import json, re, sys, yaml
from pathlib import Path
class TrivyLoader(yaml.SafeLoader):
    pass
# Go's YAML resolver recognizes true/false as booleans, but leaves YAML 1.1
# spellings such as yes/no/on/off as strings. Keep the other safe resolvers.
TrivyLoader.yaml_implicit_resolvers = {
    key: [(tag, pattern) for tag, pattern in resolvers
          if tag != 'tag:yaml.org,2002:bool']
    for key, resolvers in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
TrivyLoader.add_implicit_resolver('tag:yaml.org,2002:bool',
    re.compile(r'^(?:true|True|TRUE|false|False|FALSE)$'), list('tTfF'))
config = yaml.load(Path(sys.argv[1]).read_text(), Loader=TrivyLoader)
if config is None:
    config = {}
if not isinstance(config, dict):
    raise ValueError('Expected a YAML mapping.')
print(json.dumps({str(key).lower(): value for key, value in config.items()}.get('ignorefile')))
"""
        parsed = subprocess.run([python, "-I", "-c", parser, str(config)], env=environment,
                                capture_output=True, text=True, check=True, timeout=30)
        value = json.loads(parsed.stdout)
        if value is not None:
            if not isinstance(value, str):
                raise ValueError("Trivy ignorefile must be a local file path or an empty string.")
            ignorefile = value
            explicit_ignore = True
    if ignorefile and (explicit_ignore or (root / ignorefile).exists() or (root / ignorefile).is_symlink()):
        files.append(str(safe_path(root, ignorefile)))
    return files


def npm_audit_config(root: Path, directory: Path) -> tuple[list[str], dict]:
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", str(root))).resolve()
    if not directory.is_relative_to(workspace):
        raise ValueError("npm audit directories must stay inside the checked-out repository.")
    for ancestor in workspace.parents:
        manifest = ancestor / "package.json"
        if manifest.is_symlink():
            raise ValueError("npm workspace configurations outside the checkout are unsupported.")
        if manifest.is_file():
            payload = json.loads(manifest.read_text(encoding="utf-8-sig"))
            if not isinstance(payload, dict) or payload.get("workspaces"):
                raise ValueError("npm workspace configurations outside the checkout are unsupported.")
    files = []
    settings = {}
    while directory.is_relative_to(workspace):
        relative = directory.relative_to(workspace)
        config = directory / ".npmrc"
        if config.exists() or config.is_symlink():
            files.append(str(safe_path(workspace, (relative / ".npmrc").as_posix())))
        manifest = directory / "package.json"
        if manifest.exists() or manifest.is_symlink():
            safe_manifest = safe_path(workspace, (relative / "package.json").as_posix())
            payload = json.loads(safe_manifest.read_text(encoding="utf-8-sig"))
            if not isinstance(payload, dict):
                raise ValueError("npm project configuration is invalid.")
            settings[relative.as_posix()] = {"workspaces": payload.get("workspaces")}
        if directory == workspace:
            break
        directory = directory.parent
    return files, settings


def semgrep_config(root: Path, value: str) -> str:
    if re.fullmatch(r"p/[A-Za-z0-9_/-]+", value):
        return value
    relative = Path(value)
    if relative.is_absolute() or ".." in relative.parts or value.startswith("-"):
        raise ValueError("Semgrep configs must be local paths or p/... registry rules.")
    candidate = (root / relative).resolve(strict=True)
    if not candidate.is_relative_to(root) or not (candidate.is_file() or candidate.is_dir()):
        raise ValueError("Semgrep config must stay inside the scanned repository directory.")
    if candidate.is_dir():
        for child in candidate.rglob("*"):
            if not child.resolve().is_relative_to(root):
                raise ValueError("Semgrep config symlinks must stay inside the repository.")
    return str(candidate)


def selected_semgrep_configs(root: Path, profile: str) -> list[str]:
    explicit = split_items(input_value("semgrep-config"))
    if explicit:
        selected = explicit
    else:
        local = next((path for path in (".semgrep.yml", ".semgrep.yaml") if (root / path).exists()), None)
        selected = [local] if local else PROFILE_RULES[profile]
    return list(dict.fromkeys(semgrep_config(root, value) for value in selected + split_items(input_value("semgrep-extra-configs"))))


def clean_environment(temp_directory: Path) -> dict[str, str]:
    allowed = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "SYSTEMROOT") if key in os.environ}
    # A separate home avoids user/global scanner configs, credentials, and caches.
    home_directory = temp_directory / "home"
    home_directory.mkdir(parents=True, exist_ok=True)
    return {**allowed, "HOME": str(home_directory), "TMPDIR": str(temp_directory),
            "CI": "true", "NO_COLOR": "1", "SEMGREP_SEND_METRICS": "off",
            "SEMGREP_ENABLE_VERSION_CHECK": "0", "COMPOSER_NO_INTERACTION": "1",
            "COMPOSER_HOME": str(home_directory / "composer"),
            "npm_config_cache": str(temp_directory / "npm-cache"),
            "npm_config_userconfig": str(home_directory / ".npmrc")}


def metadata(root: Path) -> dict:
    event = {}
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    if event_path:
        event = json.loads(Path(event_path).read_text())
    commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True,
                            text=True, check=True, timeout=30).stdout.strip()
    repository = event.get("repository") or {}
    result = {
        "repository": os.environ.get("GITHUB_REPOSITORY", repository.get("full_name", "")),
        "repository_id": os.environ.get("GITHUB_REPOSITORY_ID", str(repository.get("id", ""))),
        "default_ref": repository.get("default_branch", ""),
        "ref": os.environ.get("GITHUB_REF_NAME", ""), "commit_sha": commit,
        "event_name": os.environ.get("GITHUB_EVENT_NAME", ""),
        "run_id": os.environ.get("GITHUB_RUN_ID", ""),
        "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT", "1"),
        "run_number": os.environ.get("GITHUB_RUN_NUMBER", ""),
        "actor": os.environ.get("GITHUB_ACTOR", ""),
        "run_url": f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}",
    }
    if event.get("pull_request"):
        result["pull_request_number"] = str(event["pull_request"]["number"])
    return result


def scope_hash(root: Path, scanner: str, settings: dict, configs: list[str]) -> str:
    workspace = Path(os.environ.get("GITHUB_WORKSPACE", str(root))).resolve()
    parts = {"scanner": scanner, "directory": root.relative_to(workspace).as_posix(),
             "settings": settings, "configs": []}
    for config in configs:
        path = Path(config)
        if not path.exists():
            parts["configs"].append({"rules": config})
            continue
        candidates = sorted(path.rglob("*")) if path.is_dir() else [path]
        for candidate in candidates:
            if candidate.is_file():
                resolved = candidate.resolve()
                if not resolved.is_relative_to(workspace):
                    raise ValueError("Configuration symlinks must stay inside the repository.")
                parts["configs"].append({"path": resolved.relative_to(workspace).as_posix(),
                                         "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest()})
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def save_json(path: Path, payload: dict | list) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n")
    path.chmod(0o600)


def output(name: str, value: str) -> None:
    if "\n" in value or "\r" in value:
        raise ValueError("Output must be a single line.")
    if os.environ.get("GITHUB_OUTPUT"):
        with Path(os.environ["GITHUB_OUTPUT"]).open("a") as stream:
            stream.write(f"{name}={value}\n")


def run_command(command: list[str], root: Path, environment: dict[str, str], report: Path | None = None) -> tuple[int, str]:
    completed = subprocess.run(command, cwd=root, env=environment, capture_output=True, timeout=900)
    if report is not None:
        report.write_bytes(completed.stdout)
        report.chmod(0o600)
    # Do not echo scanner stdout/stderr: findings and config values may contain secrets.
    return completed.returncode, completed.stderr.decode(errors="replace")


def valid_report(scanner: str, payload: object, code: int, stderr: str = "") -> bool:
    if scanner == "gitleaks":
        return isinstance(payload, list) and code in {0, 10}
    if not isinstance(payload, dict):
        return False
    if scanner == "semgrep":
        return (code == 0 and isinstance(payload.get("results"), list)
                and isinstance(payload.get("errors"), list) and not payload["errors"])
    if scanner == "trivy":
        # Empty filesystem scans legitimately omit Results. Require the scan
        # identity instead of accepting a bare SchemaVersion as a full report.
        results = payload.get("Results", [])
        if (code != 0 or type(payload.get("SchemaVersion")) is not int or payload["SchemaVersion"] != 2
                or payload.get("ArtifactType") != "filesystem"
                or not isinstance(payload.get("ArtifactName"), str) or not payload["ArtifactName"]
                or not isinstance(results, list) or payload.get("error")):
            return False
        for result in results:
            if (not isinstance(result, dict) or not isinstance(result.get("Target"), str)
                    or not result["Target"]):
                return False
            for key in ("Vulnerabilities", "Misconfigurations", "Secrets", "Licenses"):
                findings = result.get(key, [])
                if not isinstance(findings, list) or not all(isinstance(finding, dict) for finding in findings):
                    return False
        return True
    if scanner == "composer_audit":
        stderr = "\n".join(line for line in stderr.splitlines() if not (
            line.startswith("Composer could not detect the root package (")
            and "https://getcomposer.org/root-version" in line
        ))
        return (code in {0, 1, 2, 3} and isinstance(payload.get("advisories"), (dict, list))
                and not payload.get("error") and not re.search(r"(failed|unable|could not|incomplete|warning)", stderr, re.I))
    if scanner == "npm_audit":
        metadata = payload.get("metadata")
        if not isinstance(metadata, dict) or not isinstance(metadata.get("vulnerabilities"), dict):
            return False
        total = metadata["vulnerabilities"].get("total")
        return (code in {0, 1} and isinstance(payload.get("vulnerabilities"), dict)
                and type(total) is int and total >= 0 and not payload.get("error"))
    if scanner == "phpstan":
        return (code in {0, 1} and isinstance(payload.get("files"), dict)
                and isinstance(payload.get("totals"), dict) and not payload.get("errors"))
    return False


def counts(scanner: str, payload: dict | list) -> tuple[int, int]:
    if scanner == "gitleaks":
        return len(payload), len(payload)
    if scanner == "semgrep":
        return len(payload["results"]), len(payload["results"])
    if scanner == "phpstan":
        count = sum(len(value.get("messages", [])) for value in payload["files"].values())
        return count, count
    if scanner == "composer_audit":
        count = sum(len(value) if isinstance(value, list) else 1 for value in payload["advisories"].values()) if isinstance(payload["advisories"], dict) else len(payload["advisories"])
        return count, count
    if scanner == "npm_audit":
        count = payload["metadata"]["vulnerabilities"]["total"]
        return count, count
    total = gate = 0
    for result in payload.get("Results", []):
        for key in ("Vulnerabilities", "Misconfigurations", "Secrets", "Licenses"):
            for finding in result.get(key) or []:
                total += 1
                gate += str(finding.get("Severity", "")).upper() in {"HIGH", "CRITICAL"}
    return total, gate


class Scanner:
    def __init__(self, root: Path, reports: Path, profile: str):
        self.root = root
        self.reports = reports
        self.profile = profile
        self.environment = clean_environment(reports.parent)
        self.excludes = PROFILE_EXCLUDES[profile]

    def executable(self, name: str) -> str:
        if name in VERSIONS:
            return install(name, self.reports.parent / "tools", self.environment)
        executable = shutil.which(name, path=self.environment.get("PATH"))
        if not executable:
            raise ValueError("Required executable is unavailable on this runner.")
        return executable

    def raw_scan(self, name: str) -> dict:
        report = self.reports / f"{name}.json"
        configs = []
        settings = {}
        stdout_report = False
        if name == "gitleaks":
            config = selected_gitleaks_config(self.root)
            mode = input_value("gitleaks-mode", "directory")
            if mode not in {"git", "directory"}:
                raise ValueError("gitleaks-mode must be git or directory.")
            if mode == "git":
                assert_full_git_history(self.root, self.environment)
            command = [self.executable(name), "git" if mode == "git" else "dir", ".",
                       "--redact=100", "--no-banner", "--exit-code=10", "--report-format=json", f"--report-path={report}"]
            if config:
                configs.extend(gitleaks_config_files(self.root, config))
                command += ["--config", str(config)]
            settings["mode"] = mode
            if (self.root / ".gitleaksignore").exists():
                configs.append(str(safe_path(self.root, ".gitleaksignore")))
        elif name == "semgrep":
            configs = selected_semgrep_configs(self.root, self.profile)
            excludes = list(dict.fromkeys(self.excludes + split_items(input_value("semgrep-extra-excludes"))))
            command = [self.executable(name), "scan", "--json", "--metrics=off", "--disable-version-check", "--strict", "--output", str(report)]
            for config in configs:
                command += ["--config", config]
            for exclude in excludes:
                command += ["--exclude", exclude]
            command += ["."]
            settings["excludes"] = excludes
            if (self.root / ".semgrepignore").exists():
                configs.append(str(safe_path(self.root, ".semgrepignore")))
            configs.extend(semgrep_ignore_files(self.root))
        elif name == "trivy":
            excludes = list(dict.fromkeys(self.excludes + split_items(input_value("trivy-extra-skip-dirs"))))
            command = [self.executable(name), "fs", "--scanners", "vuln,misconfig", "--format", "json", "--output", str(report), "--exit-code", "0", "--timeout", "10m", "--quiet"]
            for exclude in excludes:
                command += ["--skip-dirs", exclude]
            command += ["."]
            settings["excludes"] = excludes
            configs.extend(trivy_config_files(self.root, self.reports.parent / "tools", self.environment))
        else:
            executable = safe_path(self.root, "vendor/bin/phpstan")
            command = [str(executable), "analyse", "--error-format=json", "--no-progress", "--memory-limit=1G"]
            explicit = input_value("phpstan-config")
            if explicit:
                config = safe_path(self.root, explicit)
                configs.extend(phpstan_config_files(self.root, config))
                command += ["--configuration", str(config)]
            else:
                for filename in ("phpstan.neon", "phpstan.neon.dist", "phpstan.dist.neon"):
                    if (self.root / filename).exists():
                        configs.extend(phpstan_config_files(self.root, safe_path(self.root, filename)))
                        break
            stdout_report = True
        scanner_scope = scope_hash(self.root, name, settings, configs)
        code, stderr = run_command(command, self.root, self.environment, report if stdout_report else None)
        payload = json.loads(report.read_text()) if report.is_file() else None
        if not valid_report(name, payload, code, stderr):
            return {"status": "failed", "reason": "Scanner failed or returned an incomplete report.", "scope_hash": scanner_scope, "exit_code": code, "report": report.name if report.exists() else None}
        findings, gate_findings = counts(name, payload)
        return {"status": "completed", "report": report.name, "scope_hash": scanner_scope,
                "findings": findings, "findings_in_fail_severities": gate_findings, "exit_code": code}

    def audit(self, name: str) -> dict:
        path_input = input_value(name.replace("_", "-") + "-paths")
        directories = split_items(path_input) or ["."]
        projects = []
        configs = []
        project_settings = {}
        findings = 0
        executable = self.executable("composer" if name == "composer_audit" else "npm")
        for relative in directories:
            try:
                directory = safe_path(self.root, relative, directory=True)
                expected = ["composer.lock"] if name == "composer_audit" else ["package-lock.json", "npm-shrinkwrap.json"]
                if not any((directory / filename).is_file() for filename in expected):
                    raise ValueError("Selected audit directory does not contain a supported lockfile.")
                for filename in expected + (["composer.json"] if name == "composer_audit" else ["package.json"]):
                    if (directory / filename).exists():
                        safe_path(self.root, (Path(relative) / filename).as_posix())
                if name == "composer_audit" and (directory / "composer.json").is_file():
                    manifest = json.loads((directory / "composer.json").read_text())
                    if not isinstance(manifest, dict) or not isinstance(manifest.get("config", {}), dict):
                        raise ValueError("Composer audit configuration is invalid.")
                    configuration = manifest.get("config", {})
                    project_settings[directory.relative_to(self.root).as_posix()] = {
                        "audit": configuration.get("audit"), "policy": configuration.get("policy"),
                        "repositories": manifest.get("repositories"),
                    }
                elif name == "npm_audit":
                    npm_configs, npm_settings = npm_audit_config(self.root, directory)
                    configs.extend(npm_configs)
                    project_settings[directory.relative_to(self.root).as_posix()] = {"ancestors": npm_settings}
                if name == "composer_audit":
                    locked = json.loads((directory / "composer.lock").read_text())
                    if (not isinstance(locked, dict) or not isinstance(locked.get("packages"), list)
                            or not isinstance(locked.get("packages-dev"), list)):
                        raise ValueError("Composer lockfile is invalid.")
                    if not locked["packages"] and not locked["packages-dev"]:
                        projects.append({"path": directory.relative_to(self.root).as_posix(), "status": "skipped", "reason": "No locked Composer dependencies to audit."})
                        continue
                command = [executable, "--no-plugins", "--no-scripts", "audit", "--locked", "--format=json"] if name == "composer_audit" else [executable, "audit", "--json", "--package-lock-only", "--ignore-scripts"]
                raw_report = self.reports / f".{name}-{len(projects)}.json"
                code, stderr = run_command(command, directory, self.environment, raw_report)
                payload = json.loads(raw_report.read_text())
                valid = valid_report(name, payload, code, stderr)
                project = {"path": directory.relative_to(self.root).as_posix(), "status": "completed" if valid else "failed", "result": payload}
                if valid:
                    findings += counts(name, payload)[0]
                else:
                    project["reason"] = "Audit failed or returned an incomplete report."
                projects.append(project)
            except (ValueError, OSError, subprocess.SubprocessError):
                projects.append({"path": relative, "status": "failed", "reason": "Selected project could not be audited."})
        report = self.reports / f"{name}.json"
        save_json(report, {"projects": projects})
        statuses = {project["status"] for project in projects}
        status = "skipped" if statuses == {"skipped"} else ("completed" if statuses == {"completed"} else "failed")
        return {"status": status, **({"report": report.name} if status != "skipped" else {}), "findings": findings,
                "findings_in_fail_severities": findings,
                "scope_hash": scope_hash(self.root, name, {"paths": directories, "projects": project_settings}, configs),
                **({"reason": "One or more dependency projects failed or provided incomplete audit coverage."} if status == "failed" else {})}


def enabled(root: Path, scanner: str) -> bool:
    default = scanner in {"gitleaks", "semgrep", "trivy"}
    if scanner == "composer_audit":
        default = bool(input_value("composer-audit-paths")) or (root / "composer.lock").is_file()
    elif scanner == "npm_audit":
        default = bool(input_value("npm-audit-paths")) or any((root / name).is_file() for name in ("package-lock.json", "npm-shrinkwrap.json"))
    return flag(input_value("run-" + scanner.replace("_", "-"), "auto"), default)


def scan() -> int:
    temporary = Path(tempfile.mkdtemp(prefix="amyla-security-scan-", dir=os.environ.get("RUNNER_TEMP")))
    reports = temporary / "reports"
    reports.mkdir(mode=0o700)
    output("reports-path", str(reports))
    summary = {"enabled_scanners": {}, "tools": {}, "action_version": "1", "scanner_versions": VERSIONS}
    try:
        workspace = Path(os.environ.get("GITHUB_WORKSPACE", os.getcwd())).resolve()
        root = safe_path(workspace, input_value("working-directory", "."), directory=True)
        summary.update(metadata(root))
        summary["sha"] = summary["commit_sha"]
        summary["ref_name"] = summary["ref"]
        summary["profile"] = profile_for(root, input_value("profile", "auto"))
        scanner = Scanner(root, reports, summary["profile"])
        for name in SCANNERS:
            try:
                should_run = enabled(root, name)
                summary["enabled_scanners"][name] = should_run
                if not should_run:
                    summary["tools"][name] = {"status": "skipped", "reason": "Disabled or no supported dependency lockfile."}
                else:
                    summary["tools"][name] = scanner.audit(name) if name.endswith("_audit") else scanner.raw_scan(name)
            except Exception:
                summary["enabled_scanners"][name] = True
                summary["tools"][name] = {"status": "failed", "reason": "Scanner installation, configuration, or execution failed."}
            print(f"{name}: {summary['tools'][name]['status']}")
    except Exception:
        summary["configuration_error"] = "Repository configuration or GitHub metadata is invalid."
        print("::error::Repository configuration or GitHub metadata is invalid.")
    save_json(reports / "summary.json", summary)
    return 0


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_endpoint(endpoint: str) -> None:
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.username or parsed.password or parsed.fragment or parsed.query:
        raise ValueError("The ingest endpoint must not contain credentials, a query, or a fragment.")
    if not parsed.hostname or (parsed.scheme != "https" and not (parsed.scheme == "http" and parsed.hostname in {"localhost", "127.0.0.1", "::1"})):
        raise ValueError("The ingest endpoint must use HTTPS (HTTP is allowed only for local tests).")


def multipart(summary: dict, reports: Path, target_id: str) -> tuple[bytes, str]:
    boundary = "amyla-" + uuid.uuid4().hex
    parts = []
    fields = {key: summary.get(key) for key in ("repository", "repository_id", "default_ref", "ref", "commit_sha", "event_name", "run_id", "run_attempt", "run_number", "actor", "run_url", "pull_request_number")}
    if target_id:
        fields["scan_target_id"] = target_id
    for key, value in fields.items():
        if value is not None and str(value):
            parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
    files = {"summary": reports / "summary.json"}
    for scanner, state in summary.get("tools", {}).items():
        if scanner in SCANNERS and state.get("report"):
            # Never trust a report filename supplied by a scanner/configuration.
            candidate = reports / f"{scanner}.json"
            if candidate.is_file() and not candidate.is_symlink():
                files[scanner] = candidate
    for key, path in files.items():
        parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"; filename="{key}.json"\r\nContent-Type: application/json\r\n\r\n'.encode() + path.read_bytes() + b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return b"".join(parts), f"multipart/form-data; boundary={boundary}"


def send_upload(endpoint: str, token: str, body: bytes, content_type: str, *, attempts: int = 3) -> str:
    validate_endpoint(endpoint)
    if "\n" in token or "\r" in token:
        raise ValueError("Invalid upload token.")
    opener = urllib.request.build_opener(NoRedirect())
    for attempt in range(attempts):
        request = urllib.request.Request(endpoint, data=body, method="POST", headers={
            "Authorization": f"Bearer {token}", "Accept": "application/json",
            "Content-Type": content_type, "User-Agent": "amyla-security-scan/1"})
        try:
            with opener.open(request, timeout=90) as response:
                data = json.loads(response.read(1024 * 1024))
                batch_id = data.get("scan_batch", {}).get("id") or data.get("data", {}).get("scan_batch_id") or data.get("scan_batch_id")
                if not batch_id or not re.fullmatch(r"[A-Za-z0-9_-]+", str(batch_id)):
                    raise ValueError("Upload response is missing a valid scan batch identifier.")
                return str(batch_id)
        except urllib.error.HTTPError as error:
            if error.code not in {429, 500, 502, 503, 504} or attempt == attempts - 1:
                raise ValueError(f"Upload returned HTTP {error.code}.") from None
        except (urllib.error.URLError, TimeoutError, ConnectionError, http.client.RemoteDisconnected, http.client.IncompleteRead):
            if attempt == attempts - 1:
                raise ValueError("Upload could not reach the ingest endpoint.") from None
        time.sleep(2 ** attempt)
    raise ValueError("Upload failed.")


def job_summary(summary: dict, upload_state: dict) -> None:
    if not os.environ.get("GITHUB_STEP_SUMMARY"):
        return
    lines = ["## Amyla Security Scan", "", "| Scanner | Status | Findings |", "| --- | --- | ---: |"]
    for name in SCANNERS:
        state = summary.get("tools", {}).get(name, {})
        lines.append(f"| {name} | {html.escape(str(state.get('status', 'failed')))} | {int(state.get('findings', 0))} |")
    for name in SCANNERS:
        state = summary.get("tools", {}).get(name, {})
        if state.get("status") == "failed" and state.get("reason"):
            lines += ["", f"**{name}:** {html.escape(str(state['reason']))}"]
    lines += ["", f"Upload: **{upload_state['status']}**."]
    if upload_state.get("reason"):
        lines += ["", html.escape(upload_state["reason"])]
    with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
        stream.write("\n".join(lines) + "\n")


def upload() -> int:
    reports = Path(input_value("reports-path"))
    state = {"status": "failed", "reason": "Scan summary is unavailable."}
    summary = {}
    try:
        summary = json.loads((reports / "summary.json").read_text())
        token = input_value("token")
        if not token:
            state = {"status": "skipped", "reason": "No upload token was supplied; scans remain available locally."}
        elif summary.get("configuration_error"):
            state = {"status": "failed", "reason": "Upload skipped because repository metadata is invalid."}
        elif not any(item.get("status") in {"completed", "failed"} for item in summary["tools"].values()):
            state = {"status": "skipped", "reason": "All scanners were disabled or skipped."}
        else:
            body, content_type = multipart(summary, reports, input_value("target-id"))
            batch_id = send_upload(input_value("ingest-url"), token, body, content_type)
            state = {"status": "completed", "scan_batch_id": batch_id}
            output("scan-batch-id", batch_id)
    except Exception:
        state = {"status": "failed", "reason": "Upload failed; check endpoint availability, token permissions, and target limits."}
    if reports.is_dir():
        save_json(reports / "upload.json", state)
    output("upload-status", state["status"])
    job_summary(summary, state)
    print(f"Upload: {state['status']}")
    return 0


def gate_result(summary: dict, upload_state: dict, fail_on_findings: bool) -> bool:
    if summary.get("configuration_error") or upload_state.get("status") == "failed":
        return False
    states = summary.get("tools", {})
    if any(state.get("status") == "failed" for state in states.values()):
        return False
    if fail_on_findings and any(state.get("findings_in_fail_severities", 0) > 0 for state in states.values()):
        return False
    return True


def gate() -> int:
    try:
        reports = Path(input_value("reports-path"))
        summary = json.loads((reports / "summary.json").read_text())
        state = json.loads((reports / "upload.json").read_text())
        success = gate_result(summary, state, flag(input_value("fail-on-findings", "false"), False))
    except Exception:
        success = False
    if not success:
        print("::error::Security scan failed. Review scanner and upload status in the job summary.")
    return 0 if success else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("scan", "upload", "gate"))
    raise SystemExit({"scan": scan, "upload": upload, "gate": gate}[parser.parse_args().command]())
