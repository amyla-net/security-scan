"""Bounded ZAP automation with origin-scoped credentials and validated reports."""

import base64
import html
import json
import os
import re
import shutil
import signal
import subprocess
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


IMAGE = "ghcr.io/zaproxy/zaproxy@sha256:17711b689795c5519c512bafee363b3976ce8457358db8405c6961e18c72dc66"


def target_url(value: str) -> str:
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme not in {"http", "https"} or not parsed.hostname
            or parsed.username is not None or parsed.password is not None
            or parsed.query or parsed.fragment or re.search(r"[\s\\]", value)):
        raise ValueError("ZAP requires an HTTP(S) target without credentials, query, or fragment.")
    port = parsed.port
    host = parsed.hostname.lower()
    host = f"[{host}]" if ":" in host else host.encode("idna").decode()
    authority = host + (f":{port}" if port and port != {"http": 80, "https": 443}[parsed.scheme] else "")
    return urllib.parse.urlunsplit((parsed.scheme, authority, parsed.path or "/", "", ""))


def configuration(input_value, secret_value=None) -> dict:
    secret_value = secret_value or input_value
    mode = input_value("zap-scan-mode", "baseline")
    if mode not in {"baseline", "full"}:
        raise ValueError("ZAP mode must be baseline or full.")
    timeout_value = input_value("zap-timeout") or ("600" if mode == "baseline" else "3600")
    if not timeout_value.isdecimal() or not 60 <= int(timeout_value) <= 5400:
        raise ValueError("ZAP timeout must be between 60 and 5400 seconds.")
    headers = json.loads(input_value("zap-headers") or "{}")
    if not isinstance(headers, dict) or len(headers) > 20:
        raise ValueError("ZAP headers must be a JSON object.")
    normalized_headers = {}
    for name, value in headers.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                or not isinstance(value, str) or not value or re.search(r"[\r\n\x00]", value)
                or name.lower() in {"host", "content-length", "connection", "transfer-encoding"}
                or name.lower() in normalized_headers):
            raise ValueError("Invalid ZAP request header.")
        normalized_headers[name.lower()] = value
    username = secret_value("zap-auth-username")
    password = secret_value("zap-auth-password")
    if bool(username) != bool(password) or ":" in username:
        raise ValueError("ZAP Basic authentication needs both username and password.")
    if username:
        if "authorization" in normalized_headers:
            raise ValueError("Basic authentication and an Authorization header cannot be combined.")
        normalized_headers["authorization"] = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
    excludes = list(dict.fromkeys(line.strip() for line in input_value("zap-exclude-urls").splitlines() if line.strip()))
    for expression in excludes:
        try:
            re.compile(expression)
        except re.error:
            raise ValueError("Invalid ZAP exclusion regex.") from None
    fail_on = input_value("zap-fail-on", "inherit")
    if fail_on not in {"inherit", "none", "high", "medium"}:
        raise ValueError("ZAP fail policy must be inherit, none, high, or medium.")
    url = target_url(input_value("zap-target-url"))
    origin = urllib.parse.urlunsplit((*urllib.parse.urlsplit(url)[:2], "", "", ""))
    scope = "^" + re.escape(origin) + r"(?:/.*)?$"
    if urllib.parse.urlsplit(url).path != "/":
        scope = "^" + re.escape(url.rstrip("/")) + r"(?:[/?].*)?$"
    # A non-secret identity distinguishes roles without hashing credentials.
    auth_profile = input_value("zap-auth-profile", "default")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", auth_profile):
        raise ValueError("ZAP auth profile must be a short non-secret identifier.")
    return {"url": url, "mode": mode, "timeout": int(timeout_value), "scope": scope,
            "excludes": excludes, "headers": normalized_headers, "fail_on": fail_on,
            "secrets": [value for value in [username, password, *normalized_headers.values(),
                         *[v.split(" ", 1)[-1] for v in normalized_headers.values()]] if value],
            "settings": {"url": url, "mode": mode, "timeout": int(timeout_value), "excludes": excludes,
                         "image": IMAGE, "plan_version": 1, "auth_profile": auth_profile,
                         "auth_type": "basic" if username else ("headers" if headers else "public"),
                         "header_names": sorted(normalized_headers)}}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def preflight(config: dict) -> None:
    opener = urllib.request.build_opener(NoRedirect())
    url = config["url"]
    for _ in range(6):
        if any(re.fullmatch(pattern, url) for pattern in config["excludes"]):
            raise ValueError("ZAP target is excluded from the scan.")
        request = urllib.request.Request(url, headers=config["headers"])
        try:
            with opener.open(request, timeout=20) as response:
                if not 200 <= response.status < 300:
                    raise ValueError("ZAP target did not return a successful response.")
                config["verification_url"] = url
                config["verification_status"] = response.status
                return
        except urllib.error.HTTPError as error:
            code, location = error.code, error.headers.get("Location", "")
            error.close()
            if code not in {301, 302, 303, 307, 308}:
                raise ValueError("ZAP target is unavailable or blocked.") from None
            destination = urllib.parse.urljoin(url, location)
            if not re.fullmatch(config["scope"], destination) or any(re.fullmatch(p, destination) for p in config["excludes"]):
                raise ValueError("ZAP target redirects outside the scan scope.") from None
            url = destination
    raise ValueError("ZAP target has too many redirects.")


def automation_plan(config: dict) -> dict:
    context = {"name": "amyla", "urls": [config["url"]], "includePaths": [config["scope"]],
               "excludePaths": config["excludes"]}
    jobs = [{"type": "passiveScan-config", "parameters": {"scanOnlyInScope": True}}]
    if config["headers"]:
        jobs.append({"type": "replacer", "rules": [
            {"description": f"request header {name}", "url": config["scope"],
             "matchType": "req_header", "matchString": name, "matchRegex": False,
             "replacementString": value}
            for name, value in sorted(config["headers"].items())
        ] + [
            {"description": f"remove {name} outside scan scope", "url": "^(?!" + config["scope"] + ").*",
             "matchType": "req_header", "matchString": name, "matchRegex": False, "replacementString": ""}
            for name in sorted(config["headers"])
        ]})
    jobs.append({"type": "requestor", "requests": [{"url": config.get("verification_url", config["url"]),
                 "method": "GET", "responseCode": config.get("verification_status", 200)}]})
    jobs.append({"type": "spider", "parameters": {
        "context": "amyla", "url": config["url"], "maxDuration": 1 if config["mode"] == "baseline" else 5,
        "threadCount": 2, "postForm": False, "processForm": config["mode"] == "full",
    }})
    if config["mode"] == "full":
        jobs.append({"type": "activeScan", "parameters": {"context": "amyla", "threadPerHost": 2,
                      "delayInMs": 100}, "policyDefinition": {"defaultStrength": "Medium", "defaultThreshold": "Medium"}})
    jobs += [{"type": "passiveScan-wait", "parameters": {"maxDuration": 5}},
             {"type": "report", "parameters": {"template": "traditional-json", "reportDir": "/zap/wrk",
                                                "reportFile": "raw-zap.json", "displayReport": False},
              "sites": [urllib.parse.urlunsplit((*urllib.parse.urlsplit(config["url"])[:2], "", "", ""))],
              "alwaysRun": True}]
    return {"env": {"contexts": [context], "parameters": {"failOnError": True, "failOnWarning": True,
                                                            "progressToStdout": False}}, "jobs": jobs}


def valid_report(payload: object, expected_url: str | None = None) -> bool:
    if not isinstance(payload, dict) or not isinstance(payload.get("@version"), str) or not payload["@version"]:
        return False
    sites = payload.get("site")
    if not isinstance(sites, list) or not sites:
        return False
    try:
        expected_origin = urllib.parse.urlsplit(target_url(expected_url))[:2] if expected_url else None
    except ValueError:
        return False
    for site in sites:
        if not isinstance(site, dict) or not isinstance(site.get("@name"), str) or not isinstance(site.get("alerts"), list):
            return False
        try:
            site_origin = urllib.parse.urlsplit(target_url(site["@name"]))[:2]
            if expected_origin and site_origin != expected_origin:
                return False
        except ValueError:
            return False
        for alert in site["alerts"]:
            if (not isinstance(alert, dict) or not re.fullmatch(r"[0-9]+", str(alert.get("pluginid", "")))
                    or str(alert.get("riskcode", "")) not in {"0", "1", "2", "3"}
                    or str(alert.get("confidence", "")) not in {"0", "1", "2", "3", "4"}
                    or not isinstance(alert.get("name", alert.get("alert")), str)
                    or not alert.get("instances") or not isinstance(alert["instances"], list)):
                return False
            for instance in alert["instances"]:
                if (not isinstance(instance, dict) or not isinstance(instance.get("uri"), str)
                        or not isinstance(instance.get("method"), str) or not instance["method"]
                        or not isinstance(instance.get("param", ""), str)):
                    return False
                try:
                    parsed = urllib.parse.urlsplit(instance["uri"])
                    instance_origin = urllib.parse.urlsplit(target_url(urllib.parse.urlunsplit((*parsed[:2], "", "", ""))))[:2]
                except ValueError:
                    return False
                if re.search(r"[\s\\]", instance["uri"].split("#", 1)[0]) or instance_origin != site_origin:
                    return False
    return True


def counts(payload: dict, threshold: str = "high") -> tuple[int, int]:
    found = {}
    for site in payload["site"]:
        for alert in site["alerts"]:
            if str(alert["confidence"]) == "0":
                continue
            for instance in alert["instances"]:
                parsed = urllib.parse.urlsplit(instance["uri"])
                keys = sorted(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
                identity = (str(alert["pluginid"]), parsed.scheme, parsed.netloc, parsed.path,
                            tuple(keys), instance["method"].upper(), instance.get("param", ""))
                found[identity] = max(found.get(identity, 0), int(alert["riskcode"]))
    return len(found), sum(risk >= (2 if threshold == "medium" else 3) for risk in found.values())


def redact(value, secrets: list[str]):
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            if key in {"@version", "@name", "@host", "@port", "@ssl", "pluginid", "riskcode", "confidence", "method"}:
                result[key] = item
            elif key == "uri" and isinstance(item, str):
                parsed = urllib.parse.urlsplit(item)
                result[key] = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, redact(parsed.path, secrets),
                                                      redact(parsed.query, secrets), ""))
            else:
                result[key] = redact(item, secrets)
        return result
    if isinstance(value, list):
        return [redact(item, secrets) for item in value]
    if isinstance(value, str):
        variants = {variant for secret in secrets if secret for variant in
                    (secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret), html.escape(secret))}
        for secret in sorted(variants, key=len, reverse=True):
            value = value.replace(secret, "[REDACTED]")
    return value


def run(config: dict, reports: Path, environment: dict) -> dict:
    work = reports.parent / "zap-work"
    work.mkdir(mode=0o700)
    (work / "home").mkdir()
    plan = work / "plan.yaml"
    name = "amyla-zap-" + uuid.uuid4().hex
    previous_handler = signal.getsignal(signal.SIGTERM)
    def terminate(signum, frame):
        raise KeyboardInterrupt("ZAP execution cancelled.")
    signal.signal(signal.SIGTERM, terminate)
    state = {"status": "failed", "reason": "ZAP could not complete the configured scan.",
             "target_url": config["url"], "scan_mode": config["mode"], "fail_on": config["fail_on"]}
    try:
        preflight(config)
        plan.write_text(json.dumps(automation_plan(config)))
        plan.chmod(0o600)
        # Pull separately: a timed-out pull must never start an orphan scanner.
        pull = subprocess.run(["docker", "pull", IMAGE], env=environment, capture_output=True, timeout=300)
        if pull.returncode != 0:
            return {**state, "reason": "The pinned ZAP image could not be downloaded."}
        command = ["docker", "run", "--rm", "--name", name, "--network", "host",
                   "--pull", "never",
                   "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                   "--env", "HOME=/zap/wrk/home", "--env", "JAVA_TOOL_OPTIONS=-Duser.home=/zap/wrk/home",
                   "--volume", f"{work}:/zap/wrk:rw", IMAGE, "zap.sh", "-cmd", "-silent", "-dir", "/zap/wrk/home",
                   "-autorun", "/zap/wrk/plan.yaml"]
        completed = subprocess.run(command, env=environment, capture_output=True, timeout=config["timeout"])
        state["exit_code"] = completed.returncode
        raw = work / "raw-zap.json"
        if raw.is_file() and not raw.is_symlink():
            payload = json.loads(raw.read_text())
            if valid_report(payload, config["url"]):
                report = reports / "zap.json"
                report.write_text(json.dumps(redact(payload, config["secrets"]), indent=2) + "\n")
                report.chmod(0o600)
                state["report"] = report.name
                if completed.returncode == 0:
                    total, gated = counts(payload, config["fail_on"])
                    state.update(status="completed", findings=total, findings_in_fail_severities=gated)
                    state.pop("reason", None)
        return state
    except subprocess.TimeoutExpired:
        return {**state, "reason": "ZAP exceeded its scan timeout; coverage is incomplete."}
    except (ValueError, OSError, urllib.error.URLError):
        return state
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        try:
            try:
                subprocess.run(["docker", "rm", "--force", name], env=environment, capture_output=True, timeout=30)
            except (OSError, subprocess.TimeoutExpired):
                pass
        finally:
            try:
                shutil.rmtree(work)
            finally:
                signal.signal(signal.SIGTERM, previous_handler)
