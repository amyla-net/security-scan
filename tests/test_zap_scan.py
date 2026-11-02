import json
import os
import subprocess
import sys
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import security_scan as scan
import zap_scan as zap


def report(url="https://staging.example.com/", risk="2"):
    return {"@version": "2.17.0", "site": [{"@name": "https://staging.example.com", "alerts": [{
        "pluginid": "10020", "name": "Missing security header", "riskcode": risk, "confidence": "2",
        "instances": [{"uri": url, "method": "GET", "param": "", "evidence": ""}]
    }]}]}


class ZapTests(unittest.TestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.values = {"zap-target-url": "https://staging.example.com/"}
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repo"
        self.reports = Path(self.temporary.name) / "reports"
        self.root.mkdir()
        self.reports.mkdir()
        os.environ["GITHUB_WORKSPACE"] = str(self.root)

    def tearDown(self):
        self.temporary.cleanup()
        self.environment.stop()

    def config(self):
        return zap.configuration(lambda name, default="": self.values.get(name, default))

    def test_zap_is_disabled_by_default_even_with_target(self):
        os.environ["SCAN_ZAP_TARGET_URL"] = self.values["zap-target-url"]
        self.assertFalse(scan.enabled(self.root, "zap"))
        os.environ["SCAN_RUN_ZAP"] = "true"
        self.assertTrue(scan.enabled(self.root, "zap"))

    def test_modes_have_distinct_plans_and_deadlines(self):
        baseline = self.config()
        self.assertEqual(600, baseline["timeout"])
        self.assertNotIn("activeScan", [j["type"] for j in zap.automation_plan(baseline)["jobs"]])
        self.values["zap-scan-mode"] = "full"
        full = self.config()
        self.assertEqual(3600, full["timeout"])
        self.assertIn("activeScan", [j["type"] for j in zap.automation_plan(full)["jobs"]])
        spider = next(job for job in zap.automation_plan(baseline)["jobs"] if job["type"] == "spider")
        self.assertFalse(spider["parameters"]["postForm"])
        self.assertEqual(200, next(job for job in zap.automation_plan(baseline)["jobs"] if job["type"] == "requestor")["requests"][0]["responseCode"])

    def test_invalid_configuration_fails_before_execution(self):
        for key, value in [("zap-scan-mode", "other"), ("zap-timeout", "0"), ("zap-timeout", "5401"),
                           ("zap-timeout", "NaN"), ("zap-fail-on", "low"), ("zap-headers", "[]"),
                           ("zap-exclude-urls", "["), ("zap-auth-profile", "secret with spaces"),
                           ("zap-auth-username", "user"), ("zap-auth-password", "password")]:
            with self.subTest(key=key, value=value):
                self.values = {"zap-target-url": "https://staging.example.com/", key: value}
                with self.assertRaises(ValueError):
                    self.config()

    def test_targets_reject_credentials_unsupported_schemes_and_injection(self):
        for target in ["", "file:///etc/passwd", "https://user:pass@example.com/", "https://example.com/?token=x",
                       "https://example.com/#x", "https://example.com:invalid/", "https://example.com/\n--privileged",
                       "https://example.com\\@evil.example/"]:
            with self.subTest(target=target), self.assertRaises(ValueError):
                zap.target_url(target)
        self.assertEqual("https://example.com/", zap.target_url("https://EXAMPLE.com:443"))

    def test_headers_are_origin_scoped_and_secret_values_do_not_enter_scope(self):
        self.values["zap-headers"] = '{"Authorization":"Bearer private-token"}'
        config = self.config()
        plan = zap.automation_plan(config)
        rule = next(j for j in plan["jobs"] if j["type"] == "replacer")["rules"][0]
        self.assertTrue(__import__("re").fullmatch(rule["url"], "https://staging.example.com/path"))
        for url in ["https://evil.example/", "https://staging.example.com.evil.example/", "http://staging.example.com/"]:
            self.assertIsNone(__import__("re").search(rule["url"], url))
        self.assertNotIn("private-token", json.dumps(config["settings"]))
        before = scan.scope_hash(self.root, "zap", config["settings"], [])
        self.values["zap-headers"] = '{"Authorization":"Bearer rotated-token"}'
        self.assertEqual(before, scan.scope_hash(self.root, "zap", self.config()["settings"], []))
        self.values["zap-auth-profile"] = "admin"
        self.assertNotEqual(before, scan.scope_hash(self.root, "zap", self.config()["settings"], []))

    def test_redirects_outside_scope_remove_every_configured_header(self):
        self.values["zap-headers"] = '{"Authorization":"Bearer private-token","X-Access-Key":"private-key"}'
        config = self.config()
        rules = next(job for job in zap.automation_plan(config)["jobs"] if job["type"] == "replacer")["rules"]
        removals = [rule for rule in rules if rule["replacementString"] == ""]
        self.assertEqual({"authorization", "x-access-key"}, {rule["matchString"] for rule in removals})
        for rule in removals:
            self.assertIsNone(__import__("re").fullmatch(rule["url"], config["url"]))
            for outside in ["https://evil.example/", "http://staging.example.com/", "https://staging.example.com.evil.example/"]:
                self.assertIsNotNone(__import__("re").fullmatch(rule["url"], outside))
        job = next(job for job in zap.automation_plan(config)["jobs"] if job["type"] == "report")
        self.assertEqual(["https://staging.example.com"], job["sites"])

    def test_basic_auth_and_header_conflicts(self):
        self.values.update({"zap-auth-username": "test-user", "zap-auth-password": "private-password"})
        self.assertEqual("Basic dGVzdC11c2VyOnByaXZhdGUtcGFzc3dvcmQ=", self.config()["headers"]["authorization"])
        self.values["zap-headers"] = '{"authorization":"Bearer token"}'
        with self.assertRaises(ValueError):
            self.config()

    def test_invalid_headers_are_rejected(self):
        for headers in [{"Host": "evil.example"}, {"X-Test": "value\r\nAuthorization: secret"},
                        {"X-Test": 1}, {"X-Test": ""}, {"X-Test": "one", "x-test": "two"}]:
            with self.subTest(headers=headers), self.assertRaises(ValueError):
                self.values["zap-headers"] = json.dumps(headers)
                self.config()

    def test_subtree_and_exclusions_change_coverage(self):
        original = scan.scope_hash(self.root, "zap", self.config()["settings"], [])
        for key, value in [("zap-scan-mode", "full"), ("zap-exclude-urls", ".*/logout"),
                           ("zap-target-url", "https://staging.example.com/app"), ("zap-timeout", "900")]:
            self.values = {"zap-target-url": "https://staging.example.com/", key: value}
            self.assertNotEqual(original, scan.scope_hash(self.root, "zap", self.config()["settings"], []))
        self.values = {"zap-target-url": "https://staging.example.com/app"}
        self.assertIsNone(__import__("re").fullmatch(self.config()["scope"], "https://staging.example.com/application"))

    def test_report_validation_accepts_empty_alerts_but_rejects_partial_shapes(self):
        payload = report()
        self.assertTrue(zap.valid_report(payload, self.values["zap-target-url"]))
        payload["site"][0]["alerts"] = []
        self.assertTrue(zap.valid_report(payload))
        for invalid in [{}, {"@version": "2.17.0", "site": []}, {"@version": "2.17.0", "site": [{}]}]:
            self.assertFalse(zap.valid_report(invalid))
        for field, value in [("riskcode", "High"), ("confidence", "invalid"), ("instances", []), ("pluginid", "")]:
            payload = report()
            payload["site"][0]["alerts"][0][field] = value
            self.assertFalse(zap.valid_report(payload))
        payload = report("https://evil.example/")
        self.assertFalse(zap.valid_report(payload, self.values["zap-target-url"]))

    def test_counts_use_risk_not_confidence_and_stable_endpoint_identity(self):
        payload = report("https://staging.example.com/?q=one")
        payload["site"][0]["alerts"][0]["instances"].append({"uri": "https://staging.example.com/?q=two", "method": "GET", "param": ""})
        self.assertEqual((1, 0), zap.counts(payload, "high"))
        self.assertEqual((1, 1), zap.counts(payload, "medium"))
        payload["site"][0]["alerts"][0]["confidence"] = "0"
        self.assertEqual((0, 0), zap.counts(payload, "medium"))

    def test_report_urls_reject_credentials_and_malformed_authorities(self):
        for url in ["https://user:password@staging.example.com/", "https://[invalid/",
                    "https://staging.example.com:invalid/", "https://staging.example.com/space here"]:
            with self.subTest(url=url):
                self.assertFalse(zap.valid_report(report(url), self.values["zap-target-url"]))
        payload = report()
        payload["site"][0]["@name"] = "file:///etc/passwd"
        self.assertFalse(zap.valid_report(payload))

    def test_reports_redact_encoded_credentials_and_preserve_schema(self):
        secret = 'token/with spaces&quotes"'
        payload = report()
        alert = payload["site"][0]["alerts"][0]
        alert["instances"][0]["evidence"] = secret + " " + zap.html.escape(secret)
        alert["instances"][0]["uri"] += "?token=" + zap.urllib.parse.quote_plus(secret)
        redacted = zap.redact(payload, [secret])
        self.assertNotIn(secret, json.dumps(redacted))
        self.assertEqual("[REDACTED] [REDACTED]", redacted["site"][0]["alerts"][0]["instances"][0]["evidence"])
        self.assertTrue(zap.valid_report(redacted, self.values["zap-target-url"]))

    def test_active_scan_fragment_payloads_do_not_invalidate_report_urls(self):
        payload = report('https://staging.example.com/?q=ZAP#javascript:alert(1) /* \\ */')
        self.assertTrue(zap.valid_report(payload, self.values["zap-target-url"]))
        self.assertEqual((1, 0), zap.counts(payload))
        redacted = zap.redact(payload, [])
        self.assertEqual('https://staging.example.com/?q=ZAP', redacted["site"][0]["alerts"][0]["instances"][0]["uri"])

    def test_zap_gates_can_override_global_findings_policy(self):
        for policy, global_gate, expected in [("inherit", False, True), ("inherit", True, False),
                                              ("none", True, True), ("high", False, False), ("medium", False, False)]:
            summary = {"tools": {"zap": {"status": "completed", "fail_on": policy, "findings_in_fail_severities": 1}}}
            self.assertEqual(expected, scan.gate_result(summary, {"status": "skipped"}, global_gate))

    def fake_run(self, command, **kwargs):
        if "run" in command:
            self.assertEqual(600, kwargs["timeout"])
            self.assertNotIn("private-token", " ".join(command))
            payload = report(risk="3")
            payload["site"][0]["alerts"][0]["instances"][0]["evidence"] = "Bearer private-token"
            (self.reports.parent / "zap-work/raw-zap.json").write_text(json.dumps(payload))
        return subprocess.CompletedProcess(command, 0)

    def test_execution_redacts_reports_cleans_work_files_and_counts_findings(self):
        self.values["zap-headers"] = '{"Authorization":"Bearer private-token"}'
        with patch.object(zap, "preflight"), patch.object(zap.subprocess, "run", side_effect=self.fake_run) as command:
            state = zap.run(self.config(), self.reports, {"PATH": "/usr/bin"})
        self.assertEqual("completed", state["status"])
        self.assertEqual(1, state["findings_in_fail_severities"])
        self.assertNotIn("private-token", (self.reports / "zap.json").read_text())
        self.assertFalse((self.reports.parent / "zap-work").exists())
        self.assertEqual("rm", command.call_args_list[-1].args[0][1])

    def test_timeout_always_removes_container_and_never_claims_completion(self):
        with patch.object(zap, "preflight"), patch.object(zap.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0), subprocess.TimeoutExpired("docker", 600), subprocess.CompletedProcess([], 0)]) as command:
            state = zap.run(self.config(), self.reports, {})
        self.assertEqual("failed", state["status"])
        self.assertNotIn("report", state)
        self.assertEqual("rm", command.call_args_list[-1].args[0][1])
        self.assertFalse((self.reports.parent / "zap-work").exists())

    def test_cancellation_removes_container_and_private_plan(self):
        with patch.object(zap, "preflight"), patch.object(zap.subprocess, "run", side_effect=[
            subprocess.CompletedProcess([], 0), KeyboardInterrupt(), subprocess.CompletedProcess([], 0)]) as command:
            with self.assertRaises(KeyboardInterrupt):
                zap.run(self.config(), self.reports, {})
        self.assertEqual("rm", command.call_args_list[-1].args[0][1])
        self.assertFalse((self.reports.parent / "zap-work").exists())

    def test_cleanup_restores_signal_handler_even_when_work_removal_fails(self):
        previous_handler = zap.signal.getsignal(zap.signal.SIGTERM)
        with patch.object(zap, "preflight"), patch.object(zap.subprocess, "run", side_effect=self.fake_run), \
                patch.object(zap.shutil, "rmtree", side_effect=OSError("cleanup failed")), self.assertRaises(OSError):
            zap.run(self.config(), self.reports, {})
        self.assertEqual(previous_handler, zap.signal.getsignal(zap.signal.SIGTERM))

    def test_basic_credentials_keep_significant_whitespace(self):
        os.environ.update(SCAN_ZAP_TARGET_URL="https://staging.example.com/", SCAN_ZAP_AUTH_USERNAME=" user ", SCAN_ZAP_AUTH_PASSWORD=" password ")
        runner = scan.Scanner(self.root, self.reports, "general")
        with patch.object(zap, "run", return_value={"status": "failed"}) as run:
            runner.raw_scan("zap")
        self.assertEqual("Basic IHVzZXIgOiBwYXNzd29yZCA=", run.call_args.args[0]["headers"]["authorization"])

    def test_plan_warnings_and_partial_reports_fail_closed(self):
        def warning(command, **kwargs):
            self.fake_run(command, **kwargs)
            return subprocess.CompletedProcess(command, 2)
        with patch.object(zap, "preflight"), patch.object(zap.subprocess, "run", side_effect=warning):
            self.assertEqual("failed", zap.run(self.config(), self.reports, {})["status"])

    def test_preflight_does_not_forward_credentials_to_external_redirect(self):
        opener = MagicMock()
        opener.open.side_effect = urllib.error.HTTPError(self.values["zap-target-url"], 302, "redirect", {"Location": "https://evil.example/"}, None)
        with patch.object(zap.urllib.request, "build_opener", return_value=opener), self.assertRaises(ValueError):
            zap.preflight(self.config())
        self.assertEqual(1, opener.open.call_count)

    def test_blocked_preflight_does_not_start_a_scan(self):
        opener = MagicMock()
        opener.open.side_effect = urllib.error.HTTPError(self.values["zap-target-url"], 403, "blocked", {}, None)
        with patch.object(zap.urllib.request, "build_opener", return_value=opener), \
                patch.object(zap.subprocess, "run", return_value=subprocess.CompletedProcess([], 0)) as command:
            state = zap.run(self.config(), self.reports, {})
        self.assertEqual("failed", state["status"])
        self.assertEqual(1, command.call_count)
        self.assertEqual("rm", command.call_args.args[0][1])

    def test_failed_zap_keeps_other_scanner_reports_and_fails_the_final_gate(self):
        os.environ["SCAN_RUN_ZAP"] = "true"
        calls = []
        def fake_raw(instance, name):
            calls.append(name)
            if name == "zap":
                raise ValueError("invalid ZAP target")
            scan.save_json(instance.reports / f"{name}.json", {})
            return {"status": "completed", "report": f"{name}.json"}
        metadata = {"repository": "owner/repo", "commit_sha": "a" * 40, "ref": "main"}
        with patch.object(scan, "metadata", return_value=metadata), \
                patch.object(scan.Scanner, "raw_scan", autospec=True, side_effect=fake_raw), \
                patch.object(scan, "output") as output, patch("builtins.print"):
            self.assertEqual(0, scan.scan())
            reports = Path(output.call_args.args[1])
        try:
            summary = json.loads((reports / "summary.json").read_text())
            self.assertEqual(["gitleaks", "semgrep", "trivy", "zap"], calls)
            self.assertTrue(all((reports / f"{name}.json").is_file() for name in calls[:-1]))
            self.assertEqual("failed", summary["tools"]["zap"]["status"])
            self.assertFalse(scan.gate_result(summary, {"status": "skipped"}, False))
        finally:
            zap.shutil.rmtree(reports.parent)

    def test_instance_metadata_and_multipart_are_preserved(self):
        os.environ["SCAN_SCAN_INSTANCE"] = "zap-baseline"
        with patch.object(scan.subprocess, "run", return_value=MagicMock(stdout="a" * 40)):
            metadata = scan.metadata(self.root)
        self.assertEqual("zap-baseline", metadata["scan_instance"])
        scan.save_json(self.reports / "summary.json", metadata)
        body, _ = scan.multipart(metadata, self.reports, "")
        self.assertIn(b'name="scan_instance"\r\n\r\nzap-baseline', body)
        os.environ["SCAN_SCAN_INSTANCE"] = "invalid\r\ninstance"
        with patch.object(scan.subprocess, "run", return_value=MagicMock(stdout="a" * 40)), self.assertRaises(ValueError):
            scan.metadata(self.root)


if __name__ == "__main__":
    unittest.main()
