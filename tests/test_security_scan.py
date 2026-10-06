import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import security_scan as scan
import install_tools


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name) / "repository"
        self.root.mkdir()
        self.reports = Path(self.temporary.name) / "reports"
        self.reports.mkdir()
        self.environment = patch.dict(os.environ, {"GITHUB_WORKSPACE": str(self.root)}, clear=True)
        self.environment.start()

    def tearDown(self):
        self.environment.stop()
        self.temporary.cleanup()

    def write(self, name, value):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value)
        return path

    def test_profiles_are_detected_from_root_manifest(self):
        for package, expected in (("laravel/framework", "laravel"), ("getkirby/cms", "kirby"), ("other/package", "php")):
            self.write("composer.json", json.dumps({"require": {package: "*"}}))
            self.assertEqual(expected, scan.profile_for(self.root, "auto"))
        (self.root / "composer.json").unlink()
        self.assertEqual("general", scan.profile_for(self.root, "auto"))
        with self.assertRaises(ValueError):
            scan.profile_for(self.root, "unknown")

    def test_gitleaks_precedence_and_default(self):
        self.assertIsNone(scan.selected_gitleaks_config(self.root))
        default = self.write(".gitleaks.toml", "title='root'")
        self.assertEqual(default, scan.selected_gitleaks_config(self.root))
        github = self.write(".github/.gitleaks.toml", "title='github'")
        self.assertEqual(github, scan.selected_gitleaks_config(self.root))
        custom = self.write("config with spaces.toml", "title='explicit'")
        os.environ["SCAN_GITLEAKS_CONFIG"] = custom.name
        self.assertEqual(custom, scan.selected_gitleaks_config(self.root))
        os.environ["SCAN_GITLEAKS_CONFIG"] = "missing.toml"
        with self.assertRaises(FileNotFoundError):
            scan.selected_gitleaks_config(self.root)

    def test_semgrep_explicit_replaces_auto_and_defaults(self):
        auto = self.write(".semgrep.yml", "rules: []")
        self.assertEqual([str(auto)], scan.selected_semgrep_configs(self.root, "laravel"))
        custom = self.write("config with spaces.yml", "rules: []")
        os.environ.update(SCAN_SEMGREP_CONFIG="config with spaces.yml,p/ci", SCAN_SEMGREP_EXTRA_CONFIGS="p/ci\np/php")
        self.assertEqual([str(custom), "p/ci", "p/php"], scan.selected_semgrep_configs(self.root, "laravel"))

    def test_paths_and_config_symlinks_cannot_escape_repository(self):
        outside = Path(self.temporary.name) / "outside.yml"
        outside.write_text("rules: []")
        (self.root / "symlink.yml").symlink_to(outside)
        for value in ("../outside.yml", str(outside), "symlink.yml", "--config=evil", "https://example.com/rules"):
            with self.subTest(value=value), self.assertRaises((ValueError, OSError)):
                scan.semgrep_config(self.root, value)
        directory = self.root / "configs"
        directory.mkdir()
        (directory / "symlink.yml").symlink_to(outside)
        with self.assertRaises(ValueError):
            scan.semgrep_config(self.root, "configs")

    def test_custom_configs_are_argv_values_and_are_not_executed_by_shell(self):
        config = self.write("$(touch PWNED) config.yml", "rules: []")
        os.environ["SCAN_SEMGREP_CONFIG"] = config.name
        runner = scan.Scanner(self.root, self.reports, "general")
        def fake_command(command, root, environment, report=None):
            self.assertIn(str(config), command)
            self.assertIn("--strict", command)
            scan.save_json(self.reports / "semgrep.json", {"results": [], "errors": []})
            return 0, ""
        with patch.object(runner, "executable", return_value="semgrep"), patch.object(scan, "run_command", side_effect=fake_command):
            self.assertEqual("completed", runner.raw_scan("semgrep")["status"])
        self.assertFalse((self.root / "PWNED").exists())

    def test_subprocess_environment_has_no_tokens_or_user_credentials(self):
        os.environ.update(SCAN_TOKEN="secret", GITHUB_TOKEN="github-secret", AWS_SECRET_ACCESS_KEY="aws-secret", COMPOSER_AUTH="composer-secret", SEMGREP_APP_TOKEN="semgrep-secret", PATH="/usr/bin")
        environment = scan.clean_environment(Path(self.temporary.name))
        self.assertFalse(set(environment) & {"SCAN_TOKEN", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "COMPOSER_AUTH", "SEMGREP_APP_TOKEN"})
        self.assertNotIn("secret", " ".join(environment.values()))
        self.assertEqual("/usr/bin", environment["PATH"])

    def test_scope_tracks_config_and_directory_but_not_dependency_contents(self):
        config = self.write(".semgrep.yml", "rules: []")
        self.write("composer.lock", "before")
        original = scan.scope_hash(self.root, "semgrep", {}, [str(config)])
        self.write("composer.lock", "after")
        self.assertEqual(original, scan.scope_hash(self.root, "semgrep", {}, [str(config)]))
        config.write_text("rules: [changed]")
        self.assertNotEqual(original, scan.scope_hash(self.root, "semgrep", {}, [str(config)]))
        nested = self.root / "nested"
        nested.mkdir()
        self.assertNotEqual(scan.scope_hash(self.root, "trivy", {}, []), scan.scope_hash(nested, "trivy", {}, []))

    def test_optional_audits_detect_only_root_lockfiles(self):
        self.write("nested/composer.lock", "{}")
        self.assertFalse(scan.enabled(self.root, "composer_audit"))
        self.assertFalse(scan.enabled(self.root, "phpstan"))
        os.environ["SCAN_COMPOSER_AUDIT_PATHS"] = "nested"
        self.assertTrue(scan.enabled(self.root, "composer_audit"))
        self.write("package-lock.json", "{}")
        self.assertTrue(scan.enabled(self.root, "npm_audit"))
        os.environ["SCAN_RUN_NPM_AUDIT"] = "false"
        self.assertFalse(scan.enabled(self.root, "npm_audit"))

    def test_scanner_failure_does_not_prevent_others(self):
        def fake_raw(instance, name):
            if name == "gitleaks":
                raise ValueError("invalid config")
            return {"status": "completed", "findings": 2, "findings_in_fail_severities": 2}
        meta = {"repository": "owner/repo", "commit_sha": "a" * 40, "ref": "main"}
        with patch.object(scan, "metadata", return_value=meta), patch.object(scan.Scanner, "raw_scan", autospec=True, side_effect=fake_raw), patch.object(scan, "output") as outputs, patch("builtins.print"):
            self.assertEqual(0, scan.scan())
            report_directory = Path(outputs.call_args.args[1])
        summary = json.loads((report_directory / "summary.json").read_text())
        self.assertEqual("failed", summary["tools"]["gitleaks"]["status"])
        self.assertEqual("completed", summary["tools"]["semgrep"]["status"])
        self.assertEqual("completed", summary["tools"]["trivy"]["status"])
        shutil_directory = report_directory.parent
        import shutil
        shutil.rmtree(shutil_directory)

    def test_audit_keeps_valid_projects_when_another_fails(self):
        lockfile = json.dumps({"packages": [{"name": "vendor/example", "version": "1.0.0"}], "packages-dev": []})
        self.write("good/composer.lock", lockfile)
        self.write("bad/composer.lock", lockfile)
        os.environ["SCAN_COMPOSER_AUDIT_PATHS"] = "good,bad"
        runner = scan.Scanner(self.root, self.reports, "general")
        def fake_command(command, root, environment, report=None):
            self.assertIn("--no-plugins", command)
            self.assertIn("--no-scripts", command)
            payload = {"advisories": {"a": [{"title": "vulnerability"}]}} if root.name == "good" else {"error": "network failure"}
            scan.save_json(report, payload)
            return 1, ""
        with patch.object(runner, "executable", return_value="composer"), patch.object(scan, "run_command", side_effect=fake_command):
            state = runner.audit("composer_audit")
        self.assertEqual("failed", state["status"])
        self.assertEqual(1, state["findings"])
        projects = json.loads((self.reports / "composer_audit.json").read_text())["projects"]
        self.assertEqual(["completed", "failed"], [item["status"] for item in projects])

    def test_empty_composer_lock_is_explicitly_skipped_without_fake_vendor_report(self):
        self.write("composer.lock", '{"packages":[],"packages-dev":[]}')
        runner = scan.Scanner(self.root, self.reports, "general")
        with patch.object(runner, "executable", return_value="composer"), patch.object(scan, "run_command") as command:
            state = runner.audit("composer_audit")
            command.assert_not_called()
        self.assertEqual("skipped", state["status"])
        self.assertNotIn("report", state)
        project = json.loads((self.reports / "composer_audit.json").read_text())["projects"][0]
        self.assertEqual("skipped", project["status"])
        self.assertNotIn("result", project)

    def test_partial_composer_project_coverage_fails_closed(self):
        self.write("empty/composer.lock", '{"packages":[],"packages-dev":[]}')
        self.write("full/composer.lock", '{"packages":[{"name":"vendor/pkg","version":"1.0.0"}],"packages-dev":[]}')
        os.environ["SCAN_COMPOSER_AUDIT_PATHS"] = "empty,full"
        runner = scan.Scanner(self.root, self.reports, "general")
        def fake_command(command, root, environment, report):
            scan.save_json(report, {"advisories": []})
            return 0, ""
        with patch.object(runner, "executable", return_value="composer"), patch.object(scan, "run_command", side_effect=fake_command):
            self.assertEqual("failed", runner.audit("composer_audit")["status"])

    def test_semgrep_scope_includes_parent_and_nested_gitignores(self):
        parent = self.write(".gitignore", "parent-ignore")
        nested = self.write("app/nested/.gitignore", "nested-ignore")
        root = self.root / "app"
        original = scan.scope_hash(root, "semgrep", {}, scan.semgrep_ignore_files(root))
        parent.write_text("changed-parent")
        self.assertNotEqual(original, scan.scope_hash(root, "semgrep", {}, scan.semgrep_ignore_files(root)))
        second = scan.scope_hash(root, "semgrep", {}, scan.semgrep_ignore_files(root))
        nested.write_text("changed-nested")
        self.assertNotEqual(second, scan.scope_hash(root, "semgrep", {}, scan.semgrep_ignore_files(root)))
        excluded = self.write(".git/info/exclude", "git-local-ignore")
        self.assertIn(str(excluded), scan.semgrep_ignore_files(root))

    def test_semgrep_included_ignore_content_changes_scope(self):
        self.write(".semgrepignore", ":include config/ignore\n")
        self.write("config/ignore", ":include nested.ignore\n")
        included = self.write("config/nested.ignore", "tests/generated\n")
        files = scan.semgrep_ignore_files(self.root)
        self.assertIn(str(included), files)
        original = scan.scope_hash(self.root, "semgrep", {}, files)
        included.write_text("src/changed\n")
        self.assertNotEqual(original, scan.scope_hash(self.root, "semgrep", {}, scan.semgrep_ignore_files(self.root)))

    def test_semgrep_ignore_includes_reject_external_paths_and_cycles(self):
        ignore_file = self.write(".semgrepignore", ":include ../outside.ignore\n")
        (self.root.parent / "outside.ignore").write_text("src/\n")
        with self.assertRaises(ValueError):
            scan.semgrep_ignore_files(self.root)
        ignore_file.write_text(":include nested.ignore\n")
        self.write("nested.ignore", ":include .semgrepignore\n")
        with self.assertRaises(ValueError):
            scan.semgrep_ignore_files(self.root)

    def test_gitleaks_git_rejects_shallow_before_installation(self):
        os.environ["SCAN_GITLEAKS_MODE"] = "git"
        runner = scan.Scanner(self.root, self.reports, "general")
        with patch.object(subprocess, "run", return_value=Mock(returncode=0, stdout="true\n")) as command, patch.object(runner, "executable") as executable:
            with self.assertRaisesRegex(ValueError, "fetch-depth"):
                runner.raw_scan("gitleaks")
            executable.assert_not_called()
            self.assertEqual(["git", "rev-parse", "--is-shallow-repository"], command.call_args.args[0])
        with patch.object(subprocess, "run", return_value=Mock(returncode=0, stdout="false\n")):
            scan.assert_full_git_history(self.root, runner.environment)

    def test_gitleaks_extended_config_content_changes_scope(self):
        config = self.write(".gitleaks.toml", '[extend]\npath = "configs/base.toml"\n')
        base = self.write("configs/base.toml", "title='base'")
        files = scan.gitleaks_config_files(self.root, config)
        self.assertEqual([str(config), str(base)], files)
        original = scan.scope_hash(self.root, "gitleaks", {}, files)
        base.write_text("title='changed'")
        self.assertNotEqual(original, scan.scope_hash(self.root, "gitleaks", {}, files))
        base.write_text('[extend]\npath = ".gitleaks.toml"\n')
        with self.assertRaises(ValueError):
            scan.gitleaks_config_files(self.root, config)

    def test_phpstan_static_includes_and_baselines_change_scope(self):
        config = self.write("phpstan.neon", "includes:\n    - config/base.neon\nparameters:\n    level: 5\n")
        base = self.write("config/base.neon", "includes: [../phpstan-baseline.neon]\n")
        baseline = self.write("phpstan-baseline.neon", "parameters:\n    ignoreErrors: []\n")
        files = scan.phpstan_config_files(self.root, config)
        self.assertEqual({str(config), str(base), str(baseline)}, set(files))
        original = scan.scope_hash(self.root, "phpstan", {}, files)
        baseline.write_text("parameters:\n    ignoreErrors: [changed]\n")
        self.assertNotEqual(original, scan.scope_hash(self.root, "phpstan", {}, files))
        config.write_text("includes:\n    - dynamic.php\n")
        self.write("dynamic.php", "<?php return [];\n")
        with self.assertRaises(ValueError):
            scan.phpstan_config_files(self.root, config)

    def test_actual_checkout_sha_is_used_instead_of_event_sha(self):
        os.environ.update(GITHUB_SHA="event-sha", GITHUB_REPOSITORY="owner/repo", GITHUB_REPOSITORY_ID="123")
        event = Path(self.temporary.name) / "event.json"
        event.write_text(json.dumps({"repository": {"default_branch": "trunk"}, "pull_request": {"number": 42}}))
        os.environ["GITHUB_EVENT_PATH"] = str(event)
        with patch.object(subprocess, "run", return_value=Mock(stdout="actual-checkout-sha\n")):
            metadata = scan.metadata(self.root)
        self.assertEqual("actual-checkout-sha", metadata["commit_sha"])
        self.assertEqual("trunk", metadata["default_ref"])
        self.assertEqual("42", metadata["pull_request_number"])


class ReportTests(unittest.TestCase):
    def test_findings_exit_codes_are_completed_not_runtime_errors(self):
        fixtures = [
            ("gitleaks", [{"RuleID": "test", "Secret": "REDACTED"}], 10),
            ("semgrep", {"results": [{"check_id": "test"}], "errors": []}, 0),
            ("trivy", {"SchemaVersion": 2, "Results": []}, 0),
            ("composer_audit", {"advisories": {"pkg": [{"title": "test"}]}}, 1),
            ("npm_audit", {"vulnerabilities": {"pkg": {}}, "metadata": {"vulnerabilities": {"total": 1}}}, 1),
            ("phpstan", {"files": {"test.php": {"messages": [{"message": "test"}]}}, "totals": {"file_errors": 1}, "errors": []}, 1),
        ]
        for scanner, payload, code in fixtures:
            with self.subTest(scanner=scanner):
                self.assertTrue(scan.valid_report(scanner, payload, code))
                self.assertFalse(scan.valid_report(scanner, payload, 99))

    def test_incomplete_scanner_reports_fail_closed(self):
        fixtures = [
            ("gitleaks", {}, 0),
            ("semgrep", {"results": [], "errors": [{"message": "bad config"}]}, 0),
            ("trivy", {"error": "database download failed"}, 0),
            ("composer_audit", {"error": "registry failure"}, 1),
            ("npm_audit", {"error": "ENOTFOUND"}, 1),
            ("phpstan", {"files": {}, "totals": {}, "errors": ["Internal error"]}, 1),
        ]
        for scanner, payload, code in fixtures:
            with self.subTest(scanner=scanner):
                self.assertFalse(scan.valid_report(scanner, payload, code))
        self.assertFalse(scan.valid_report("composer_audit", {"advisories": []}, 0, "Warning: incomplete audit"))
        root_hint = "Composer could not detect the root package (vendor/project) version, defaulting to '1.0.0'. See https://getcomposer.org/root-version"
        self.assertTrue(scan.valid_report("composer_audit", {"advisories": []}, 0, root_hint))
        self.assertFalse(scan.valid_report("composer_audit", {"advisories": []}, 0, "Could not reach registry; audit incomplete"))

    def test_trivy_gate_only_counts_high_and_critical(self):
        payload = {"Results": [{"Vulnerabilities": [{"Severity": "LOW"}, {"Severity": "HIGH"}], "Misconfigurations": [{"Severity": "CRITICAL"}]}]}
        self.assertEqual((3, 2), scan.counts("trivy", payload))

    def test_default_gate_reports_findings_without_blocking(self):
        summary = {"tools": {"semgrep": {"status": "completed", "findings_in_fail_severities": 2}}}
        self.assertTrue(scan.gate_result(summary, {"status": "skipped"}, False))
        self.assertFalse(scan.gate_result(summary, {"status": "completed"}, True))
        self.assertFalse(scan.gate_result(summary, {"status": "failed"}, False))
        summary["tools"]["semgrep"]["status"] = "failed"
        self.assertFalse(scan.gate_result(summary, {"status": "completed"}, False))


class UploadTests(unittest.TestCase):
    def test_endpoint_requires_tls_and_rejects_credential_urls(self):
        for endpoint in ("http://example.com/ingest", "https://user:password@example.com/ingest", "https://example.com/ingest?token=secret", "https://example.com/ingest#fragment"):
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                scan.validate_endpoint(endpoint)
        scan.validate_endpoint("https://example.com/ingest")
        scan.validate_endpoint("http://127.0.0.1:8080/ingest")

    def test_successful_upload_returns_batch_and_retries_temporary_errors(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b'{"scan_batch_id":42}'
        opener = Mock()
        opener.open.side_effect = [urllib.error.HTTPError("https://example.com", 503, "temporary", {}, io.BytesIO()), response]
        with patch.object(scan.urllib.request, "build_opener", return_value=opener), patch.object(scan.time, "sleep"):
            self.assertEqual("42", scan.send_upload("https://example.com", "TOKEN", b"body", "multipart/form-data"))
        self.assertEqual(2, opener.open.call_count)
        request = opener.open.call_args.args[0]
        self.assertEqual("Bearer TOKEN", request.get_header("Authorization"))

    def test_authentication_failure_and_redirect_are_not_retried(self):
        for status in (401, 403, 302, 422):
            opener = Mock()
            opener.open.side_effect = urllib.error.HTTPError("https://example.com", status, "error", {}, io.BytesIO(b"secret response"))
            with self.subTest(status=status), patch.object(scan.urllib.request, "build_opener", return_value=opener), patch.object(scan.time, "sleep"), self.assertRaises(ValueError) as error:
                scan.send_upload("https://example.com", "SECRET_TOKEN", b"body", "multipart/form-data")
            self.assertNotIn("SECRET_TOKEN", str(error.exception))
            self.assertNotIn("secret response", str(error.exception))
            self.assertEqual(1, opener.open.call_count)

    def test_multipart_only_includes_real_scanner_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = Path(directory)
            summary = {"repository": "owner/repo", "repository_id": "123", "tools": {"gitleaks": {"status": "failed"}, "semgrep": {"status": "completed", "report": "../../secret"}}}
            scan.save_json(reports / "summary.json", summary)
            scan.save_json(reports / "semgrep.json", {"results": []})
            body, content_type = scan.multipart(summary, reports, "")
            self.assertIn(b'name="repository_id"', body)
            self.assertIn(b'name="semgrep"', body)
            self.assertNotIn(b'name="gitleaks"', body)
            self.assertNotIn(b'name="scan_target_id"', body)
            self.assertTrue(content_type.startswith("multipart/form-data; boundary="))

    def test_missing_token_runs_scan_only_without_network_upload(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = Path(directory)
            scan.save_json(reports / "summary.json", {"tools": {"semgrep": {"status": "completed"}}})
            with patch.dict(os.environ, {"SCAN_REPORTS_PATH": directory}, clear=True), patch.object(scan, "send_upload") as sender, patch("builtins.print"):
                self.assertEqual(0, scan.upload())
                sender.assert_not_called()
            self.assertEqual("skipped", json.loads((reports / "upload.json").read_text())["status"])

    def test_upload_failure_is_captured_for_final_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            reports = Path(directory)
            scan.save_json(reports / "summary.json", {"tools": {"semgrep": {"status": "failed"}}})
            with patch.dict(os.environ, {"SCAN_REPORTS_PATH": directory, "SCAN_TOKEN": "SECRET"}, clear=True), patch.object(scan, "send_upload", side_effect=ValueError("SECRET")), patch("builtins.print"):
                self.assertEqual(0, scan.upload())
            state = json.loads((reports / "upload.json").read_text())
            self.assertEqual("failed", state["status"])
            self.assertNotIn("SECRET", json.dumps(state))


class InstallTests(unittest.TestCase):
    def test_binary_checksum_is_verified_before_extraction(self):
        response = Mock()
        response.__enter__ = Mock(return_value=response)
        response.__exit__ = Mock(return_value=False)
        response.read.return_value = b"tampered archive"
        with tempfile.TemporaryDirectory() as directory, patch.object(install_tools.platform, "system", return_value="Linux"), patch.object(install_tools.platform, "machine", return_value="x86_64"), patch.object(install_tools.urllib.request, "urlopen", return_value=response), self.assertRaises(ValueError):
            install_tools.install("gitleaks", Path(directory), {})


class HttpIntegrationTests(unittest.TestCase):
    def serve(self, handler):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        return f"http://127.0.0.1:{server.server_port}"

    def test_real_multipart_upload_retries_identical_payload(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append((self.path, self.headers.get("Authorization"), self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(503 if len(received) == 1 else 202)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"scan_batch_id":123}')

            def log_message(self, *_):
                pass

        endpoint = self.serve(Handler)
        with tempfile.TemporaryDirectory() as directory:
            reports = Path(directory)
            summary = {"repository": "owner/repo", "repository_id": "123", "default_ref": "main", "commit_sha": "a" * 40, "run_id": "456", "run_attempt": "1", "tools": {"semgrep": {"status": "completed", "report": "semgrep.json"}}}
            scan.save_json(reports / "summary.json", summary)
            scan.save_json(reports / "semgrep.json", {"results": []})
            body, content_type = scan.multipart(summary, reports, "")
            with patch.object(scan.time, "sleep"):
                self.assertEqual("123", scan.send_upload(endpoint + "/ingest", "runtime-test-token", body, content_type))
        self.assertEqual(2, len(received))
        self.assertEqual(received[0], received[1])
        self.assertEqual("Bearer runtime-test-token", received[0][1])
        self.assertIn(b'name="summary"', received[0][2])
        self.assertIn(b'name="semgrep"', received[0][2])

    def test_real_redirect_does_not_forward_authorization(self):
        received = []
        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                received.append(self.path)
                self.send_response(302)
                self.send_header("Location", "/unexpected")
                self.end_headers()

            def do_GET(self):
                received.append(self.path)
                self.send_response(200)
                self.end_headers()

            def log_message(self, *_):
                pass

        endpoint = self.serve(Handler)
        with self.assertRaises(ValueError):
            scan.send_upload(endpoint + "/ingest", "runtime-test-token", b"body", "multipart/form-data")
        self.assertEqual(["/ingest"], received)


if __name__ == "__main__":
    unittest.main()
