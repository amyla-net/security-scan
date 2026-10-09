# Amyla Security Scan

A standalone GitHub Action that scans your repository and optionally uploads reports to [Amyla Services](https://services.amyla.net). Amyla resolves the repository and creates its target on the first upload. No target ID or GitHub App installation is needed. Amyla-managed execution is **Coming soon**.

## Quick-setup

1. Create an Amyla team upload token with `scanner:ingest` and `scanner:targets:create` permissions and save it as the GitHub secret `AMYLA_SCANNER_TOKEN`.
2. Add `.github/workflows/security.yml`:

```yaml
name: Security scan
on: [push, pull_request]
permissions:
  contents: read
jobs:
  security:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false
      - uses: amyla-net/security-scan@ACTION_RELEASE_COMMIT_SHA
        with:
          token: ${{ secrets.AMYLA_SCANNER_TOKEN }}
```

Replace `ACTION_RELEASE_COMMIT_SHA` with the full commit SHA of the release you want to use.

By default, Gitleaks scans secrets, Semgrep scans source code, and Trivy scans vulnerabilities and misconfigurations. Composer/npm audits run when supported lockfiles exist at the scan root; PHPStan is disabled. The profile is inferred from root `composer.json` (`laravel`, `kirby`, `php`, or `general`). Findings are reported without blocking the job; technical errors fail it.

Without a token, the action runs in **scan-only mode**, including fork pull requests without secrets. Do not execute untrusted pull-request code with secrets using `pull_request_target`.

## Full-config-example

Replace the action step above with this example to see **all 21 inputs**. It assumes a Laravel/Node monorepo with the listed configuration files and audit directories; adapt those paths to your repository. Empty optional values select automatic discovery or defaults.

Ubuntu x64 runners with Python 3.11+ are supported. Set up your required PHP/Composer/Node versions before the action. Lockfile audits do not require dependency installation; enabling PHPStan requires installed project dependencies and `vendor/bin/phpstan` at the scan root.

```yaml
- name: Scan and report
  id: security
  uses: amyla-net/security-scan@ACTION_RELEASE_COMMIT_SHA
  with:
    token: ${{ secrets.AMYLA_SCANNER_TOKEN }} # Empty: scan only
    ingest-url: https://services.amyla.net/api/scanner/ingests/github-actions
    scan-target-id: '' # Optional legacy target ID; normally leave empty

    working-directory: '.' # Relative to the checkout; default: .
    profile: laravel # auto (default), laravel, kirby, php, general
    fail-on-findings: 'true' # Default: false; Trivy blocks on HIGH/CRITICAL only

    # Each scanner accepts true (on), false (off), or auto.
    run-gitleaks: 'auto' # Default: on
    run-semgrep: 'auto' # Default: on
    run-trivy: 'auto' # Default: on
    run-composer-audit: 'auto' # On for explicit audit paths or root composer.lock
    run-npm-audit: 'auto' # On for explicit paths or root npm lockfiles
    run-phpstan: 'true' # Default: false; auto also leaves it disabled

    gitleaks-config: .github/gitleaks.toml # Default: automatic discovery
    gitleaks-mode: directory # Default; git requires checkout fetch-depth: 0

    semgrep-config: .github/semgrep.yml # Replaces profile rules; default: auto
    semgrep-extra-configs: | # Adds rules; default: empty
      p/php
      p/javascript
    semgrep-extra-excludes: | # Adds exclusion patterns; default: empty
      tests/generated
      public/build

    composer-audit-paths: | # Default: root only
      .
      packages/library
    npm-audit-paths: | # Default: root only
      .
      apps/frontend

    phpstan-config: phpstan.neon # Default: project config discovery
    trivy-extra-skip-dirs: | # Adds directory exclusion patterns; default: empty
      tests/generated
      public/build
```

## Configuration notes

- **Paths and lists:** Configuration files and audit directories must exist and stay inside `working-directory`, including symlinks. Lists accept commas or newlines. The action does not overwrite project configuration or `.env`.
- **Gitleaks:** Auto discovery checks `.github/.gitleaks.toml`, then `.gitleaks.toml`, then built-in rules. Custom configs replace built-in rules unless `[extend]` sets `useDefault = true`. `.gitleaksignore` is respected; reports redact secrets. Git mode requires a full checkout (`fetch-depth: 0`) and scans repository-wide history, even with a nested `working-directory`.
- **Semgrep:** Auto discovery checks `.semgrep.yml`, then `.semgrep.yaml`, then profile rules. Local files/directories and `p/...` registry rules are supported. Selected configs replace profile rules; extra configs add rules. `.semgrepignore` and Git ignore files, including local includes, affect coverage.
- **Trivy and PHPStan:** Trivy reads `trivy.yaml` and its configured local `ignorefile`, or `.trivyignore` by default; an empty `ignorefile` disables ignores. PHPStan supports static NEON configs, includes, and baselines; dynamic PHP/parameter-based includes fail explicitly.
- **Monorepos:** Keep all audit paths in one action invocation per repository/run attempt. Each selected directory needs `composer.lock`, `package-lock.json`, or `npm-shrinkwrap.json` as appropriate. Matrix invocations are not combined into one Amyla batch.

## Results and outputs

Scanners run independently, and available reports are uploaded before the final gate. Findings block only with `fail-on-findings: 'true'`; technical scanner errors and upload failures always fail the job. Uploads require HTTPS, reject redirects, and retry transient connection failures, HTTP 429, and selected 5xx responses.

Each completed scanner supplies a scope hash covering its directory, configuration, ignores, and audit settings. Dependency declarations and lockfile contents do not change this hash. Failed scans and changed scopes preserve earlier findings. npm coverage includes ancestor `.npmrc` and workspace settings up to the checkout root; external config symlinks and workspaces are rejected.

Scanner processes use an isolated environment without the upload token or inherited cloud/registry credentials. Private dependency registries are not configured automatically. Scanner versions are pinned and binary downloads are checksum-verified; details are in [install_tools.py](scripts/install_tools.py).

| Output | Description |
| --- | --- |
| `scan-batch-id` | Amyla batch ID; empty when no upload completed. |
| `reports-path` | Temporary directory containing `summary.json` and available raw reports. |
| `upload-status` | `completed`, `failed`, or `skipped`. |

Read these via `steps.security.outputs` when the action step has `id: security`. Artifact publishing and retention are controlled by your workflow; reports can contain source fragments and repository paths.

## Development and licensing

Install `PyYAML==6.0.3` in your development environment and run `python3 -m unittest discover -s tests -v`. CI also runs Actionlint, ShellCheck, Zizmor, and fixture smoke tests without an Amyla ingest token.

The action is [MIT licensed](LICENSE). Scanner tools and registry rules retain their upstream licenses: [Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/LICENSE), [Semgrep](https://github.com/semgrep/semgrep/blob/develop/LICENSE), and [Trivy](https://github.com/aquasecurity/trivy/blob/main/LICENSE).
