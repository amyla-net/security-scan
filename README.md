# Amyla Security Scan

A standalone GitHub Action that scans your repository and optionally uploads reports to [Amyla Services](https://services.amyla.net). All action code, configuration, installation, and tests live in this repository.

Add one team upload token as a GitHub secret and include the action in your workflow. Amyla resolves your repository automatically and creates its target on the first upload. No target ID or GitHub App installation is required.

## Quick start

1. In Amyla, create a team upload token with `scanner:ingest` and `scanner:targets:create` permissions.
2. Save it as the repository or organization secret `AMYLA_SCANNER_TOKEN`.
3. Add `.github/workflows/security.yml`:

```yaml
name: Security scan
on:
  push:
  pull_request:
  schedule:
    - cron: '23 4 * * *'
  workflow_dispatch:
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
      - name: Scan and report
        id: security
        uses: amyla-net/security-scan@ACTION_RELEASE_COMMIT_SHA
        with:
          token: ${{ secrets.AMYLA_SCANNER_TOKEN }}
```

**Replace `ACTION_RELEASE_COMMIT_SHA` with the full commit SHA of the published release.** This repository has not published its first release yet; the placeholder intentionally does not point to a mutable branch. The planned first release is `v1.0.0`.

Ubuntu x64 GitHub-hosted runners are supported. Python 3.11+ is included. Composer and npm audits use the executables on the runner; set up your project's required PHP/Composer/Node versions before this action if needed. Dependency installation is unnecessary for lockfile audits. PHPStan requires an existing project installation.

Without `token`, the action runs in **scan-only mode**. This also covers fork pull requests, where GitHub does not expose repository secrets. Do not use `pull_request_target` to execute untrusted pull-request code with secrets.

## Custom configuration

Paths are relative to `working-directory`, must exist, and must stay inside that directory, including symlinks. Files are read as supplied; the action does not overwrite configuration or `.env`.

```yaml
- uses: amyla-net/security-scan@ACTION_RELEASE_COMMIT_SHA
  with:
    token: ${{ secrets.AMYLA_SCANNER_TOKEN }}
    gitleaks-config: .github/gitleaks.toml
    semgrep-config: |
      .github/semgrep.yml
      p/php
    semgrep-extra-excludes: tests/generated
```

Gitleaks uses the explicit `gitleaks-config`, otherwise `.github/.gitleaks.toml`, otherwise `.gitleaks.toml`, otherwise its built-in rules. A custom configuration replaces built-in rules unless it includes `[extend]` with `useDefault = true`. Local `[extend].path` files are also validated and included in the scope hash; these paths are relative to the invocation directory. The existing `.gitleaksignore` is respected. Missing or invalid explicit configs fail that scanner rather than silently falling back. Reports use full secret redaction.

Semgrep uses explicit `semgrep-config` values, otherwise `.semgrep.yml`, otherwise `.semgrep.yaml`, otherwise the detected profile's rule sets. **Explicit and auto-detected local configs replace the profile rules.** `semgrep-extra-configs` adds rules to whichever selection was made. Local files/directories and `p/...` Semgrep registry rule sets are supported; lists accept commas or newlines, and spaces in file paths are preserved. `.semgrepignore` is respected. Registry rule sets retain their upstream licenses and may evolve independently of the pinned CLI version.

By default, Gitleaks scans the **current checkout contents**, not Git history. To scan all available Git history, use `gitleaks-mode: git` and `fetch-depth: 0` in checkout. Git mode rejects shallow checkouts as a technical failure, so incomplete history cannot resolve earlier findings. With `git` mode, Git history is repository-wide even when `working-directory` selects a subdirectory.

## Inputs and outputs

| Input | Default | Behavior |
| --- | --- | --- |
| `token` | empty | Optional team upload token; empty skips upload. |
| `ingest-url` | `https://services.amyla.net/api/scanner/ingests/github-actions` | HTTPS ingest endpoint; redirects are rejected. |
| `scan-target-id` | empty | Optional legacy target identifier. |
| `working-directory` | `.` | Relative repository directory to scan. |
| `profile` | `auto` | `laravel`, `kirby`, `php`, or `general`; inferred from root `composer.json`. |
| `fail-on-findings` | `false` | Block on findings after upload; Trivy gates HIGH/CRITICAL only. |
| `run-gitleaks` / `run-semgrep` / `run-trivy` | `auto` | Default enabled; each accepts `auto`, `true`, `false`. |
| `run-composer-audit` / `run-npm-audit` | `auto` | Detect supported lockfiles in the selected root; accepts `auto`, `true`, `false`. |
| `run-phpstan` | `false` | Opt-in `true`; uses existing `vendor/bin/phpstan`. `auto` also leaves it disabled. |
| `gitleaks-config` | empty | Explicit local Gitleaks config path. |
| `gitleaks-mode` | `directory` | `directory` for current contents; `git` for checked-out history. |
| `semgrep-config` | empty | Authoritative local configs or `p/...` registry rule sets. |
| `semgrep-extra-configs` | empty | Additional Semgrep configs or registry rule sets. |
| `semgrep-extra-excludes` | empty | Additional exclusion patterns. |
| `composer-audit-paths` / `npm-audit-paths` | empty | Comma/newline directory lists; empty means root only. |
| `phpstan-config` | empty | Explicit local config; otherwise normal PHPStan project discovery. |
| `trivy-extra-skip-dirs` | empty | Additional directory exclusion patterns. |

| Output | Description |
| --- | --- |
| `scan-batch-id` | Uploaded Amyla batch ID, empty when upload did not complete. |
| `reports-path` | Absolute temporary directory with `summary.json` and available raw reports. |
| `upload-status` | `completed`, `failed`, or `skipped`. |

Reports remain available for later workflow steps; artifact publishing is owned by the caller. Choose artifact retention deliberately because reports may contain source fragments, dependency names, and repository paths.

## Scanner coverage and failures

Pinned scanner versions: Gitleaks **8.30.1**, Semgrep **1.179.0**, Trivy **0.75.0**. Gitleaks and Trivy archives are verified against SHA256 checksums stored in the action. Semgrep installs into an isolated virtual environment. When `trivy.yaml` exists, its effective `ignorefile` is parsed with **PyYAML 6.0.3** in a separate isolated virtual environment. Composer/npm versions come from the runner or your preceding setup steps.

Gitleaks scans secrets, Semgrep scans source code, and Trivy scans dependency vulnerabilities and misconfigurations. Composer audit reads `composer.lock` with plugins/scripts disabled; npm audit reads `package-lock.json` or `npm-shrinkwrap.json` without installing dependencies or running scripts. PHPStan uses project dependencies and configuration when explicitly enabled.

Each scanner runs independently. A technical scanner/configuration/install error does not prevent the remaining scanners or the upload of available reports. Findings are reported by default. Technical errors and upload failures always fail the final gate. The job summary distinguishes `completed`, `failed`, and `skipped`; failures never become empty successful scans. Upload retries transient network errors, HTTP 429, and selected 5xx statuses; authentication and validation failures are not retried.

For monorepos, audit explicit project directories in one invocation:

```yaml
- uses: amyla-net/security-scan@ACTION_RELEASE_COMMIT_SHA
  with:
    token: ${{ secrets.AMYLA_SCANNER_TOKEN }}
    composer-audit-paths: |
      apps/backend
      packages/library
    npm-audit-paths: apps/frontend
```

Only the selected root is auto-detected. Explicit directories without supported lockfiles produce a technical failure. This first version supports one action invocation per repository/run attempt: keep all audit paths in that invocation. Multiple independent action invocations in a matrix are not combined into one Amyla batch.

## Upload contract

The action sends multipart uploads with `summary` and genuine raw reports under `gitleaks`, `semgrep`, `trivy`, `phpstan`, `composer_audit`, and `npm_audit`. Dependency audits wrap original vendor JSON in `{"projects":[{"path":"...","status":"completed|failed","result":{...}}]}`. No fabricated empty-success reports are sent.

Repository metadata includes `repository`, `repository_id`, `default_ref`, `ref`, the actual checked-out `commit_sha`, run ID/attempt/number, actor, event name, run URL, and PR number when applicable. A target ID is omitted unless explicitly configured. The upload token authorizes its Amyla team; client-provided repository metadata is not independent proof of GitHub origin.

`summary.enabled_scanners` tracks selection; `summary.tools[scanner].status` distinguishes completed, failed, and skipped execution. Each completed scanner supplies `scope_hash`, a deterministic SHA256 of its directory, configuration contents, ignore files, rule-set names, and scope settings. Semgrep includes ancestor/nested `.gitignore`, `.semgrepignore`, recursively referenced `:include` files, and the checkout's `.git/info/exclude` when present. Ignore includes must remain inside the checkout; cyclic includes fail explicitly. PHPStan follows static local NEON includes and baselines, including commented include lists; dynamic PHP/parameter-based configuration includes are unsupported in this release and fail explicitly. Trivy includes the effective ignore file selected by `trivy.yaml`, or `.trivyignore` by default; an empty `ignorefile` disables ignores. Custom ignore files must exist and remain inside the scan directory. Dependency audits include each selected project's Composer `config.audit`, `config.policy`, and repository settings, or npm `.npmrc` and workspace settings. Dependency declarations and lockfile contents are excluded. The backend uses this value to avoid resolving earlier findings using a different configuration or scan directory. Failed scans preserve existing findings.

Scan subprocesses receive an isolated environment without the upload token or inherited cloud/registry credentials. npm audit scope also includes ancestor `.npmrc` and `package.json` workspace settings up to the checkout root, including ancestors above `working-directory`; external symlinks and workspace configurations outside the checkout fail explicitly. Dependency and lockfile contents remain outside the scope hash. Private dependency registries are not configured by this first release; failed access is reported as an audit failure. Upload is a separate step and does not follow redirects.

Amyla-managed execution is **Coming soon**. This release implements CI execution only.

## Development and licensing

Install the YAML parser for tests with `python3 -m pip install 'PyYAML==6.0.3'` in your development environment, then run `python3 -m unittest discover -s tests -v`. CI also runs Actionlint, ShellCheck, Zizmor, and smoke tests using this local action and its own fixtures. No Amyla private repository or external ingest token is needed.

The action code is [MIT licensed](LICENSE). Scanner tools and registry rule packages retain their own licenses: [Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/LICENSE), [Semgrep](https://github.com/semgrep/semgrep/blob/develop/LICENSE), and [Trivy](https://github.com/aquasecurity/trivy/blob/main/LICENSE). Installing a scanner does not relicense its upstream distribution or rules.
