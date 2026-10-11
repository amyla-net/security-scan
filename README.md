# Amyla Security Scan

A standalone GitHub Action that scans your repository and optionally uploads reports to [Amyla Services](https://services.amyla.net). Amyla resolves the repository and creates its target on the first upload. No target ID or GitHub App installation is needed. Amyla-managed execution is **Coming soon**.

## Requirements

| Requirement | When needed | Provided by |
| --- | --- | --- |
| Ubuntu x64, Bash, Git, and Python 3.11+ with `venv`/pip | Every run | Your runner; the example uses `ubuntu-latest`. |
| Gitleaks, Semgrep, and Trivy | When enabled | The action installs pinned versions automatically. |
| PHP and a current Composer 2 version | Composer audit | Your workflow, for example with `setup-php`. |
| Node.js and npm | npm audit | Your workflow, for example with `setup-node`. |
| PHP, installed project dependencies, and `vendor/bin/phpstan` at the scan root | PHPStan, when explicitly enabled | Your workflow/project. |

The scan root is `working-directory` (default: `.`). Composer audit automatically runs for a root `composer.lock`; npm audit runs for a root `package-lock.json` or `npm-shrinkwrap.json`. Explicit audit paths also enable their audit in `auto` mode. Without supported lockfiles, automatic audits are `skipped`; an enabled audit with missing executables or invalid paths fails. Yarn/pnpm lockfiles do not enable npm audit.

Lockfile audits need neither `composer install` nor `npm ci`; they use the committed lockfiles without installing project dependencies. An empty Composer lockfile with no packages is `skipped`. PHPStan requires installed project dependencies and is disabled by default. Selecting a profile changes scanner rules and exclusions, not these requirements.

Outbound network access is required for scanner downloads, Python packages, registry rules, and vulnerability/advisory data, including in scan-only mode. An Amyla upload token is needed only to upload reports.

## Quick-setup

1. Create an Amyla team upload token with `scanner:ingest` and `scanner:targets:create` permissions and save it as the GitHub secret `AMYLA_SCANNER_TOKEN`.
2. Add `.github/workflows/security.yml`. This complete PHP/Node example uses PHP `8.5` and Node `24`; adapt them to your project. Remove the PHP setup if neither Composer audit nor PHPStan runs, and the Node setup if npm audit does not run. Adjust `main` if your default branch has another name.

```yaml
name: Security scan

on:
  push:
    branches: [main]
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

concurrency:
  group: ${{ github.workflow }}-${{ github.event.pull_request.number || github.ref }}
  cancel-in-progress: true

jobs:
  security:
    runs-on: ubuntu-latest
    timeout-minutes: 45
    steps:
      - name: Check out repository
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Set up PHP
        uses: shivammathur/setup-php@eb7c497e18156a6bbabfef1d3a82760b9eda3962 # v2.40.0
        with:
          php-version: '8.5'
          coverage: none
          tools: composer:v2

      - name: Set up Node.js
        uses: actions/setup-node@a0853c24544627f65ddf259abe73b1d18a591444 # v5.0.0
        with:
          node-version: '24'
          package-manager-cache: false

      - name: Scan and report
        id: security
        uses: amyla-net/security-scan@73baefa96b12bef90ca5e793c077d66df71728b6 # Validated main commit
        with:
          token: ${{ secrets.AMYLA_SCANNER_TOKEN }}
          profile: auto
          fail-on-findings: 'false'
```

The examples pin actions to full commit SHAs. Update the Security Scan pin to the reviewed commit you want to use. Node's automatic package-manager cache is disabled because this workflow audits lockfiles without installing project dependencies.

By default, Gitleaks scans secrets, Semgrep scans source code, and Trivy scans vulnerabilities and misconfigurations. Composer/npm audits run when supported lockfiles exist at the scan root; PHPStan is disabled. The profile is inferred from root `composer.json` (`laravel`, `kirby`, `php`, or `general`). Findings are reported without blocking the job; technical errors fail it.

For **scan-only mode**, skip creating the Amyla token and replace the action's `token` value with `''`. Fork pull requests without secrets also run scan-only. Do not execute untrusted pull-request code with secrets using `pull_request_target`.

## Full-config-example

Replace the action step above with this example to see **all 21 inputs**. It assumes a Laravel/Node monorepo with the listed configuration files and audit directories; adapt those paths to your repository. Each audit directory needs its supported lockfile. This example also enables PHPStan, so install project dependencies, including PHPStan, before the action. Empty optional values select automatic discovery or defaults.

```yaml
- name: Scan and report
  id: security
  uses: amyla-net/security-scan@73baefa96b12bef90ca5e793c077d66df71728b6 # Validated main commit
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

## Optional scan-only smoke test

To verify all five default scanners in a Laravel/Node repository, keep the quick-setup checkout and runtime steps, then replace its action step with the two steps below. The scan root must contain a `composer.lock` with at least one locked package and a `package-lock.json` or `npm-shrinkwrap.json`, alongside the corresponding project manifests. This example explicitly enables both audits; `profile: laravel` alone does not enable them. PHPStan remains disabled.

The extra check requires all five statuses to be `completed`, the upload status to be `skipped`, and no Amyla batch ID. It deliberately rejects skipped audits; omit it for repositories that do not need both audits.

```yaml
- name: Scan without uploading
  id: security
  uses: amyla-net/security-scan@73baefa96b12bef90ca5e793c077d66df71728b6 # Validated main commit
  with:
    token: ''
    profile: laravel
    fail-on-findings: 'false'
    run-composer-audit: 'true'
    run-npm-audit: 'true'

- name: Verify scan-only execution
  if: ${{ !cancelled() && steps.security.outputs.reports-path != '' }}
  env:
    REPORTS_PATH: ${{ steps.security.outputs.reports-path }}
    UPLOAD_STATUS: ${{ steps.security.outputs.upload-status }}
    SCAN_BATCH_ID: ${{ steps.security.outputs.scan-batch-id }}
  run: |
    python3 - <<'PY'
    import json
    import os
    from pathlib import Path

    if os.environ['UPLOAD_STATUS'] != 'skipped' or os.environ['SCAN_BATCH_ID']:
        raise SystemExit('Expected scan-only execution without an uploaded batch.')

    summary = json.loads((Path(os.environ['REPORTS_PATH']) / 'summary.json').read_text())
    expected = ('gitleaks', 'semgrep', 'trivy', 'composer_audit', 'npm_audit')
    incomplete = [name for name in expected if summary.get('tools', {}).get(name, {}).get('status') != 'completed']
    if incomplete:
        raise SystemExit('Scanners did not complete: ' + ', '.join(incomplete))

    print('All five scanners completed; Amyla upload was skipped.')
    PY
```

## Development and licensing

Install `PyYAML==6.0.3` in your development environment and run `python3 -m unittest discover -s tests -v`. CI also runs Actionlint, ShellCheck, Zizmor, and fixture smoke tests without an Amyla ingest token.

The action is [MIT licensed](LICENSE). Scanner tools and registry rules retain their upstream licenses: [Gitleaks](https://github.com/gitleaks/gitleaks/blob/master/LICENSE), [Semgrep](https://github.com/semgrep/semgrep/blob/develop/LICENSE), and [Trivy](https://github.com/aquasecurity/trivy/blob/main/LICENSE).
