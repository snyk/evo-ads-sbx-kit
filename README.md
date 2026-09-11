# Snyk ADS Sandbox Kit

An experimental Docker Sandboxes mixin for Claude. The repository contains one
kit, [`snyk-ads`](./snyk-ads/), requiring **sbx 0.39.0 or later**.

The kit supports standalone AgentScan with a Snyk token and enterprise installation
through ADS. It stages optional corporate certificates, installs tools, and runs
AgentScan at startup and after a 15-minute pause between attempts.

## Getting started

Clone the repository and validate the kit:

```bash
git clone git@github.com:snyk/evo-ads-sbx-kit.git
cd evo-ads-sbx-kit
sbx kit validate ./snyk-ads
```

Run the launch commands below from this repository directory. If your network
uses TLS interception, [stage your corporate root certificate](#corporate-certificates-and-network-access)
before creating the sandbox. Choose free tier or enterprise authentication below.

## Repository layout

```text
evo-ads-sbx-kit/
├── README.md
├── snyk-ads/
│   ├── spec.yaml
│   ├── README.md
│   └── files/home/
│       ├── .snyk-kit/   # Authentication, download, and component helpers
│       └── corp-ca/     # Optional corporate root certificates
└── tests/test_auth.py
```

Pass the entire `snyk-ads/` directory to `--kit`. Copy that directory when
vendoring the kit into another project. The older PDF and Word guides under
`docs/` describe the previous setup; use this README for current commands.

## Authentication

| Mode | Credentials | Installation |
| --- | --- | --- |
| Standalone / free tier | `SNYK_TOKEN` | Latest stable AgentScan release from GitHub, with SHA-256 verification |
| Enterprise | `SNYK_TENANT_ID` and `SNYK_ADS_PUSH_KEY`; optional `SNYK_TOKEN` for Studio | ADS installs the components enabled in the tenant's Evo settings |

Credentials are supplied explicitly with `-e`. The kit does not declare credential
defaults or import host variables. A supplied push key selects enterprise mode and
requires a tenant UUID, even if a token is also supplied. Free tier needs no tenant
ID or empty enterprise overrides. Keep secrets in environment variables rather
than command-line literals.

### Free tier

Export `SNYK_TOKEN` in your terminal, then run:

```bash
sbx run claude \
  --kit ./snyk-ads \
  --name "$(hostname)-sandbox-free" \
  -e SNYK_TOKEN
```

The binary is installed at `~/.local/share/snyk-agent-scan/agent-scan`.
This path installs AgentScan only, without Guard or Studio.

### Enterprise

Export `SNYK_ADS_PUSH_KEY` in your terminal and replace the tenant placeholder.
If you want token authentication for Studio, also export `SNYK_TOKEN`.
Studio can instead use an interactive OAuth login through `snyk_auth` or
`snyk auth` inside the sandbox:

```bash
sbx run claude \
  --kit ./snyk-ads \
  --name "$(hostname)-sandbox" \
  -e SNYK_TENANT_ID="<your-tenant-uuid>" \
  -e SNYK_ADS_PUSH_KEY \
  -e SNYK_TOKEN
```

Omit `-e SNYK_TOKEN` to use OAuth or existing CLI credentials for Studio.
Enterprise installation still uses the tenant ID and push key. The agent checks
Studio authentication and guides the user through login only when needed; an
absent token environment variable alone does not require action. Alternatively,
export a token in your host terminal and pass it through `-e SNYK_TOKEN`.
Do not paste credentials into the agent conversation. Supplying a token alongside
the push key does not switch the kit to standalone mode.

Scan, Guard, and Studio are independently enabled in Evo. The kit logs downloaded
components to `~/.snyk/ads-components.log` and relies on ADS installer exit handling.
A tenant with Scan disabled can install successfully; the scan worker logs a skip.
Enterprise binaries are under `~/.ads-scan/bin/` and may not be on PATH.

## Corporate certificates and network access

If your network intercepts TLS, place its PEM-encoded root certificate at:

```text
snyk-ads/files/home/corp-ca/zscaler-root-ca.crt
```

The `.crt` extension is required. Certificates are gitignored. See the
[certificate guide](./snyk-ads/files/home/corp-ca/README.md) for export and
validation instructions. The kit adds certificates to the system trust store and
sets Node's additional CA bundle. Missing certificates do not themselves abort setup,
but intercepted downloads may fail without them.

The kit allows `downloads.snyk.io`, `api.snyk.io`, `evo.snyk.io`, `app.snyk.io`,
`registry.npmjs.org`, `github.com`, and `release-assets.githubusercontent.com`.
Organization policy may require these domains to be allowed centrally.

## Agent-assisted security reviews

Inside the sandbox, ask Claude:

> Run an AgentScan security review and summarize the findings for this sandbox.
 The kit's
instructions explain authentication, binary discovery, and synchronous results via
`--show-analysis-results`. AgentScan does not require `snyk auth`; Snyk CLI has
separate authentication.

Background results are logged rather than inserted into an existing conversation.
Enterprise background scans can submit asynchronous analysis to Snyk. MCP execution
consent is preserved for interactive scans.

## Identity and recurring scans

Scan receives `--machine-id "docker-sbx:${SANDBOX_NAME}:${SANDBOX_ID}"` in both
modes. Docker provides these variables inside the sandbox. The ID survives a restart
and changes when the sandbox is recreated.

Guard currently uses the sandbox hostname assigned by ADS. Exporting `MACHINE_ID`
for the installer does not override that choice; Guard and Scan therefore use
different identifiers. The kit does not reinstall Guard to change its identity.

The background worker scans immediately, waits 900 seconds after each attempt, and
repeats. A lock prevents duplicate workers. Failures are logged and retried without
blocking sandbox startup. A missing Scan binary causes the worker to exit. AgentScan
versions below 0.6.0, or an unreadable version, produce a warning without stopping scans.

## Verification and troubleshooting

```bash
sbx kit validate ./snyk-ads
sbx exec "<sandbox-name>" sh -c 'cat "$HOME/.snyk/agent-scan-startup.log"'
sbx exec "<sandbox-name>" sh -c 'sh "$HOME/.snyk-kit/ads-components.sh" report'
```

Replace `<sandbox-name>` with the name passed at creation, such as
`$(hostname)-sandbox` for enterprise or `$(hostname)-sandbox-free` for free tier.

The component report is for ADS installations. For standalone installations, check
`~/.local/share/snyk-agent-scan/agent-scan` instead.

| Symptom | Check |
| --- | --- |
| TLS download failure, curl 60/77 | Corporate root certificate and system trust store |
| Connection failure, curl 6/7 | DNS, proxy, and organization network policy |
| Enterprise credential validation fails | Tenant UUID and supplied push key |
| No Scan binary | Authentication mode, installer output, and Evo component settings |
| `which agent-scan` finds nothing | Use the mode-specific binary path; enterprise names differ |
| No recurring output | Startup log and sbx version |

## Local checks

```bash
python3 -m unittest discover -s tests -v
shellcheck snyk-ads/files/home/.snyk-kit/*.sh
sbx kit validate ./snyk-ads
```
