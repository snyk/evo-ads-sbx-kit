# Snyk ADS Sandbox Kit

An experimental Docker Sandboxes mixin, requiring **sbx 0.39.0 or later**. The
kit's `spec.yaml` and `files/` live at the repository root — there is only one
kit here, so there's nothing to disambiguate with a subdirectory.

The kit installs whichever Snyk components you request — AgentScan, Agent
Guard, and/or Snyk Studio — directly from their public release channels. It
stages optional corporate certificates, installs the requested components,
and runs AgentScan at startup and after a 15-minute pause between attempts.
There is no dependency on Snyk's ADS installer or any tenant-side
configuration: what gets installed is exactly what you ask for.

This repository is closed to public contributions.

## Getting started

Clone the repository and validate the kit:

```bash
git clone git@github.com:snyk/evo-ads-sbx-kit.git
cd evo-ads-sbx-kit
sbx kit validate .
```

Run the launch commands below from this repository directory. If your network
uses TLS interception, [stage your corporate root certificate](#corporate-certificates-and-network-access)
before creating the sandbox.

## Repository layout

```text
evo-ads-sbx-kit/
├── README.md
├── spec.yaml
├── files/home/
│   ├── .snyk-kit/   # Component selection, auth, and download helpers
│   └── corp-ca/     # Optional corporate root certificates
└── tests/test_auth.py
```

Pass the repository root to `--kit` (or clone it standalone and pass that
clone's root). Copy `spec.yaml` and `files/` when vendoring the kit into
another project.

## Components

Select what to install with `SNYK_COMPONENTS`, a comma-separated list of
`scan`, `guard`, and/or `studio`. It defaults to `scan` when omitted.

| Component | Credential required | Notes |
| --- | --- | --- |
| `scan` (AgentScan) | `SNYK_TOKEN`, or `SNYK_ADS_PUSH_KEY` | Free-tier with a token, or enterprise upload with a push key |
| `guard` (Agent Guard) | `SNYK_ADS_PUSH_KEY` | `SNYK_TENANT_ID` is optional — Agent Guard only needs it for the interactive push-key-minting flow this kit never uses |
| `studio` (Snyk Studio) | none to install | Optional `SNYK_TOKEN` authenticates its Snyk CLI afterward |

Scan and Guard are the same `agent-scan` binary (downloaded once, from
[github.com/snyk/agent-scan releases](https://github.com/snyk/agent-scan/releases),
SHA-256 verified) and always live at
`~/.local/share/snyk-agent-scan/agent-scan`, in every mode. Studio is a
separate binary from
[github.com/snyk/studio-recipes releases](https://github.com/snyk/studio-recipes/releases),
downloaded and verified the same way.

Credentials are supplied explicitly with `-e`. The kit does not declare
credential defaults or import host variables. Requesting a component without
its required credential fails sandbox creation immediately, with a clear
error — it does not silently skip the component.

### Default: free-tier AgentScan

```bash
sbx run claude \
  --kit . \
  --name "$(hostname)-sandbox-free" \
  -e SNYK_TOKEN
```

`SNYK_COMPONENTS` defaults to `scan`, so this installs AgentScan only.

### AgentScan + Agent Guard

```bash
sbx run claude \
  --kit . \
  --name "$(hostname)-sandbox" \
  -e SNYK_COMPONENTS=scan,guard \
  -e SNYK_ADS_PUSH_KEY
```

Guard hooks install directly (no ADS installer involved), so the identity
Guard reports matches Scan's — both use
`docker-sbx:${SANDBOX_NAME}:${SANDBOX_ID}` — from the very first install.

### All three components

```bash
sbx run claude \
  --kit . \
  --name "$(hostname)-sandbox-all" \
  -e SNYK_COMPONENTS=scan,guard,studio \
  -e SNYK_ADS_PUSH_KEY
```

### Studio alone

```bash
sbx run claude \
  --kit . \
  --name "$(hostname)-sandbox-studio" \
  -e SNYK_COMPONENTS=studio
```

No credential is required to install Studio. Studio's Snyk CLI can instead
authenticate interactively via `snyk_auth`/`snyk auth` inside the sandbox, or
you can pass `-e SNYK_TOKEN` alongside `SNYK_COMPONENTS=studio` to
pre-authenticate it. Never paste credentials into the agent conversation.

### Custom Snyk API base (`SNYK_API`)

By default Scan and Guard talk to `https://api.snyk.io`. Set `SNYK_API` to
point them at a different Snyk API base instead — the kit passes it to
`guard install` as `--url`, and to `scan` as `--analysis-url` with the same
path AgentScan uses by default (only the host changes):

```bash
sbx run claude \
  --kit . \
  --name "$(hostname)-sandbox" \
  -e SNYK_COMPONENTS=scan,guard \
  -e SNYK_ADS_PUSH_KEY \
  -e SNYK_API=https://api.example-region.snyk.io
```

## Corporate certificates and network access

### Do you even need this?

Check what's actually terminating TLS on the way to Snyk's servers before
assuming either way:

```bash
openssl s_client -connect downloads.snyk.io:443 </dev/null 2>/dev/null | grep -E '^\s*i:' | tail -1
```

A public CA in the output (DigiCert, Amazon, ISRG, etc.) means nothing is
intercepting TLS — skip this section entirely. A corporate proxy name
(Zscaler, Netskope, Palo Alto, ...) means your network is intercepting TLS
and you need to stage its root certificate, below.

### Staging the corporate CA certificate

Place its PEM-encoded root certificate in `files/home/corp-ca/` with
a `.crt` extension — any filename works, the install step globs `*.crt`:

```text
files/home/corp-ca/your-corporate-ca.crt
```

**macOS, from the system keychain** (replace `"Zscaler Root CA"` with your
proxy's CA name):

```bash
security find-certificate -a -c "Zscaler Root CA" -p \
  /Library/Keychains/System.keychain \
  > files/home/corp-ca/your-corporate-ca.crt
```

**Linux, from the system trust store** (Debian/Ubuntu path shown; RHEL-based
distros use `/etc/pki/ca-trust/source/anchors/`):

```bash
cp /usr/local/share/ca-certificates/your-corporate-ca.crt \
  files/home/corp-ca/your-corporate-ca.crt
```

**From the live TLS chain**, if you don't have keychain/trust-store access —
this pulls the topmost certificate your proxy actually presents, which is
usually an intermediate rather than a true self-signed root (proxies
typically don't serve their root), but is sufficient as a trust anchor in
practice:

```bash
openssl s_client -connect downloads.snyk.io:443 -showcerts </dev/null 2>/dev/null \
  | awk '/-----BEGIN CERTIFICATE-----/{buf=""} {buf=buf $0 "\n"} /-----END CERTIFICATE-----/{last=buf} END{printf "%s", last}' \
  > files/home/corp-ca/your-corporate-ca.crt
```

Validate before spending a sandbox create on it:

```bash
head -1 files/home/corp-ca/*.crt        # must read BEGIN CERTIFICATE
openssl x509 -in files/home/corp-ca/your-corporate-ca.crt -noout -text \
  | grep -A1 'Basic Constraints'                 # must read CA:TRUE
```

See the [certificate guide](./files/home/corp-ca/README.md) for the
full set of rules (PEM vs DER, root vs leaf, gitignore behavior). The kit
adds certificates to the system trust store and sets Node's additional CA
bundle. Missing certificates do not themselves abort setup, but intercepted
downloads may fail without them.

### Network allowlist

The kit allows `**.snyk.io` (any host under `snyk.io`, any subdomain depth —
covers `api.snyk.io`, `deeproxy.snyk.io`, `downloads.snyk.io`, and a custom
`SNYK_API` host), plus `registry.npmjs.org`, `github.com`, and
`release-assets.githubusercontent.com`. Snyk Code (SAST) needs access to
`deeproxy.snyk.io`; AgentScan, Guard, and Studio binaries download from
`github.com`/`release-assets.githubusercontent.com`. Organization policy may
require these domains to be allowed centrally. Kit changes apply when
creating a sandbox; existing sandboxes need their network policy updated or
must be recreated.

## Agent-assisted security reviews

Inside the sandbox, ask Claude:

> Run an AgentScan security review and summarize the findings for this sandbox.

The kit's instructions explain authentication, binary discovery, and synchronous
results via `--show-analysis-results`. AgentScan does not require `snyk auth`;
Snyk CLI has separate authentication.

Background results are logged rather than inserted into an existing conversation.
Enterprise background scans can submit asynchronous analysis to Snyk. MCP execution
consent is preserved for interactive scans.

## Verification and troubleshooting

```bash
sbx kit validate .
sbx exec "<sandbox-name>" sh -c 'sh "$HOME/.snyk-kit/resolve-components.sh"'
sbx exec "<sandbox-name>" sh -c 'cat "$HOME/.snyk/agent-scan-startup.log"'
```

Replace `<sandbox-name>` with the name passed at creation.

`resolve-components.sh` prints `scan=0|1 guard=0|1 studio=0|1
auth_mode=enterprise|standalone|none` and fails with a specific error if a
requested component is missing its required credential. AgentScan and Guard
always share `~/.local/share/snyk-agent-scan/agent-scan`; Studio's binary is
at `~/.local/share/snyk-studio/snyk-studio-installer`.

| Symptom | Check |
| --- | --- |
| TLS download failure, curl 60/77 | Corporate root certificate and system trust store |
| Connection failure, curl 6/7 | DNS, proxy, and organization network policy |
| Sandbox creation fails immediately with a `snyk-ads: ERROR` | Which component was requested and which credential it needs (see [Components](#components)) |
| No Scan binary | Whether `scan` was actually requested in `SNYK_COMPONENTS` |
| No recurring output | Startup log and sbx version |
