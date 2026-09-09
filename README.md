# Snyk ADS Sandbox Kit

> This is an experimental Kit and should be considered a tech preview. Evo was not built directly for Docker Sandboxes and some gaps and limitations may appear. Although, most of it does work. 

A [Docker Sandboxes](https://docs.docker.com/ai/sandboxes/) kit (`kind: mixin`) that installs
**Snyk ADS** — the Agent Detection & Response guard hooks — into a Claude sandbox, so every tool
call, shell execution and file write the agent makes is reported to the Snyk Evo control plane.

The kit does four things:

1. Stages your corporate root CA into the VM's trust store (Zscaler and friends).
2. Preflights your two Snyk credentials and fails the create if either is missing or malformed.
3. Downloads the correct architecture of the ADS installer and runs it as the agent user.
4. Verifies the guard hooks were actually written, and fails loudly if they weren't.

**Requires** `sbx` **0.38.0 or later** (0.39.0 if you want `--env-file`). The `files/` staging
directory this kit depends on landed in 0.38.0.

---



## Folder structure

The unit `sbx` consumes is a **directory**, not a file. This repo is laid out so a fresh clone
works with `--kit ./snyk-ads` and no restructuring:

```
evo-ads-docker-sandbox-kit/
├── README.md
├── .gitignore                                 ← ignores corp-ca/*.crt by default
├── snyk-ads/                                  ← this is what you pass to --kit
│   ├── spec.yaml                              ← the kit definition (required)
│   └── files/                                 ← staged into the VM before install runs
│       └── home/
│           └── corp-ca/
│               ├── README.md                  ← how to export and validate your cert
│               ├── example-root-ca.crt.example ← expected PEM shape (ignored by the glob)
│               └── <your-root-ca>.crt         ← you add this; see below
├── snyk-ads-next/                             ← proposed, opt-in. Not the supported kit.
│   ├── README.md                              ← what it adds and why
│   ├── spec.yaml
│   └── files/home/corp-ca/                    ← same staging as above
└── docs/
    ├── Snyk_ADS_Sandbox_Kit_-_How-To_Guide.pdf
    └── Snyk_ADS_Sandbox_Kit_-_How-To_Guide.docx
```

Anything under `files/` is copied into the sandbox **before** the `setup.install` commands run,
with `files/home/` mapping to `/home/agent/`. So:


| Path in the kit                          | Path inside the VM                        |
| ---------------------------------------- | ----------------------------------------- |
| `files/home/corp-ca/zscaler-root-ca.crt` | `/home/agent/corp-ca/zscaler-root-ca.crt` |
| `files/home/corp-ca/anything-else.crt`   | `/home/agent/corp-ca/anything-else.crt`   |


The first install step globs `/home/agent/corp-ca/*.crt` and installs every match into the system
trust store. Drop in as many certs as your proxy chain needs; you don't edit `spec.yaml` to add one.
Non-`.crt` files in that directory — the two placeholders — are ignored and safe.

To vendor the kit inside another project, copy the whole `snyk-ads/` directory across. The
`docs/` folder and this README are not part of the kit.

### Two kits, and which to use

`snyk-ads/` **is the supported one.** Use it unless you have a reason not to.

`snyk-ads-next/` is an opt-in proposal that adds per-sandbox machine identity (from
`SANDBOX_NAME` + `SANDBOX_ID`, new in sbx 0.39.0) and a `startup` hook that re-runs the
agent-scan inventory on every sandbox start rather than only at creation. It exists so those two
changes can be reviewed as a working spec rather than as a diff in a thread.


|                        | `snyk-ads/`                                                          | `snyk-ads-next/`                |
| ---------------------- | -------------------------------------------------------------------- | ------------------------------- |
| Status                 | Supported                                                            | Proposed, opt-in                |
| Minimum `sbx`          | 0.38.0                                                               | **0.39.0**                      |
| Machine identity       | One shared identity — all sandboxes collapse to a single console row | Unique per sandbox              |
| Inventory refresh      | Once, at creation                                                    | Every sandbox start             |
| Unverified assumptions | None                                                                 | Two, both flagged in its README |


Full rationale, the fixes applied to the original proposal, and what still needs confirming
against a shipped binary: `[snyk-ads-next/README.md](./snyk-ads-next/README.md)`.

---



## Staging the corporate CA certificate

Skip this section entirely if your network does not intercept TLS. The kit is designed to work
without a cert — the CA step is **non-fatal by design** and just prints a warning.

The directory already exists at `snyk-ads/files/home/corp-ca/` — it has its own
[README](./snyk-ads/files/home/corp-ca/README.md) and an
`[example-root-ca.crt.example](./snyk-ads/files/home/corp-ca/example-root-ca.crt.example)`
showing the exact format expected. You just add the real cert next to them.

### 1. Export your root CA in PEM form

**macOS (Zscaler, from the System keychain):**

```bash
security find-certificate -a -c "Zscaler Root CA" -p \
  /Library/Keychains/System.keychain \
  > snyk-ads/files/home/corp-ca/zscaler-root-ca.crt
```

If that returns nothing, the cert may be in the login keychain or under a different common name.
List what's there:

```bash
security find-certificate -a -p /Library/Keychains/System.keychain \
  | openssl storeutl -noout -text /dev/stdin | grep -i 'issuer\|subject'
```

**Linux:** the cert is usually already at `/usr/local/share/ca-certificates/` or
`/etc/pki/ca-trust/source/anchors/` — copy it straight across.

**Last resort — pull the root out of the live chain:**

```bash
openssl s_client -showcerts -connect downloads.snyk.io:443 </dev/null 2>/dev/null \
  | awk '/BEGIN CERT/,/END CERT/' > /tmp/chain.pem
```

Then split `/tmp/chain.pem` and keep the **last** certificate in it — that's the root your proxy
is presenting.

### 2. Check it before you burn a sandbox create on it

```bash
# must print BEGIN CERTIFICATE
head -1 snyk-ads/files/home/corp-ca/zscaler-root-ca.crt

# must parse, and CA:TRUE must appear in the basic constraints
openssl x509 -in snyk-ads/files/home/corp-ca/zscaler-root-ca.crt -noout -text \
  | grep -A1 'Basic Constraints'
```



### Four things that will bite you here


| Gotcha                                 | Why it matters                                                                                                                                                                                                                                 |
| -------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Must be PEM, not DER.**              | The file has to start with `-----BEGIN CERTIFICATE-----`. A binary `.cer` from a browser export will be staged happily and then ignored by `update-ca-certificates`. Convert with `openssl x509 -inform der -in in.cer -out out.crt`.          |
| **Must have a** `.crt` **extension.**  | `update-ca-certificates` only picks up `*.crt`. A file named `zscaler.pem` is copied into the VM and silently does nothing.                                                                                                                    |
| **Must be the ROOT, not the leaf.**    | Trusting the intercepted server cert doesn't establish the chain. You want the self-signed CA at the top.                                                                                                                                      |
| **Don't commit a cert you shouldn't.** | A corporate root CA is a public key, not a secret — but check your org's policy before pushing it. `snyk-ads/files/home/corp-ca/*.crt` is gitignored here by default; `git add -f <path>` if you deliberately want to share it with your team. |




### What the kit deliberately does *not* do

It never sets `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` or `PIP_CERT`. Those **replace** the system
bundle, which breaks the trust the sandbox credential proxy depends on. The kit only *appends*, via
`update-ca-certificates`.

The one exception is `NODE_EXTRA_CA_CERTS`, which is set to the regenerated system bundle. Node
ships its own CA list and ignores the system trust store, so without this the ADS installer's npm
step fails TLS behind Zscaler even when `curl` succeeded. `NODE_EXTRA_CA_CERTS` is additive, not a
replacement — that's why it's safe. **If you fork this kit, keep that line.**

---



## The two credentials


|                       | `SNYK_TENANT_ID`                              | `SNYK_ADS_PUSH_KEY`                                             |
| --------------------- | --------------------------------------------- | --------------------------------------------------------------- |
| What it is            | A UUID identifying your tenant. Not a secret. | The credential the guard hooks push agent activity with.        |
| Where to get it       | Snyk Evo console → Settings → General         | Snyk Evo console → Settings. Shown once.                        |
| How it reaches the VM | `-e SNYK_TENANT_ID=<uuid>`                    | `-e SNYK_ADS_PUSH_KEY` (bare name, value from your shell)       |
| Where it ends up      | An installer flag. Not persisted.             | Written to the hook config on disk inside the VM, in plaintext. |
| Treat it as           | An identifier — fine in a runbook.            | A live secret. Store in 1Password; rotate if printed.           |


Only one of these is a secret. Treating the tenant ID as one costs ergonomics and buys nothing.

**The push key is container-resident, and it cannot be otherwise.** The ADS installer writes it to
disk inside the VM and the hooks read it for every push, so there is nothing for the credential
proxy to inject into — which is why this kit correctly has no `credentials:` block. The security
boundary here is the microVM plus the egress allow-list, not the absence of the secret. See §7 of
the [How-To Guide](./docs/Snyk_ADS_Sandbox_Kit_-_How-To_Guide.pdf).

---



## Quick start

```bash
# 0. cheap validation before you spend a sandbox create
sbx kit validate ./snyk-ads/

# 1. resolve the push key from 1Password into your shell
set -o pipefail
export SNYK_ADS_PUSH_KEY="$(op read 'op://Engineering/Snyk ADS/credential')"

# 2. launch
sbx run claude --kit ./snyk-ads --name $(hostname)-sandbox \
  -e SNYK_TENANT_ID=5de58927-xxxx-xxxx-xxxx-xxxxxxxxf6fe \
  -e SNYK_ADS_PUSH_KEY \
  -e SANDBOX_USER=$(whoami)
```

Four lines, four reasons:


|                              | Why                                                                                                                                                                                                                                                                     |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--name $(hostname)-sandbox` | The Evo console identifies machines by hostname. Without a name you get an `sbx`-generated one and you're guessing which row is yours in **Agent Behavior → Machines**. Deriving it from your hostname makes the sandbox traceable back to the laptop that launched it. |
| `-e SNYK_TENANT_ID=<uuid>`   | A literal is fine here — the tenant ID is an identifier, not a secret. Preflight rejects anything that isn't a UUID.                                                                                                                                                    |
| `-e SNYK_ADS_PUSH_KEY`       | **No** `=value`**.** A bare name tells `sbx` to lift the value out of your current environment, keeping the secret out of shell history and out of `ps` argv. Don't "fix" it by adding the literal.                                                                     |
| `-e SANDBOX_USER=$(whoami)`  | The spec maps this to `USER` inside the VM. Without it, activity attributes to the sandbox's default `agent` user and every engineer's sessions look identical in the console.                                                                                          |


> **The tenant ID above is masked.** Replace it with your own full UUID from
> Evo → Settings → General. The value as written will fail preflight — deliberately, so a
> copy-paste can't silently point your activity at someone else's tenant.



### On identity and attribution

`--name` and `SANDBOX_USER` are the two things that make console output readable when more than
one person is running the kit. Neither affects whether the install works, which is why they're
easy to skip and then regret.

The spec also has `MACHINE_ID` commented out on purpose — setting it **collapses every sandbox
into a single row** in the console. Leave it commented unless that's genuinely what you want.

`LOGNAME` is likewise commented out alongside `USER`. Some tooling reads one and some the other;
uncomment it if attribution still looks wrong after setting `SANDBOX_USER`.

`--kit` is creation-time only. To attach the kit to a sandbox that's already running:

```bash
sbx kit add my-sandbox ./snyk-ads/
```

That works here because this mixin only touches the three fields a mixin can add in place:
`environment.variables`, `setup.install` and `permissions.network.allow`.

---



## Verify

A successful create prints, in order:

```
corp-ca: staged zscaler-root-ca.crt
corp-ca: installed 1 certificate(s) into the system trust store
corp-ca: outbound TLS verified
snyk-ads: credentials OK
snyk-ads: installing for linux-arm64
snyk-ads: hooks OK
```

Then check inside the VM:

```bash
ls ~/.ads-scan/bin/            # snyk-guard, snyk-scan, snyk-studio-installer
ls ~/.snyk-studio/             # device-id, cli-path, ades/
grep -i snyk ~/.claude/settings.json
```

And in the console: **Agent Behavior → Machines**, find your sandbox by the name you passed to
`--name`. Activity should appear within a minute or two of the agent doing anything. Drilling into
a session shows the files written, domains reached and prompts that drove it — the **Files Written**
panel is the one worth watching.

If the row is there but attributed to `agent` rather than you, you launched without
`-e SANDBOX_USER=$(whoami)`.

> `snyk` not being on `PATH` is expected. The ADS guard hooks and the interactive Snyk CLI
> (`snyk_code_scan`, `snyk_sca_scan`) authenticate separately. Run `snyk auth` inside the sandbox
> if you want scanning as well as the guard.

---



## Network policy

The kit allows five domains and nothing else:


| Domain               | Why                          |
| -------------------- | ---------------------------- |
| `downloads.snyk.io`  | Installer download           |
| `api.snyk.io`        | `REMOTE_HOOKS_BASE_URL`      |
| `evo.snyk.io`        | Steady-state pushes          |
| `app.snyk.io`        | Console callbacks            |
| `registry.npmjs.org` | The ADS installer's npm step |


> **Under organization governance, kit-level allow rules are ignored.** Docker's docs are explicit
> about this: only org allow rules grant access. If governance is on in your org, these five
> domains must be allowed centrally or the install dies at the download step. Check with
> `sbx policy ls`.

---



## Troubleshooting


| Symptom                                              | Cause                                                                                                     | Fix                                                                                                |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `curl exit 60` or `77`                               | TLS trust — the proxy's root CA isn't in the store.                                                       | Stage the **root** CA at `files/home/corp-ca/<name>.crt`, PEM, `.crt` extension.                   |
| `curl exit 6` or `7`                                 | Egress blocked. Not a cert problem.                                                                       | Org governance overrides kit allow rules — `sbx policy ls`.                                        |
| `curl exit 22`                                       | HTTP error from `downloads.snyk.io`.                                                                      | Usually a wrong architecture path; the kit detects arch, so check the printed `linux-<arch>` line. |
| `corp-ca: WARNING no .crt files found`               | Nothing under `files/home/corp-ca/`, or `sbx` < 0.38.0.                                                   | Non-fatal. Only a problem if the install then fails with 60/77. Check `sbx version`.               |
| `SNYK_TENANT_ID is not a valid tenant ID`            | A tenant *name* or a truncated paste.                                                                     | Copy the UUID from Settings → General.                                                             |
| `SNYK_ADS_PUSH_KEY is not set`                       | Expired `op` session, nearly always.                                                                      | `op whoami`, then `eval $(op signin)`, then re-export.                                             |
| `invalid character in secret reference: '('`         | 1Password item title contains parentheses.                                                                | Rename to a clean handle, or use the item UUID.                                                    |
| `/token` reference fails                             | API Credential items store the value in a field named `credential`, not `token`.                          | `op item get <item>` to list real field names.                                                     |
| npm step fails TLS but curl worked                   | Node ignores the system trust bundle.                                                                     | Already handled by `NODE_EXTRA_CA_CERTS`. Don't remove it if you fork.                             |
| Install succeeds, no hooks in settings               | Install ran as root, hooks went to `/root/.claude/`.                                                      | Already handled by `user: "1000"`. Don't remove it.                                                |
| `--kit can only be used when creating a new sandbox` | It's a creation-time flag.                                                                                | `sbx kit add <sandbox> ./snyk-ads/`                                                                |
| Clean install, console stays empty                   | Key is well-formed but wrong, revoked, or from another tenant. Preflight checks shape, not authorisation. | Re-mint the push key and confirm it matches the tenant ID.                                         |
| Can't tell which console row is your sandbox         | Launched without `--name`, so `sbx` generated one.                                                        | `--name $(hostname)-sandbox` at create time. Not changeable afterwards.                            |
| Sessions attributed to `agent`, not you              | `SANDBOX_USER` wasn't passed.                                                                             | `-e SANDBOX_USER=$(whoami)`. If it persists, uncomment `LOGNAME` in the spec.                      |
| Every sandbox shows as one row in the console        | `MACHINE_ID` is set.                                                                                      | Leave it commented out in the spec — setting it collapses all sandboxes together.                  |




### When the create won't come up at all

There's a diagnostic twin of this kit (`snyk-ads-diag`) that runs the same CA and network steps but
where **every step ends** `exit 0` and takes no credentials. The point is to get a sandbox that
actually boots so you can run the real installer by hand with its stderr visible. Reach for it when
you can't tell a TLS failure from an egress failure from the outside.

---



## Design notes for anyone forking this

Three lines in `spec.yaml` look removable and are not:

- `user: "1000"` **on the install step.** Install defaults to root; as root the installer writes
hooks to `/root/.claude/` and the agent never loads them.
- `set -eu` **in the install step.** Without it a failed `curl` falls through to the final `grep`,
whose `|| echo` branch exits 0 — `sbx` reports a green install for a sandbox with no hooks at all.
- `NODE_EXTRA_CA_CERTS`**.** See the CA section above.

The CA step is intentionally non-fatal while the credential preflight is intentionally fatal. That
asymmetry is deliberate: a missing CA isn't necessarily an error (plenty of networks don't intercept
TLS), and keeping it fatal would guarantee you can never get inside the VM to find out which failure
you actually have. A missing push key, by contrast, produces a *silently* broken sandbox — so it
gets gated up front.

---



## Further reading

- **[Snyk ADS Sandbox Kit — How-To Guide](./docs/Snyk_ADS_Sandbox_Kit_-_How-To_Guide.pdf)** ([.docx](./docs/Snyk_ADS_Sandbox_Kit_-_How-To_Guide.docx)) — the full walkthrough, including the 1Password setup and the security-model reasoning
- [Docker Sandboxes — security model](https://docs.docker.com/ai/sandboxes/security/)
- [Docker Sandboxes — kit spec reference](https://docs.docker.com/ai/sandboxes/customize/kits/)
- [Docker Sandboxes — managing credentials](https://docs.docker.com/ai/sandboxes/configuration/credentials/)
- [Docker Sandboxes — authentication workflows](https://docs.docker.com/ai/sandboxes/workflows/authentication/)

