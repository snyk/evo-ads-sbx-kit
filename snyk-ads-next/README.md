# snyk-ads-next — proposed, opt-in

> **This is not the supported kit.** Use [`../snyk-ads/`](../snyk-ads/) unless you are
> specifically evaluating the two changes below. This directory exists so the proposal can be
> reviewed and tested as a working spec rather than as a diff in a Slack thread.

Everything in [`../snyk-ads/`](../snyk-ads/), plus two additions from Ramon Lopez Narvaez's
proposal:

1. **Per-sandbox machine identity**, built from `SANDBOX_NAME` + `SANDBOX_ID`.
2. **A `setup.startup` hook** that re-runs the agent-scan inventory on every sandbox start and repeats after a 15-minute pause between scans,
   not just at creation.

**Requires `sbx` 0.39.0 or later.** The supported kit needs only 0.38.0. That version bump is
the cost of adopting this.

---

## Why these two changes

### 1. Machine identity — this fixes a feature that's currently switched off

`../snyk-ads/spec.yaml` has `MACHINE_ID` commented out with the note
*"collapses all sandboxes to one row"*. That's what happens with a **static** machine ID: every
sandbox reports the same value and the console's Machines tab shows one row for all of them.

Docker fixed the input side of this in 0.39.0:

> Sandboxes now expose their own identity as `SANDBOX_NAME` and `SANDBOX_ID` environment
> variables, matching the name and id shown by `sbx ls --json`; the older `SANDBOX_VM_ID` still
> carries the sandbox name but is deprecated.
>
> — [sbx release notes, 0.39.0](https://docs.docker.com/ai/sandboxes/release-notes/#0390)

So the ID can now be **dynamic** — unique per sandbox — which is the thing that was missing.
`MACHINE_ID` goes from "must stay off" to "safe to turn on".

It composes with the launch flags rather than replacing them:

| Signal | Answers | Source |
| --- | --- | --- |
| `SANDBOX_NAME` | which laptop | your `--name $(hostname)-sandbox` |
| `SANDBOX_ID` | which sandbox instance | injected by the daemon, 0.39.0+ |
| `USER` | which human | your `-e SANDBOX_USER=$(whoami)` |

Result: `docker-sbx:jacks-mbp-sandbox:01JAB...`, attributed to a named user.

**A subtlety worth not re-discovering:** `MACHINE_ID` is *not* set in `environment.variables`.
That block interpolates from the **host** shell at create time, and `SANDBOX_NAME` / `SANDBOX_ID`
only exist **inside** the sandbox. Setting it there expands to an empty string — reproducing the
exact all-sandboxes-in-one-row failure this change is meant to fix. It's composed inside the
install and startup commands instead, where those variables are available. Both use
`MACHINE_ID="docker-sbx:${SANDBOX_NAME}:${SANDBOX_ID}"` directly. sbx 0.39.0+ is required;
installation fails if either variable is missing or empty. No identity file or older-version
fallback is used.

### 2. Startup hook — closes a gap the supported kit has

`setup.install` runs **once, at creation**. The MCP-server and skill inventory is therefore a
single snapshot: restart the sandbox, or add an MCP server mid-life, and nothing re-reports.

Docker's kit reference is explicit about the split:

> Install commands run once at creation; startup commands run each time the sandbox starts.
> [...] Startup commands are for work that can run alongside the agent, such as a background
> service. They must be idempotent.

The same page warns that startup commands *"don't gate the agent entrypoint"* — which is why
**only the inventory push** lives there. The ADS hook install stays in `setup.install`; moving it
to `startup` would race the agent's own initialization and give you a sandbox that sometimes
starts unhooked.

---

## What changed from Ramon's sketch

His version is a proposal in a doc, not a spec meant to run. The following changes were needed before it
would work:

| His sketch | Problem | Here |
| --- | --- | --- |
| `--push-key "$PUSH_KEY"` | Variable doesn't exist — the kit sets `SNYK_ADS_PUSH_KEY`. Would push with an empty key. | Uses `SNYK_ADS_PUSH_KEY`, and skips with a logged reason if it's empty. |
| `snyk-agent-scan` bare on `PATH` | Verified installs put ADS binaries in `~/.ads-scan/bin/`. | Resolves `~/.ads-scan/bin/` first, then `PATH`, then skips quietly. |
| Startup failure behaviour unstated | A failing inventory push could affect boot. | Scan failures are logged and retried after 15 minutes. Logs to `~/.snyk/agent-scan-startup.log`. |

Kept from his version, unchanged, because they're right: `flock -n` (idempotency under concurrent
starts), `background: true`, and `set -eu` / `unset NPM_CONFIG_PREFIX` in install.

Everything from the supported kit is carried over untouched: corp-CA staging, the TLS probe,
credential preflight, architecture detection, `user: "1000"`, and the post-install hooks check.

---

## What still needs verifying

Two things in `spec.yaml` are marked `UNVERIFIED` at the point of use. **Both are guesses from the
proposal, not confirmed against a shipped binary.** Check them before trusting any output:

**(a) How the installer takes the machine ID.** The spec exports `MACHINE_ID` as an environment
variable, on the assumption that's what the installer reads — which is what the supported kit's
commented-out `MACHINE_ID:` line implies. Ramon's doc also shows a `--machine-id` flag form. If
the flag is required instead, the spec has the alternative invocation ready to uncomment.

```bash
# inside a sandbox
/tmp/ads-installer --help
```

Don't add the flag speculatively — an unrecognised flag aborts the install.

**(b) The agent-scan subcommand and flags.** `scan --machine-id --push-key` is taken verbatim
from the proposal.

```bash
sbx exec <sandbox> -- ~/.ads-scan/bin/snyk-scan --help
```

---

## Try it

Identical to the supported kit, only the `--kit` path changes:

```bash
sbx version                     # must be >= 0.39.0
sbx kit validate ./snyk-ads-next/

set -o pipefail
export SNYK_ADS_PUSH_KEY="$(op read 'op://Engineering/Snyk ADS/credential')"

sbx run claude --kit ./snyk-ads-next --name $(hostname)-sandbox \
  -e SNYK_TENANT_ID=<your-tenant-uuid> \
  -e SNYK_ADS_PUSH_KEY \
  -e SANDBOX_USER=$(whoami)
```

Staging a corporate CA works exactly as in the supported kit — drop it in
[`files/home/corp-ca/`](./files/home/corp-ca/).

### What a good run prints

Same as the supported kit, plus the machine identity:

```
snyk-ads: machine id docker-sbx:jacks-mbp-sandbox:01JAB...
```

Then, after the sandbox starts:

```bash
cat ~/.snyk/agent-scan-startup.log
```

The startup hook logs each scan attempt, so restarting the sandbox and re-reading
that log is the quickest way to confirm the hook is firing at all.

### Checking it actually did something

In the console, **Agent Behavior → Machines**: two sandboxes launched from this kit should be
**two rows**, not one. If they collapse, compare the machine identity in each startup log
and verify that the installer uses the exported `MACHINE_ID`.

---

## Failure modes specific to this kit

| Symptom | Cause | Fix |
| --- | --- | --- |
| Sandboxes still collapse to one row | Machine ID reached the installer empty, or the installer doesn't read `MACHINE_ID` from the environment. | Check the `machine id` line printed at install, then verifying item **(a)** above. |
| `agent-scan: SKIP no scan binary found` | Install didn't complete, or the binary name changed. | The log lists `~/.ads-scan/bin/` contents. Compare against verifying item **(b)**. |
| `agent-scan: SKIP push key not present` | `SNYK_ADS_PUSH_KEY` didn't carry into the startup environment. | Confirm it was exported at create time. Startup runs in a login shell; the kit's `environment.variables` should carry it. |
| Log file empty after a restart | The startup hook isn't running. | `sbx kit validate`, and confirm `setup.startup` is supported on your `sbx` version. |
| Inventory appears twice per boot | Two starts raced and `flock` didn't hold. | Expected to be rare; report it — `flock -n` should make the second exit immediately. |

Everything else — TLS, credentials, egress, hooks — behaves as documented in the
[root README](../README.md#troubleshooting).

The startup log includes the AgentScan version. Versions older than 0.6.0, including
0.6.0 prereleases, produce a warning; an unavailable or unrecognized version does too.
These warnings do not prevent the inventory scan. This check does not enable Linux scheduling.

While ADS installer scheduling is unavailable on Linux, the background startup worker
runs a scan immediately, waits 900 seconds after each attempt, and repeats while the
sandbox runs. A lifetime `flock` prevents duplicate workers, including during the wait.
Failed scans are logged and retried on the next cycle. Stopping the sandbox stops the
worker; starting it again launches a new worker with an immediate scan.
