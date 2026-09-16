# snyk-ads

Launch from the repository root with `sbx run claude --kit ./snyk-ads` and
the credentials for whichever components you request. This is the
repository's only kit. It requires sbx 0.39.0 or later and extends the
Claude sandbox.

- Select components with `-e SNYK_COMPONENTS=scan,guard,studio` (comma-separated;
  defaults to `scan`).
- `scan` needs `SNYK_TOKEN` (free-tier) or `SNYK_ADS_PUSH_KEY` (enterprise
  upload). `guard` needs `SNYK_ADS_PUSH_KEY` only — no tenant ID required.
  `studio` needs no credential to install; pass `-e SNYK_TOKEN` or use OAuth
  login inside the sandbox for its CLI.
- Components install directly from their public GitHub release channels —
  there is no dependency on Snyk's ADS installer or tenant-side configuration.
- Scans run at startup and repeat after a 15-minute pause between attempts.
- Agent instructions explain binary discovery and on-demand security reviews.

See the [setup guide](../README.md) for commands, authentication, identity,
logs, and troubleshooting. Place optional corporate root certificates in
[`files/home/corp-ca/`](./files/home/corp-ca/).
