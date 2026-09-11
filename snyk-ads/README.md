# snyk-ads

Launch from the repository root with `sbx run claude --kit ./snyk-ads` and
the credentials for your chosen mode. This is the repository's only kit. It requires sbx 0.39.0 or later
and extends the Claude sandbox.

- Standalone: supply `SNYK_TOKEN` to install the latest AgentScan release.
- Enterprise: supply `SNYK_TENANT_ID` and `SNYK_ADS_PUSH_KEY` to install the
  components enabled in Evo through ADS. Also pass `-e SNYK_TOKEN` for
  Studio's CLI token authentication, or use OAuth login inside the sandbox.
  The push key still selects enterprise mode. The agent requests authentication
  only when neither a token nor existing CLI credentials are available.
- Scans run at startup and repeat after a 15-minute pause between attempts.
- Agent instructions explain binary discovery and on-demand security reviews.

See the [setup guide](../README.md) for commands, authentication, identity,
logs, and troubleshooting. Place optional corporate root certificates in
[`files/home/corp-ca/`](./files/home/corp-ca/).
