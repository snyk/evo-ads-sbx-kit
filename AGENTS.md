# Project agent memory

- Build the v3 kit with
  `docker buildx build . -f snyk-evo-ads.yaml --output type=cacheonly`;
  lifecycle hooks must declare every input environment variable in `env`.
  Run offline unit tests with
  `python3 -m unittest discover -s tests -v`.
- For real v3 launches, use
  `sbx run docker.io/docker/sbx-kit-claude:2.1.267 --kit "$PWD" --detach`.
  The built-in `claude` kit is not yet v3-compatible; sbx v0.48.0 rejects
  the literal `--kit .` as an invalid kit name, so use the absolute path.
- For real CA trust-store checks without sbx credentials, run
  `python3 tests/corp_ca_container.py` (Docker and the local shell sandbox
  template required; see the script).

## Maintaining this file

Keep this file for knowledge useful to almost every future agent session in this project.
Do not repeat what the codebase already shows; point to the authoritative file or command instead.
Prefer rewriting or pruning existing entries over appending new ones.
When updating this file, preserve this bar for all agents and keep entries concise.
