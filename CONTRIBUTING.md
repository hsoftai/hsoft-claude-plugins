# Contributing to secrets-guard

Thanks for your interest in making secrets-guard better! This project follows a
test-first workflow and welcomes new detectors, vault providers, and additional
security plugins for the marketplace.

## Ground rules

- Be respectful — see our [Code of Conduct](CODE_OF_CONDUCT.md).
- Never commit real secrets, even in tests. Use the public sample values
  (e.g. the AWS docs example key `AKIAIOSFODNN7EXAMPLE`).
- Security issues go through [SECURITY.md](SECURITY.md), not public issues.

## Development setup

```sh
cd src
go test ./... -race      # run the suite
go vet ./...
golangci-lint run        # if installed
```

The Go module lives under `src/`. Plugin assets (manifest, hooks, binaries) live
under `plugins/secrets-guard/`.

## Test-first

This project is built test-first. For any behavior change:

1. Add or update a test that fails for the right reason.
2. Implement until it passes.
3. Keep tests table-driven where possible (see `internal/detect`).

## Adding a secret detector

1. Add a `Category` constant in `internal/detect/category.go`.
2. Add a positive case **and** a non-secret negative case in
   `internal/detect/detect_test.go`.
3. Add the rule in `internal/detect/detect.go`. Prefer anchored, specific
   patterns over broad ones to keep false positives low.

## Adding a vault provider

1. Implement `vault.Provider` (`Name`, `Scheme`, `Available`, `Resolve`) in a new
   file under `internal/vault/`, mirroring `keeper.go` / `onepassword.go`.
2. Wire it into `Select` and add it to the `auto` order.
3. Reuse the existing provider test battery with a mocked `Runner`.

## Adding a plugin to the marketplace

Create `plugins/<your-plugin>/` with its own `.claude-plugin/plugin.json` and add
an entry to `.claude-plugin/marketplace.json`. Run `claude plugin validate` on both.

## Manual end-to-end checks

See [docs/manual-testing.md](docs/manual-testing.md) for how to exercise the hooks
against a real `claude -p` session.

## Pull requests

- Keep PRs focused and described.
- Make sure `go test ./... -race` and `go vet ./...` pass.
- Update `CHANGELOG.md` under "Unreleased".
- Bump `version` in `plugin.json` (and the marketplace entry) for releases.
