# tana-cli-core

`tana-cli-core` is the shared lifecycle library for Tana's Rust command-line
tools. It provides `SharedCli` for signed self-update, check, monitor and
rollback; Linkhash login, logout and identity lookup; XDG paths; Ruba event
emission; and resumable declarative setup.

The signed update path preserves the sealed `VerifiedArtifact` boundary from
tana#722: untrusted release bytes cannot reach the atomic installer until the
artifact, release manifest, latest statement, trust generation, digest and
size have all been verified.

## Use from Linkhash Cargo

Configure the Linkhash sparse registry (the checked-in configuration targets a
local Linkhash facade), then declare the versioned dependency:

```toml
[dependencies]
tana-cli-core = { version = "=0.2.0", registry = "linkhash" }
```

Version `0.1.0` is the earlier token-file and identity-only crate. The complete
shared lifecycle facade starts at `0.2.0`; consumers pin it exactly while the
initial integration is rolled out.

Cargo authentication belongs in the caller's private Cargo credentials, never
in this repository.

## Validate

```sh
cargo build --all-targets
cargo test --all-targets
cargo package --registry linkhash
```

The separate-process signed-release topology test additionally needs a real
Linkhash binary via `LINKHASH_REAL_BINARY`; see the test source for the exact
invocation.

## Extraction provenance

This repository was history-preservingly extracted from
`tana/tana@ea6aa47363f912689afd76f1a5acacb9665bde9a`, path
`crates/tana-cli-core/`, using `git subtree split`. The extracted ancestry ends
at `9cc36595fd49d9e8bb3a8681e8e58c9298a2f56a`; unrelated `tana/tana` history
was intentionally excluded.
