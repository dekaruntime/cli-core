# deka-cli-core

Shared lifecycle library for Deka's Rust command-line tools. One crate,
`deka-cli-core`, published from this repo.

## What's in this crate

- **`cli`** — the `SharedCli` integration surface a CLI wires up once:
  - `self_service` — signed self-update (`SelfAction::Update`), health
    monitoring (`SelfAction::Monitor`), and rollback to the previous
    installed release.
  - `auth` — device-code login/logout against an identity origin, backed
    by the token store below.
  - `setup` — a declarative, resumable setup plan (`SetupStep` /
    `SetupPlan`) for first-run provisioning: creating directories, writing
    config files, running commands.
- **`update`** — the signed-release verification and atomic-install
  pipeline invoked by `self_service`. Downloaded release bytes only reach
  the installer as a `VerifiedArtifact`: a capability type with no public
  constructor, produced only after the release manifest, the "latest"
  freshness statement, the artifact digest and size, and the trust
  generation have all checked out against a compiled root-of-trust
  (`TrustStore`). The compiled roots and their generation-1 anchor set are
  embedded at build time and are public keys only; nothing here can sign
  a release.
- **`token_file`** — an XDG-path, mode-0600 on-disk store for a single
  `SecretToken`, with basic hardening against symlink and permission
  tampering.
- **`whoami`** — a minimal HTTP client for an identity-origin `whoami`
  endpoint, plus origin validation (`validate_linkhash_origin`) shared by
  the auth flow.
- **`pulse_client`** — a small async HTTP client used to emit self-update
  and health events to an operational event sink, with bearer-token
  support from a token file.
- **`src/bin/harar-anchor-init.rs`** — an offline ceremony tool. Given
  four raw 32-byte Ed25519 private-key files (mode 0600, read once,
  zeroized after use) it produces a signed `anchor-set.json` /
  `anchor-set.sig.json` pair. It never touches the network and is not
  invoked by any CLI at runtime — it is how a new trust generation is
  minted, out of band.

## Use from Cargo

```toml
[dependencies]
deka-cli-core = "0.2"
```

`0.1.0` was an earlier token-file/identity-only crate; `0.2.0` is the
current shared lifecycle facade and is where new consumers should start.

A CLI wires this in roughly as:

```rust
use deka_cli_core::{AuthSpec, HealthProbe, ProductSpec, SelfAction, SharedCli};

let product = ProductSpec::new("mycli", env!("CARGO_PKG_VERSION"), "https://example.invalid", HealthProbe::argv(&["--self-test"]))?
    .with_auth(AuthSpec::new("https://identity.example.invalid"));
let shared = SharedCli::from_xdg(product)?;
shared.run_self(SelfAction::Update { check_only: false, exact: None, allow_major: false })?.print()?;
```

See `examples/` for two complete wire-ups.

Credentials for any private registry you consume this crate from belong
in the caller's own Cargo configuration, never in this repository.

## Mutable registry compatibility

Existing `pub fn register(registry: &mut Registry)` functions can be passed to
`RegistryBuilder::new().inherit(legacy).with(owner::register).build()`.
`Registry` exposes Deka core's `new`, `add_command`, `add_flag`, and `add_param`
methods with the same signatures.

`CommandSpec` still requires the `owner` field introduced in 0.4.0. Legacy
struct literals can use `owner: ""`; `.with()` tags newly appended commands
with empty or whitespace-only owners as `"legacy"` and preserves explicit
owners. `.register(specs)` still requires nonblank owners, `.inherit(specs)`
still tags every inherited command as `"legacy"`, and `.build()` rejects
duplicate command names across all registration paths.

## Context compatibility (RFD 61)

`registry::Context` exposes `args` and `env: EnvContext`, where `env.cwd` is a
`PathBuf`. `Context::new(args)` keeps its signature and captures cwd.
`Context::from_env(&Registry) -> Result<Self, ContextError>` parses process
arguments and returns `ContextError::Parse(Vec<ParseError>)` on parse errors.
`EnvContext::load() -> Self` captures cwd with a `"."` fallback. No environment
variables or handler configuration are read. Both new types are also re-exported
at the crate root.

On wasm32, `from_env` is cfg-gated out. `EnvContext::load()` and
`Context::new(args)` remain available and use `"."` without host process access.

The dsc reference (`e3d9226`, `crates/core/src/context.rs`) has exactly this
native Context surface. Its `Context::from_env`, exhaustive `ContextError::Parse`
matches, and `context.env.cwd` accesses map directly to these shared types.

The Deka reference (`89f173a`, `.deka-ref/crates/core/src/context.rs`) additionally
owns `env.vars`, `handler`, and `ContextError::HandlerResolve`. Those remain
consumer-side as required by RFD 61. Its parsed `args` and `env.cwd` map to a
shared Context; this is not a claim that replacing Deka's entire Context with a
re-export compiles unchanged. In particular, `crates/cli/src/lib.rs` constructs
the richer Context, `cli/mod.rs` matches `HandlerResolve`, and self-update and
monitor tests construct handler-bearing contexts. `tests/context_bridge.rs`
checks the args/cwd projection and dispatch; the existing registry bridge tests
continue to check mutable registration and `Context::new(args)` unchanged.

Rust source compatibility caveat: adding the public `env` field requires old
`Context { args }` struct literals to supply `env` or use `Context::new(args)`.
The constructor, args field, parser, registry, and dispatch signatures are
unchanged; this field addition cannot preserve args-only struct literals.

## Build and test

```sh
cargo build --all-targets
cargo test --all-targets
```

One test file, `tests/signed_release_real_topology.rs`, exercises the
signed-update path against a real producer binary out-of-process; those
tests are `#[ignore]`d by default and need `LINKHASH_REAL_BINARY` set to
that binary's path.

## History

This repository's history was extracted, full ancestry intact, from an
earlier internal monorepo location and then renamed to its current crate
name (`deka-cli-core`). Nothing about that predecessor affects the public
API described above.
