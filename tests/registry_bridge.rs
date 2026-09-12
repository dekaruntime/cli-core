#![cfg(feature = "registry")]

use deka_cli_core::registry::{
    Args, BuildError, CommandSpec, Context, FlagSpec, ParamSpec, Registry, RegistryBuilder,
    SubcommandSpec,
};
use std::sync::atomic::{AtomicUsize, Ordering};

static DISPATCHES: AtomicUsize = AtomicUsize::new(0);

fn handler(context: &Context) {
    assert_eq!(context.args.flags.get("-v"), Some(&true));
    assert_eq!(context.args.params.get("--output").unwrap(), "out");
    DISPATCHES.fetch_add(1, Ordering::SeqCst);
}

fn command(name: &'static str, owner: &'static str) -> CommandSpec {
    CommandSpec {
        name,
        owner,
        category: "test",
        summary: "legacy command",
        aliases: &["r"],
        subcommands: &[SubcommandSpec {
            name: "check",
            summary: "check command",
            aliases: &["c"],
            handler,
        }],
        handler,
    }
}

// Same public signature and mutable registration calls as Deka's in-tree core.
pub fn register(registry: &mut Registry) {
    registry.add_command(command("run", ""));
    registry.add_flag(FlagSpec {
        name: "--verbose",
        aliases: &["-v"],
        description: "verbose output",
    });
    registry.add_param(ParamSpec {
        name: "--output",
        description: "output path",
    });
}

#[test]
fn legacy_registration_parses_and_dispatches_commands_and_subcommands() {
    let registry = RegistryBuilder::new().with(register).build().unwrap();
    assert_eq!(registry.commands()[0].owner, "legacy");
    assert_eq!(registry.flags()[0].name, "--verbose");
    assert_eq!(registry.params()[0].name, "--output");
    for tokens in [
        vec!["r", "-v", "--output", "out"],
        vec!["r", "c", "-v", "--output", "out"],
    ] {
        let parsed = Args::collect(tokens.into_iter().map(str::to_owned).collect(), &registry);
        assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
        registry.dispatch(&Context::new(parsed.args)).unwrap();
    }
    assert_eq!(DISPATCHES.load(Ordering::SeqCst), 2);
}

#[test]
fn direct_mutable_registry_supports_existing_registration() {
    let mut registry = Registry::new();
    register(&mut registry);
    assert_eq!(registry.command_for("r").unwrap().name, "run");
    assert_eq!(registry.flags().len(), 1);
    assert_eq!(registry.params().len(), 1);
}

#[test]
fn with_and_inherit_collide_in_either_order() {
    for builder in [
        RegistryBuilder::new()
            .inherit([command("run", "old")])
            .with(register),
        RegistryBuilder::new()
            .with(register)
            .inherit([command("run", "old")]),
    ] {
        assert_eq!(
            builder.build().unwrap_err(),
            BuildError::DuplicateCommand {
                name: "run".into(),
                first_owner: "legacy".into(),
                second_owner: "legacy".into(),
            }
        );
    }
}

#[test]
fn with_accepts_fn_once_preserves_owners_and_sees_prior_registrations() {
    let owned = command("owned", "pm");
    let registry = RegistryBuilder::new()
        .inherit([command("old", "ignored")])
        .with(move |registry| {
            assert_eq!(registry.command_named("old").unwrap().owner, "legacy");
            registry.add_command(owned);
            registry.add_command(command("blank", " \t"));
        })
        .with(register)
        .build()
        .unwrap();
    assert_eq!(registry.command_named("owned").unwrap().owner, "pm");
    assert_eq!(registry.command_named("blank").unwrap().owner, "legacy");
    assert_eq!(registry.command_named("run").unwrap().owner, "legacy");
}

#[test]
fn with_does_not_relax_register_validation() {
    for builder in [
        RegistryBuilder::new()
            .register([command("invalid", "")])
            .with(register),
        RegistryBuilder::new()
            .with(register)
            .register([command("invalid", "")]),
    ] {
        assert_eq!(
            builder.build().unwrap_err(),
            BuildError::MissingOwner {
                name: "invalid".into()
            }
        );
    }
    let error = RegistryBuilder::new()
        .with(register)
        .register([command("run", "pm")])
        .build()
        .unwrap_err();
    assert_eq!(
        error,
        BuildError::DuplicateCommand {
            name: "run".into(),
            first_owner: "legacy".into(),
            second_owner: "pm".into(),
        }
    );
}
