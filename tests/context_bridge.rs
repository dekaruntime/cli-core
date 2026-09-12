#![cfg(feature = "registry")]

use deka_cli_core::{Args, CommandSpec, Context, Registry};
use std::path::PathBuf;

#[test]
fn consumer_owned_state_maps_to_shared_dispatch_without_recapturing_cwd() {
    // Deka retains its handler/vars state; its parsed args and cwd map directly.
    struct ProductContext {
        args: Args,
        cwd: PathBuf,
        handler: String,
    }
    fn handler(context: &Context) {
        assert_eq!(context.env.cwd, PathBuf::from("consumer/workspace"));
        assert_eq!(context.args.positionals, ["main.ds"]);
    }
    let mut registry = Registry::new();
    registry.add_command(CommandSpec {
        name: "run",
        owner: "legacy",
        category: "test",
        summary: "consumer bridge",
        aliases: &[],
        subcommands: &[],
        handler,
    });
    let parsed = Args::collect(vec!["run".into(), "main.ds".into()], &registry);
    assert!(parsed.errors.is_empty());
    let product = ProductContext {
        args: parsed.args,
        cwd: PathBuf::from("consumer/workspace"),
        handler: "consumer-owned handler resolution".into(),
    };
    let mut shared = Context::new(product.args.clone());
    shared.env.cwd = product.cwd.clone();
    registry.dispatch(&shared).unwrap();
    assert_eq!(product.handler, "consumer-owned handler resolution");
}
