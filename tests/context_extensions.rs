#![cfg(feature = "registry")]

use deka_cli_core::{Args, CommandSpec, Context, Registry, SubcommandSpec};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn context() -> Context {
    Context::new(Args::collect(Vec::new(), &Registry::new()).args)
}

#[test]
fn insert_get_roundtrip_and_replacement() {
    // Consumer state need not implement Clone or Debug.
    struct State(String);
    let mut ctx = context();
    assert!(ctx.extensions().get::<State>().is_none());
    ctx.extensions_mut().insert(State("resolved".into()));
    assert_eq!(ctx.extensions().get::<State>().unwrap().0, "resolved");
    ctx.extensions_mut().insert(State("replacement".into()));
    assert_eq!(ctx.extensions().get::<State>().unwrap().0, "replacement");
}

#[test]
fn types_and_contexts_are_isolated() {
    struct First(u32);
    struct Second(u32);
    let mut ctx = context();
    ctx.extensions_mut().insert(First(1));
    ctx.extensions_mut().insert(Second(2));
    assert_eq!(ctx.extensions().get::<First>().unwrap().0, 1);
    assert_eq!(ctx.extensions().get::<Second>().unwrap().0, 2);
    assert!(ctx.extensions().get::<u32>().is_none());
    assert!(context().extensions().get::<First>().is_none());
}

#[test]
fn dispatcher_passes_resolved_state_to_command_and_subcommand_handlers() {
    struct HandlerSnapshot {
        entrypoint: String,
        calls: Arc<AtomicUsize>,
    }
    fn handler(ctx: &Context) {
        let snapshot = ctx.extensions().get::<HandlerSnapshot>().unwrap();
        assert_eq!(snapshot.entrypoint, "consumer/main.ds");
        assert_eq!(ctx.args.positionals, ["input.ds"]);
        snapshot.calls.fetch_add(1, Ordering::SeqCst);
    }
    let mut registry = Registry::new();
    registry.add_command(CommandSpec {
        name: "run",
        owner: "consumer",
        category: "test",
        summary: "resolved consumer handler",
        aliases: &[],
        subcommands: &[SubcommandSpec {
            name: "check",
            summary: "check resolved consumer handler",
            aliases: &[],
            handler,
        }],
        handler,
    });
    let calls = Arc::new(AtomicUsize::new(0));
    for tokens in [vec!["run", "input.ds"], vec!["run", "check", "input.ds"]] {
        let parsed = Args::collect(tokens.into_iter().map(str::to_owned).collect(), &registry);
        assert!(parsed.errors.is_empty());
        let mut ctx = Context::new(parsed.args);
        // The consumer dispatcher resolves state before handing off fn(&Context).
        ctx.extensions_mut().insert(HandlerSnapshot {
            entrypoint: "consumer/main.ds".into(),
            calls: Arc::clone(&calls),
        });
        registry.dispatch(&ctx).unwrap();
    }
    assert_eq!(calls.load(Ordering::SeqCst), 2);
}

#[test]
fn context_remains_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Context>();
}

#[test]
fn clone_shares_extensions_but_replacement_is_local() {
    // Neither Clone nor Debug is required on stored values.
    struct State(AtomicUsize);
    let mut original = context();
    original.extensions_mut().insert(State(AtomicUsize::new(1)));
    let mut cloned = original.clone();
    let first = original.extensions().get::<State>().unwrap();
    let second = cloned.extensions().get::<State>().unwrap();
    assert!(std::ptr::eq(first, second));
    second.0.store(2, Ordering::SeqCst);
    assert_eq!(first.0.load(Ordering::SeqCst), 2);

    cloned.extensions_mut().insert(State(AtomicUsize::new(3)));
    assert_eq!(
        original
            .extensions()
            .get::<State>()
            .unwrap()
            .0
            .load(Ordering::SeqCst),
        2
    );
    drop(original);
    assert_eq!(
        cloned
            .extensions()
            .get::<State>()
            .unwrap()
            .0
            .load(Ordering::SeqCst),
        3
    );
}
