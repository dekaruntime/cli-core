//! Separate processes exercise real argv/cwd without changing the test runner's state.
#[cfg(not(target_arch = "wasm32"))]
fn main() {
    use deka_cli_core::{CommandSpec, Context, ContextError, FlagSpec, Registry, SubcommandSpec};
    use std::process::Command;

    fn handler(context: &Context) {
        assert_eq!(context.env.cwd, std::env::current_dir().unwrap());
        assert_eq!(
            context.args.commands.first().map(String::as_str),
            Some("run")
        );
        assert_eq!(context.args.flags.get("--verbose"), Some(&true));
        assert_eq!(context.args.positionals, ["input.ds"]);
        println!("dispatched");
    }

    let mut registry = Registry::new();
    registry.add_command(CommandSpec {
        name: "run",
        owner: "test",
        category: "test",
        summary: "Context dispatch",
        aliases: &[],
        subcommands: &[SubcommandSpec {
            name: "check",
            summary: "Context subcommand dispatch",
            aliases: &[],
            handler,
        }],
        handler,
    });
    registry.add_flag(FlagSpec {
        name: "--verbose",
        aliases: &[],
        description: "verbose output",
    });

    // This test-driver marker is never read by the library.
    if std::env::var_os("CLI_CORE_CONTEXT_TEST_CHILD").is_some() {
        match Context::from_env(&registry) {
            Ok(context) if context.args.commands.is_empty() => {
                assert!(context.args.positionals.is_empty());
                assert_eq!(context.env.cwd, std::env::current_dir().unwrap());
                let cloned = Context::new(context.args.clone()).clone();
                assert_eq!(cloned.env.cwd, context.env.cwd);
                println!("empty argv constructed");
            }
            Ok(context) => registry.dispatch(&context).unwrap(),
            Err(ContextError::Parse(errors)) => {
                assert_eq!(errors.len(), 1);
                assert_eq!(errors[0].token, "--unknown");
                assert!(matches!(
                    errors[0].kind,
                    deka_cli_core::ParseErrorKind::UnknownToken
                ));
                println!("parse error preserved");
            }
        }
        return;
    }

    let executable = std::env::current_exe().unwrap();
    let cwd = std::env::temp_dir().canonicalize().unwrap();
    for (args, expected) in [
        (vec!["run", "--verbose", "input.ds"], "dispatched"),
        (vec!["run", "check", "--verbose", "input.ds"], "dispatched"),
        (vec!["--unknown"], "parse error preserved"),
        (vec![], "empty argv constructed"),
    ] {
        let output = Command::new(&executable)
            .args(args)
            .env("CLI_CORE_CONTEXT_TEST_CHILD", "1")
            .current_dir(&cwd)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), expected);
    }
    println!(
        "context_env: 4 process-argv/cwd cases passed; command and subcommand dispatch passed"
    );
}

#[cfg(target_arch = "wasm32")]
fn main() {}
