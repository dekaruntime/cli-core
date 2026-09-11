use deka_cli_core::{
    AuthSpec, HealthProbe, LoginOptions, ProductSpec, SecretToken, SelfAction, SharedCli,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let product = ProductSpec::new(
        "gild",
        env!("CARGO_PKG_VERSION"),
        "https://linkha.sh",
        HealthProbe::argv(&["--self-test"]),
    )?
    .with_auth(AuthSpec::new("https://github.com"));
    let shared = SharedCli::from_xdg(product)?;
    match std::env::args().nth(1).as_deref() {
        Some("update") => shared
            .run_self(SelfAction::Update {
                check_only: false,
                exact: None,
                allow_major: false,
            })?
            .print()?,
        Some("monitor") => shared
            .run_self(SelfAction::Monitor {
                emit_to_ruba: false,
                json: false,
            })?
            .print()?,
        Some("rollback") => shared.run_self(SelfAction::Rollback)?.print()?,
        Some("login") => {
            shared.login(LoginOptions::token(SecretToken::new(std::env::var(
                "TANA_GIT_TOKEN",
            )?)?))?;
        }
        Some("logout") => shared.logout()?,
        Some("whoami") => println!("{}", shared.whoami()?.id),
        _ => eprintln!("usage: gild <update|monitor|rollback|login|logout|whoami>"),
    }
    Ok(())
}
