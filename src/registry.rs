//! Portable command registration, parsing, and dispatch for Tana CLIs.

use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone)]
pub struct CommandSpec {
    pub name: &'static str,
    pub owner: &'static str,
    pub category: &'static str,
    pub summary: &'static str,
    pub aliases: &'static [&'static str],
    pub subcommands: &'static [SubcommandSpec],
    pub handler: fn(&Context),
}

#[derive(Debug, Clone)]
pub struct SubcommandSpec {
    pub name: &'static str,
    pub summary: &'static str,
    pub aliases: &'static [&'static str],
    pub handler: fn(&Context),
}

#[derive(Debug, Clone)]
pub struct FlagSpec {
    pub name: &'static str,
    pub aliases: &'static [&'static str],
    pub description: &'static str,
}

#[derive(Debug, Clone)]
pub struct ParamSpec {
    pub name: &'static str,
    pub description: &'static str,
}

/// Parsed input passed unchanged to command and subcommand handlers.
#[derive(Debug, Clone)]
pub struct Context {
    pub args: Args,
}

impl Context {
    pub fn new(args: Args) -> Self {
        Self { args }
    }
}

#[derive(Debug, Clone)]
pub struct Args {
    pub flags: HashMap<String, bool>,
    pub params: HashMap<String, String>,
    pub commands: Vec<String>,
    pub positionals: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ParseOutcome {
    pub args: Args,
    pub errors: Vec<ParseError>,
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub token: String,
    pub kind: ParseErrorKind,
    pub suggestions: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ParseErrorKind {
    UnknownToken,
    MissingParamValue { param: String },
}

impl ParseError {
    fn unknown(token: String, suggestions: Vec<String>) -> Self {
        Self {
            token,
            kind: ParseErrorKind::UnknownToken,
            suggestions,
        }
    }

    fn missing_param(param: String) -> Self {
        Self {
            token: param.clone(),
            kind: ParseErrorKind::MissingParamValue { param },
            suggestions: Vec::new(),
        }
    }
}

impl Args {
    pub fn collect(args: Vec<String>, registry: &Registry) -> ParseOutcome {
        let mut flags = HashMap::new();
        let mut params = HashMap::new();
        let mut commands = Vec::new();
        let mut positionals = Vec::new();
        let mut errors = Vec::new();
        let mut flag_tokens: HashSet<&'static str> = HashSet::new();
        let mut param_tokens: HashSet<&'static str> = HashSet::new();
        let suggestion_tokens = registry.suggestion_tokens();

        for flag in registry.flags() {
            flag_tokens.insert(flag.name);
            for alias in flag.aliases {
                flag_tokens.insert(alias);
            }
        }
        for param in registry.params() {
            param_tokens.insert(param.name);
        }

        let mut current_command = None;
        let mut iter = args.iter().enumerate();
        while let Some((_index, arg)) = iter.next() {
            let token = arg.as_str();
            if let Some((name, value)) = token.split_once('=') {
                if flag_tokens.contains(name) {
                    flags.insert(name.to_string(), true);
                    params.insert(name.to_string(), value.to_string());
                    continue;
                }
            }
            if flag_tokens.contains(token) {
                flags.insert(arg.clone(), true);
                continue;
            }
            if param_tokens.contains(token) {
                if let Some(value) = iter.next().map(|(_, value)| value) {
                    params.insert(arg.clone(), value.clone());
                } else {
                    errors.push(ParseError::missing_param(arg.clone()));
                }
                continue;
            }
            if let Some(command) = current_command {
                if let Some(subcommand) = registry.subcommand_for(command, token) {
                    commands.push(subcommand.name.to_string());
                } else if token.starts_with('-') {
                    errors.push(ParseError::unknown(
                        arg.clone(),
                        suggest(token, &suggestion_tokens),
                    ));
                } else {
                    positionals.push(arg.clone());
                }
                continue;
            }
            if let Some(command) = registry.command_for(token) {
                commands.push(command.name.to_string());
                current_command = Some(command);
            } else if token.starts_with('-') {
                errors.push(ParseError::unknown(
                    arg.clone(),
                    suggest(token, &suggestion_tokens),
                ));
            } else if looks_like_path(token) {
                positionals.push(arg.clone());
            } else {
                errors.push(ParseError::unknown(
                    arg.clone(),
                    suggest(token, &suggestion_tokens),
                ));
            }
        }
        ParseOutcome {
            args: Args {
                flags,
                params,
                commands,
                positionals,
            },
            errors,
        }
    }
}

pub fn parse_env(registry: &Registry) -> ParseOutcome {
    #[cfg(target_arch = "wasm32")]
    let args: Vec<String> = Vec::new();
    #[cfg(not(target_arch = "wasm32"))]
    let args: Vec<String> = std::env::args().skip(1).collect();
    Args::collect(args, registry)
}

#[derive(Debug, Default)]
pub struct RegistryBuilder {
    registry: Registry,
}

impl RegistryBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    /// Run an existing mutable registration function on the inner registry.
    ///
    /// Newly added commands with blank owners are tagged `"legacy"`. Explicit
    /// owners are preserved, and validation still happens in [`Self::build`].
    pub fn with(mut self, f: impl FnOnce(&mut Registry)) -> Self {
        let first_new_command = self.registry.commands.len();
        f(&mut self.registry);
        for command in self.registry.commands.iter_mut().skip(first_new_command) {
            if command.owner.trim().is_empty() {
                command.owner = "legacy";
            }
        }
        self
    }

    /// Absorb commands that have not yet migrated to an owner crate.
    pub fn inherit(mut self, commands: impl IntoIterator<Item = CommandSpec>) -> Self {
        self.registry
            .commands
            .extend(commands.into_iter().map(|mut command| {
                command.owner = "legacy";
                command
            }));
        self
    }

    pub fn register(mut self, commands: impl IntoIterator<Item = CommandSpec>) -> Self {
        self.registry.commands.extend(commands);
        self
    }

    pub fn flags(mut self, flags: impl IntoIterator<Item = FlagSpec>) -> Self {
        self.registry.flags.extend(flags);
        self
    }

    pub fn params(mut self, params: impl IntoIterator<Item = ParamSpec>) -> Self {
        self.registry.params.extend(params);
        self
    }

    pub fn build(self) -> Result<Registry, BuildError> {
        let mut seen = HashMap::new();
        for command in &self.registry.commands {
            if command.owner != "legacy" && command.owner.trim().is_empty() {
                return Err(BuildError::MissingOwner {
                    name: command.name.to_string(),
                });
            }
            if let Some(first_owner) = seen.insert(command.name, command.owner) {
                return Err(BuildError::DuplicateCommand {
                    name: command.name.to_string(),
                    first_owner: first_owner.to_string(),
                    second_owner: command.owner.to_string(),
                });
            }
        }
        Ok(self.registry)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BuildError {
    DuplicateCommand {
        name: String,
        first_owner: String,
        second_owner: String,
    },
    MissingOwner {
        name: String,
    },
}

impl fmt::Display for BuildError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateCommand {
                name,
                first_owner,
                second_owner,
            } => write!(
                formatter,
                "command `{name}` is registered by both `{first_owner}` and `{second_owner}`"
            ),
            Self::MissingOwner { name } => {
                write!(formatter, "command `{name}` must declare a non-empty owner")
            }
        }
    }
}

impl Error for BuildError {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DispatchError {
    MissingCommand,
    TooManyCommands,
    UnknownCommand(String),
    UnknownSubcommand { command: String, subcommand: String },
}

impl fmt::Display for DispatchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingCommand => write!(formatter, "no command was provided"),
            Self::TooManyCommands => {
                write!(formatter, "at most one command and subcommand are allowed")
            }
            Self::UnknownCommand(command) => write!(formatter, "unknown command `{command}`"),
            Self::UnknownSubcommand {
                command,
                subcommand,
            } => write!(
                formatter,
                "unknown subcommand `{subcommand}` for `{command}`"
            ),
        }
    }
}

impl Error for DispatchError {}

#[derive(Debug, Default, Clone)]
pub struct Registry {
    commands: Vec<CommandSpec>,
    flags: Vec<FlagSpec>,
    params: Vec<ParamSpec>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_command(&mut self, command: CommandSpec) {
        self.commands.push(command);
    }

    pub fn add_flag(&mut self, flag: FlagSpec) {
        self.flags.push(flag);
    }

    pub fn add_param(&mut self, param: ParamSpec) {
        self.params.push(param);
    }

    pub fn commands(&self) -> &[CommandSpec] {
        &self.commands
    }
    pub fn flags(&self) -> &[FlagSpec] {
        &self.flags
    }
    pub fn params(&self) -> &[ParamSpec] {
        &self.params
    }

    pub fn command_for(&self, token: &str) -> Option<&CommandSpec> {
        self.commands
            .iter()
            .find(|command| command.name == token || command.aliases.contains(&token))
    }

    pub fn command_named(&self, name: &str) -> Option<&CommandSpec> {
        self.commands.iter().find(|command| command.name == name)
    }

    pub fn subcommand_for<'a>(
        &'a self,
        command: &'a CommandSpec,
        token: &str,
    ) -> Option<&'a SubcommandSpec> {
        command
            .subcommands
            .iter()
            .find(|subcommand| subcommand.name == token || subcommand.aliases.contains(&token))
    }

    pub fn subcommand_named<'a>(
        &'a self,
        command: &'a CommandSpec,
        name: &str,
    ) -> Option<&'a SubcommandSpec> {
        command
            .subcommands
            .iter()
            .find(|subcommand| subcommand.name == name)
    }

    /// Dispatches using the same command/subcommand selection used by the
    /// in-tree Deka core: the first command selects a handler and an optional
    /// second command selects its subcommand handler.
    pub fn dispatch(&self, context: &Context) -> Result<(), DispatchError> {
        let commands = &context.args.commands;
        let Some(command_name) = commands.first() else {
            return Err(DispatchError::MissingCommand);
        };
        if commands.len() > 2 {
            return Err(DispatchError::TooManyCommands);
        }
        let command = self
            .command_named(command_name)
            .ok_or_else(|| DispatchError::UnknownCommand(command_name.clone()))?;
        if let Some(subcommand_name) = commands.get(1) {
            let subcommand = self
                .subcommand_named(command, subcommand_name)
                .ok_or_else(|| DispatchError::UnknownSubcommand {
                    command: command_name.clone(),
                    subcommand: subcommand_name.clone(),
                })?;
            (subcommand.handler)(context);
        } else {
            (command.handler)(context);
        }
        Ok(())
    }

    pub fn suggestion_tokens(&self) -> Vec<String> {
        let mut tokens = Vec::new();
        for command in &self.commands {
            tokens.push(command.name.to_string());
            for alias in command.aliases {
                tokens.push(alias.to_string());
            }
            for subcommand in command.subcommands {
                tokens.push(subcommand.name.to_string());
                for alias in subcommand.aliases {
                    tokens.push(alias.to_string());
                }
            }
        }
        for flag in &self.flags {
            tokens.push(flag.name.to_string());
            for alias in flag.aliases {
                tokens.push(alias.to_string());
            }
        }
        for param in &self.params {
            tokens.push(param.name.to_string());
        }
        tokens
    }
}

fn looks_like_path(token: &str) -> bool {
    token.contains('/')
        || token.contains('\\')
        || token.ends_with(".ds")
        || token.ends_with(".dsx")
        || token.starts_with("./")
        || token.starts_with("../")
}

fn suggest(token: &str, candidates: &[String]) -> Vec<String> {
    let threshold = if token.len() <= 4 {
        1
    } else if token.len() <= 7 {
        2
    } else {
        3
    };
    let mut scored: Vec<(usize, &String)> = candidates
        .iter()
        .map(|candidate| (levenshtein(token, candidate), candidate))
        .collect();
    scored.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(right.1)));
    scored
        .into_iter()
        .filter(|(distance, _)| *distance <= threshold)
        .take(3)
        .map(|(_, candidate)| candidate.clone())
        .collect()
}

fn levenshtein(a: &str, b: &str) -> usize {
    if a.is_empty() {
        return b.chars().count();
    }
    if b.is_empty() {
        return a.chars().count();
    }
    let b_len = b.chars().count();
    let mut previous: Vec<usize> = (0..=b_len).collect();
    let mut current = vec![0; b_len + 1];
    for (i, a_char) in a.chars().enumerate() {
        current[0] = i + 1;
        for (j, b_char) in b.chars().enumerate() {
            let cost = usize::from(a_char != b_char);
            current[j + 1] = current[j].min(previous[j + 1]).min(previous[j] + cost);
        }
        previous.clone_from_slice(&current);
    }
    previous[b_len]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    static HANDLER_RAN: AtomicBool = AtomicBool::new(false);

    fn handler(_context: &Context) {
        HANDLER_RAN.store(true, Ordering::SeqCst);
    }

    fn command(name: &'static str, owner: &'static str) -> CommandSpec {
        CommandSpec {
            name,
            owner,
            category: "test",
            summary: "test command",
            aliases: &[],
            subcommands: &[],
            handler,
        }
    }

    fn security_registry() -> Registry {
        RegistryBuilder::new()
            .flags([
                FlagSpec {
                    name: "--allow-read",
                    aliases: &[],
                    description: "allow filesystem reads",
                },
                FlagSpec {
                    name: "--deny-read",
                    aliases: &[],
                    description: "deny filesystem reads",
                },
                FlagSpec {
                    name: "--allow-net",
                    aliases: &[],
                    description: "allow network",
                },
                FlagSpec {
                    name: "--verbose",
                    aliases: &[],
                    description: "verbose",
                },
            ])
            .build()
            .expect("security registry builds")
    }

    #[test]
    fn parses_bare_allow_read_flag() {
        let parsed = Args::collect(vec!["--allow-read".to_string()], &security_registry());
        assert!(parsed.errors.is_empty());
        assert_eq!(parsed.args.flags.get("--allow-read"), Some(&true));
        assert!(!parsed.args.params.contains_key("--allow-read"));
    }

    #[test]
    fn parses_allow_read_equals_list() {
        let parsed = Args::collect(
            vec!["--allow-read=./src,./data".to_string()],
            &security_registry(),
        );
        assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
        assert_eq!(parsed.args.flags.get("--allow-read"), Some(&true));
        assert_eq!(
            parsed.args.params.get("--allow-read").map(String::as_str),
            Some("./src,./data")
        );
    }

    #[test]
    fn parses_deny_read_equals_path() {
        let parsed = Args::collect(vec!["--deny-read=/etc".to_string()], &security_registry());
        assert!(parsed.errors.is_empty());
        assert_eq!(
            parsed.args.params.get("--deny-read").map(String::as_str),
            Some("/etc")
        );
    }

    #[test]
    fn path_tokens_without_command_are_positionals() {
        let parsed = Args::collect(vec!["app/main.ds".to_string()], &security_registry());
        assert!(parsed.errors.is_empty(), "{:?}", parsed.errors);
        assert_eq!(parsed.args.positionals, vec!["app/main.ds"]);
    }

    #[test]
    fn unknown_flags_without_command_still_error() {
        let parsed = Args::collect(vec!["--not-a-real-flag".to_string()], &security_registry());
        assert!(!parsed.errors.is_empty());
        assert!(parsed.args.positionals.is_empty());
    }

    #[test]
    fn inherit_and_register_collision_is_a_build_error() {
        let error = RegistryBuilder::new()
            .inherit([command("install", "old-owner")])
            .register([command("install", "pm")])
            .build()
            .expect_err("collisions must fail");
        assert!(matches!(error, BuildError::DuplicateCommand { .. }));
    }

    #[test]
    fn inherit_only_works_and_tags_commands_legacy() {
        let registry = RegistryBuilder::new()
            .inherit([command("install", "old-owner")])
            .build()
            .expect("inherited commands build");
        assert_eq!(registry.commands()[0].owner, "legacy");
    }

    #[test]
    fn register_only_works() {
        let registry = RegistryBuilder::new()
            .register([command("install", "pm")])
            .build()
            .expect("owned command builds");
        assert_eq!(registry.commands()[0].owner, "pm");
    }

    #[test]
    fn owner_command_dispatches_its_handler() {
        HANDLER_RAN.store(false, Ordering::SeqCst);
        let registry = RegistryBuilder::new()
            .register([command("install", "pm")])
            .build()
            .expect("owned command builds");
        let parsed = Args::collect(vec!["install".to_string()], &registry);
        registry
            .dispatch(&Context::new(parsed.args))
            .expect("registered command dispatches");
        assert!(HANDLER_RAN.load(Ordering::SeqCst));
    }

    #[test]
    fn non_legacy_commands_require_an_owner() {
        let error = RegistryBuilder::new()
            .register([command("install", "")])
            .build()
            .expect_err("owner is required");
        assert!(matches!(error, BuildError::MissingOwner { .. }));
    }
}
