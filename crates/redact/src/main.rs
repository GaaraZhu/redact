use clap::{Parser, Subcommand};

mod command;
mod config_cmd;
mod enable_disable;
mod hook;
mod init;
mod list;
mod run;
mod starter;
mod validate;

#[derive(Parser)]
#[command(
    name = "redact",
    version,
    about = "PII-filtering proxy for AI agent query tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// PreToolUse hook: rewrite matching Bash commands to route through redact run
    Hook,
    /// Execute a tool with Gate 1 + Gate 2 PII redaction on its JSON output
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Register the PreToolUse hook in the agent harness settings
    Init {
        /// Target harness (currently only claude-code is supported)
        #[arg(long, default_value = "claude-code")]
        harness: String,
    },
    /// Manage the redact config file
    Config {
        /// Print the resolved config file path and exit
        #[arg(long)]
        path: bool,
        /// Print the raw config file contents and exit
        #[arg(long)]
        print: bool,
        /// Write a starter config if missing, then exit (no editor)
        #[arg(long = "init-only")]
        init_only: bool,
    },
    /// List configured tools and their sql_arg values
    List,
    /// Load config, compile patterns, and report errors or warnings
    Validate,
    /// Enable PII redaction (sets enabled: true in config)
    Enable,
    /// Disable PII redaction (sets enabled: false in config)
    Disable,
    /// Print version
    Version,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hook => hook::run(),
        Commands::Run { args } => run::run(args),
        Commands::Init { harness } => init::run(&harness),
        Commands::Config {
            path,
            print,
            init_only,
        } => config_cmd::run(path, print, init_only),
        Commands::List => list::run(),
        Commands::Validate => validate::run(),
        Commands::Enable => enable_disable::run(true),
        Commands::Disable => enable_disable::run(false),
        Commands::Version => println!("{}", env!("CARGO_PKG_VERSION")),
    }
}
