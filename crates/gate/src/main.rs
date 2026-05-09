use clap::{Parser, Subcommand};

mod command;
mod config_cmd;
mod enable_disable;
mod hook;
mod init;
mod init_opencode;
mod list;
mod run;
mod scan;
mod starter;
mod uninstall;
mod validate;

#[derive(Parser)]
#[command(
    name = "gate",
    version,
    about = "PII-filtering proxy for AI agent query tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// PreToolUse hook: rewrite matching Bash commands to route through gate run
    Hook,
    /// Execute a tool with Gate 1 + Gate 2 PII redaction on its JSON output.
    /// With no args, reads JSON from stdin and applies Gate 2 directly.
    Run {
        /// Print per-field redaction decisions to stderr for debugging
        #[arg(long)]
        verbose: bool,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Register the PreToolUse hook in the agent harness settings
    Init {
        /// Target harness: claude-code (default) or opencode
        #[arg(long, default_value = "claude-code")]
        harness: String,
        /// Installation scope for opencode: global (default) or project
        #[arg(long, default_value = "global")]
        scope: String,
    },
    /// Manage the gate config file
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
    /// Read columnar JSON from stdin and report PII-exposed column names.
    /// Pipe the output of a schema query (SELECT TABLE_NAME, COLUMN_NAME ...) into this command.
    /// Example: tkdbr query --sql "SELECT TABLE_NAME, COLUMN_NAME FROM ..." | gate scan
    Scan {
        /// Show all detected columns in the Top Findings section (not truncated)
        #[arg(long)]
        verbose: bool,
    },
    /// Load config, compile patterns, and report errors or warnings
    Validate,
    /// Enable PII redaction (sets enabled: true in config)
    Enable,
    /// Disable PII redaction (sets enabled: false in config)
    Disable,
    /// Remove the hook, config directory, and any gate-generated opencode plugins
    Uninstall,
    /// Print version
    Version,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hook => hook::run(),
        Commands::Run { verbose, args } => run::run(args, verbose),
        Commands::Init { harness, scope } => init::run(&harness, &scope),
        Commands::Config {
            path,
            print,
            init_only,
        } => config_cmd::run(path, print, init_only),
        Commands::List => list::run(),
        Commands::Scan { verbose } => scan::run(verbose),
        Commands::Validate => validate::run(),
        Commands::Enable => enable_disable::run(true),
        Commands::Disable => enable_disable::run(false),
        Commands::Uninstall => uninstall::run(),
        Commands::Version => println!("{}", env!("CARGO_PKG_VERSION")),
    }
}
