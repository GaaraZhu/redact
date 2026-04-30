use clap::{Parser, Subcommand};

mod hook;
mod redactor;
mod run;

#[derive(Parser)]
#[command(
    name = "redact",
    about = "PII-filtering proxy for AI agent query tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// PreToolUse hook: rewrite matching commands to route through redact run
    Hook,
    /// Execute a tool with Gate 2 PII redaction on its JSON output
    Run {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Hook => hook::run(),
        Commands::Run { args } => run::run(args),
    }
}
