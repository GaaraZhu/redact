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
    /// Register the PreToolUse hook in the agent harness settings.
    /// With --mcp, registers a gate mcp proxy entry for an MCP server instead.
    Init {
        /// Target harness: claude-code (default) or opencode
        #[arg(long, default_value = "claude-code")]
        harness: String,
        /// Installation scope: global/user (default) or project
        #[arg(long, default_value = "global")]
        scope: String,
        /// Name of the MCP server to register (e.g. "postgres")
        #[arg(long)]
        mcp: Option<String>,
        /// Upstream MCP server command string (used with --mcp), e.g. "uvx mcp-server-postgres"
        #[arg(long = "mcp-cmd")]
        mcp_cmd: Option<String>,
        /// Convert all existing MCP servers in the harness config to gate mcp proxies (dry-run by default)
        #[arg(long = "wrap-mcp")]
        wrap_mcp: bool,
        /// Comma-separated list of server names to wrap (used with --wrap-mcp; default wraps all)
        #[arg(long)]
        servers: Option<String>,
        /// Apply changes (used with --wrap-mcp; default is dry-run)
        #[arg(long)]
        yes: bool,
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
        /// Emit results as JSON instead of human-readable text
        #[arg(long)]
        json: bool,
    },
    /// Run a stdio MCP proxy: intercepts tools/call responses and redacts PII.
    /// Usage: gate mcp [--] <upstream-cmd> [args...]
    /// Example: gate mcp -- uvx mcp-server-postgres
    Mcp {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        upstream: Vec<String>,
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
        Commands::Init {
            harness,
            scope,
            mcp,
            mcp_cmd,
            wrap_mcp,
            servers,
            yes,
        } => init::run(
            &harness,
            &scope,
            mcp.as_deref(),
            mcp_cmd.as_deref(),
            wrap_mcp,
            servers.as_deref(),
            yes,
        ),
        Commands::Config {
            path,
            print,
            init_only,
        } => config_cmd::run(path, print, init_only),
        Commands::List => list::run(),
        Commands::Scan { verbose, json } => scan::run(verbose, json),
        Commands::Mcp { upstream } => {
            // Strip a leading "--" separator if clap passed it through
            let upstream = if upstream.first().map(String::as_str) == Some("--") {
                upstream[1..].to_vec()
            } else {
                upstream
            };
            mcp::run(upstream)
        }
        Commands::Validate => validate::run(),
        Commands::Enable => enable_disable::run(true),
        Commands::Disable => enable_disable::run(false),
        Commands::Uninstall => uninstall::run(),
        Commands::Version => println!("{}", env!("CARGO_PKG_VERSION")),
    }
}
