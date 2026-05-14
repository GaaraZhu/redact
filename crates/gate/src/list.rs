use common::config::Config;
use common::error::exit_with_error;

const RAW_CLIENTS: &[&str] = &["mysql", "psql", "databricks"];
const TOOLKIT_TOOLS: &[&str] = &["tkpsql", "tkdbr"];

pub fn run() {
    let config = Config::load().unwrap_or_else(|e| {
        exit_with_error(&format!(
            "failed to load config: {e}. Run `gate config --init-only` to create a starter config."
        ));
    });

    if config.tools.is_empty() {
        println!("No tools configured. Run `gate config` to add tools.");
        return;
    }

    let mut tools: Vec<(&String, &common::config::ToolConfig)> = config.tools.iter().collect();
    tools.sort_by_key(|(name, _)| name.as_str());

    println!("{:<20} {:<14} NOTE", "TOOL", "SQL_ARG");
    println!("{}", "-".repeat(64));
    for (name, tool) in tools {
        let sql_arg = tool.sql_arg.as_deref().unwrap_or("(none)");
        let note = if TOOLKIT_TOOLS.contains(&name.as_str()) {
            "(toolkit-managed)"
        } else if RAW_CLIENTS.contains(&name.as_str()) {
            "(raw client — credentials reachable to AI)"
        } else {
            ""
        };
        println!("{:<20} {:<14} {}", name, sql_arg, note);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn raw_clients_constant_contains_mysql_psql_databricks() {
        assert!(RAW_CLIENTS.contains(&"mysql"));
        assert!(RAW_CLIENTS.contains(&"psql"));
        assert!(RAW_CLIENTS.contains(&"databricks"));
    }

    #[test]
    fn toolkit_tools_constant_contains_tkpsql_tkdbr() {
        assert!(TOOLKIT_TOOLS.contains(&"tkpsql"));
        assert!(TOOLKIT_TOOLS.contains(&"tkdbr"));
    }
}
