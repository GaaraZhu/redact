pub fn is_agent_harness() -> bool {
    ["CLAUDECODE", "OPENCODE", "COPILOT_CLI", "COPILOT_RUN_APP"]
        .iter()
        .any(|var| std::env::var(var).is_ok())
}
