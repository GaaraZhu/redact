const HARNESS_VARS: &[&str] = &[
    "CLAUDECODE",
    "OPENCODE",
    "COPILOT_CLI",
    "COPILOT_RUN_APP",
    "CURSOR_AGENT",
    "CURSOR_TRACE_ID",
];

pub fn is_agent_harness() -> bool {
    HARNESS_VARS.iter().any(|var| std::env::var(var).is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static LOCK: Mutex<()> = Mutex::new(());

    fn with_only_var<F: FnOnce() -> bool>(var: &str, f: F) -> bool {
        let _guard = LOCK.lock().unwrap();
        let saved: Vec<Option<String>> =
            HARNESS_VARS.iter().map(|v| std::env::var(v).ok()).collect();
        for v in HARNESS_VARS {
            unsafe { std::env::remove_var(v) };
        }
        unsafe { std::env::set_var(var, "1") };
        let result = f();
        // restore
        for (v, val) in HARNESS_VARS.iter().zip(saved.iter()) {
            match val {
                Some(s) => unsafe { std::env::set_var(v, s) },
                None => unsafe { std::env::remove_var(v) },
            }
        }
        result
    }

    fn with_no_vars<F: FnOnce() -> bool>(f: F) -> bool {
        let _guard = LOCK.lock().unwrap();
        let saved: Vec<Option<String>> =
            HARNESS_VARS.iter().map(|v| std::env::var(v).ok()).collect();
        for v in HARNESS_VARS {
            unsafe { std::env::remove_var(v) };
        }
        let result = f();
        for (v, val) in HARNESS_VARS.iter().zip(saved.iter()) {
            match val {
                Some(s) => unsafe { std::env::set_var(v, s) },
                None => unsafe { std::env::remove_var(v) },
            }
        }
        result
    }

    #[test]
    fn false_when_no_harness_vars_set() {
        assert!(!with_no_vars(is_agent_harness));
    }

    #[test]
    fn claudecode_detected() {
        assert!(with_only_var("CLAUDECODE", is_agent_harness));
    }

    #[test]
    fn opencode_detected() {
        assert!(with_only_var("OPENCODE", is_agent_harness));
    }

    #[test]
    fn copilot_cli_detected() {
        assert!(with_only_var("COPILOT_CLI", is_agent_harness));
    }

    #[test]
    fn copilot_run_app_detected() {
        assert!(with_only_var("COPILOT_RUN_APP", is_agent_harness));
    }

    #[test]
    fn cursor_agent_detected() {
        assert!(with_only_var("CURSOR_AGENT", is_agent_harness));
    }

    #[test]
    fn cursor_trace_id_detected() {
        assert!(with_only_var("CURSOR_TRACE_ID", is_agent_harness));
    }
}
