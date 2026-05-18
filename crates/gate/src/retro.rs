//! `gate retro` — protection retrospective.
//!
//! Reads the JSONL stats log and prints three numbers plus a top-categories
//! breakdown. Lines that fail to parse are skipped with a warning so a
//! crash-truncated last line doesn't kill the whole report.
//!
//! Synonym keywords: `stats`, `audit`, `report` (referenced in the clap
//! help text so people grepping `--help` find this command).

use common::config::Config;
use common::stats::{stats_path, Event};
use std::collections::HashMap;
use std::io::{BufRead, BufReader};

pub fn run() {
    let config = Config::load().unwrap_or_default();
    if !config.stats.enabled {
        println!(
            "Stats collection is disabled in config. Set `stats.enabled: true` \
             in your gate config to enable it."
        );
        return;
    }

    let path = match stats_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[gate retro] cannot resolve stats path: {e}");
            return;
        }
    };

    if !path.exists() {
        print_empty();
        return;
    }

    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[gate retro] cannot read {}: {e}", path.display());
            return;
        }
    };

    let mut summary = Summary::default();
    for line in BufReader::new(file).lines().map_while(Result::ok) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        match serde_json::from_str::<Event>(trimmed) {
            Ok(ev) => summary.add(ev),
            Err(_) => summary.malformed += 1,
        }
    }

    if summary.queries == 0 {
        print_empty();
        return;
    }

    print_report(&summary);
}

#[derive(Default, Debug, PartialEq)]
struct ToolStat {
    queries: usize,
    queries_with_pii: usize,
}

#[derive(Default)]
struct Summary {
    queries: usize,
    queries_with_pii: usize,
    fields_redacted: usize,
    type_counts: HashMap<String, usize>,
    tool_stats: HashMap<String, ToolStat>,
    malformed: usize,
}

impl Summary {
    fn add(&mut self, ev: Event) {
        self.queries += 1;
        let has_pii = ev.fields_redacted > 0;
        if has_pii {
            self.queries_with_pii += 1;
        }
        self.fields_redacted += ev.fields_redacted;
        let stat = self.tool_stats.entry(ev.tool).or_default();
        stat.queries += 1;
        if has_pii {
            stat.queries_with_pii += 1;
        }
        for (k, v) in ev.types {
            *self.type_counts.entry(k).or_insert(0) += v;
        }
    }
}

// All separators and table rows render to this width.
// Top Tools columns: TOOL_COL(25) + 2 + "Queries protected"(17) + 2 +
//                    "Queries with PII"(16) + 2 + "Hit rate"(8) = 72.
const TABLE_WIDTH: usize = 72;
const TOOL_COL: usize = 25; // TABLE_WIDTH - 47

fn truncate_to(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max.saturating_sub(3)])
    }
}

fn print_empty() {
    println!(
        "No protections recorded yet. Run a query through a configured tool \
         to see results here."
    );
}

fn print_report(s: &Summary) {
    println!();
    println!("\x1b[1;96mGate Retro — all time\x1b[0m");
    println!("{}", "─".repeat(TABLE_WIDTH));
    let hit_pct = if s.queries > 0 {
        (s.queries_with_pii as f64 / s.queries as f64) * 100.0
    } else {
        0.0
    };
    let bar_width = 24usize;
    let filled = ((hit_pct / 100.0) * bar_width as f64).round() as usize;
    let bar = format!(
        "{}{}",
        "█".repeat(filled.min(bar_width)),
        "░".repeat(bar_width - filled.min(bar_width))
    );

    println!("{:<TOOL_COL$}  {:>24}", "Queries protected:", s.queries);
    println!(
        "{:<TOOL_COL$}  {:>24}",
        "Queries with PII:", s.queries_with_pii
    );
    println!(
        "{:<TOOL_COL$}  {:>24}",
        "PII fields redacted:", s.fields_redacted
    );
    println!();
    println!("{:<TOOL_COL$}  {}    {:.1}%", "Hit rate:", bar, hit_pct);
    println!();

    if !s.tool_stats.is_empty() {
        let mut rows: Vec<(&String, &ToolStat)> = s.tool_stats.iter().collect();
        rows.sort_by(|a, b| b.1.queries.cmp(&a.1.queries).then(a.0.cmp(b.0)));

        const H_PROT: &str = "Queries protected";
        const H_PII: &str = "Queries with PII";
        const H_HR: &str = "Hit rate";

        println!("\x1b[1;96mTool Breakdown\x1b[0m");
        println!("{}", "─".repeat(TABLE_WIDTH));
        println!(
            "{:<TOOL_COL$}  {:>17}  {:>16}  {:>8}",
            "Tool", H_PROT, H_PII, H_HR,
        );
        println!("{}", "─".repeat(TABLE_WIDTH));
        for (name, stat) in &rows {
            let hit_rate = format!(
                "{:.1}%",
                (stat.queries_with_pii as f64 / stat.queries as f64) * 100.0
            );
            println!(
                "{:<TOOL_COL$}  {:>17}  {:>16}  {:>8}",
                truncate_to(name, TOOL_COL),
                stat.queries,
                stat.queries_with_pii,
                hit_rate,
            );
        }
        println!();
    }

    if !s.type_counts.is_empty() {
        let mut by_count: Vec<(&String, &usize)> = s.type_counts.iter().collect();
        by_count.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let total_redacted: usize = s.type_counts.values().sum();

        const H_CAT: &str = "Category";
        const H_REDACTED: &str = "PII fields redacted";
        const H_PCT: &str = "Percentage";

        println!("\x1b[1;96mPII Breakdown\x1b[0m");
        println!("{}", "─".repeat(TABLE_WIDTH));
        println!("{:<TOOL_COL$}  {:>20}  {:>23}", H_CAT, H_REDACTED, H_PCT,);
        println!("{}", "─".repeat(TABLE_WIDTH));
        for (name, count) in by_count.iter().take(10) {
            let pct = if total_redacted > 0 {
                (**count as f64 / total_redacted as f64) * 100.0
            } else {
                0.0
            };
            println!(
                "{:<TOOL_COL$}  {:>20}  {:>22.1}%",
                truncate_to(name, TOOL_COL),
                count,
                pct,
            );
        }
        println!();
    }

    println!(
        "\x1b[2m{} sensitive fields never reached the model.\x1b[0m",
        s.fields_redacted
    );
    println!();

    if s.malformed > 0 {
        eprintln!(
            "[gate retro] note: skipped {} malformed line(s) in stats log",
            s.malformed
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn ev(tool: &str, fields: usize, types: &[(&str, usize)]) -> Event {
        let mut m = HashMap::new();
        for (k, v) in types {
            m.insert(k.to_string(), *v);
        }
        Event {
            ts: 0,
            path: "bash".to_string(),
            tool: tool.to_string(),
            fields_redacted: fields,
            types: m,
        }
    }

    #[test]
    fn summary_aggregates_per_type_counts_across_events() {
        let mut s = Summary::default();
        s.add(ev("tkpsql", 5, &[("email", 3), ("ssn", 2)]));
        s.add(ev("tkpsql", 4, &[("email", 4)]));
        s.add(ev("postgres", 2, &[("phone", 2)]));
        assert_eq!(s.queries, 3);
        assert_eq!(s.queries_with_pii, 3);
        assert_eq!(s.fields_redacted, 11);
        assert_eq!(s.type_counts.get("email"), Some(&7));
        assert_eq!(s.type_counts.get("ssn"), Some(&2));
        assert_eq!(s.type_counts.get("phone"), Some(&2));
    }

    #[test]
    fn hit_rate_excludes_clean_queries() {
        let mut s = Summary::default();
        s.add(ev("tkpsql", 3, &[("email", 3)]));
        s.add(ev("tkpsql", 0, &[]));
        s.add(ev("tkpsql", 0, &[]));
        assert_eq!(s.queries, 3);
        assert_eq!(s.queries_with_pii, 1);
    }

    #[test]
    fn summary_counts_per_tool() {
        let mut s = Summary::default();
        s.add(ev("tkpsql", 3, &[("email", 3)]));
        s.add(ev("tkpsql", 0, &[]));
        s.add(ev("postgres", 1, &[("ssn", 1)]));
        assert_eq!(s.tool_stats.get("tkpsql").map(|t| t.queries), Some(2));
        assert_eq!(
            s.tool_stats.get("tkpsql").map(|t| t.queries_with_pii),
            Some(1)
        );
        assert_eq!(s.tool_stats.get("postgres").map(|t| t.queries), Some(1));
        assert_eq!(
            s.tool_stats.get("postgres").map(|t| t.queries_with_pii),
            Some(1)
        );
        assert_eq!(s.tool_stats.get("mcp"), None);
    }

    #[test]
    fn summary_starts_empty() {
        let s = Summary::default();
        assert_eq!(s.queries, 0);
        assert_eq!(s.fields_redacted, 0);
        assert!(s.type_counts.is_empty());
        assert_eq!(s.malformed, 0);
    }
}
