//! `gate retro` — protection retrospective.
//!
//! Reads the JSONL stats log and prints three numbers plus a top-categories
//! breakdown. Lines that fail to parse are skipped with a warning so a
//! crash-truncated last line doesn't kill the whole report.
//!
//! Synonym keywords: `stats`, `audit`, `report` (referenced in the clap
//! help text so people grepping `--help` find this command).

use common::config::Config;
use common::patterns::map_to_tier1_category;
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
    /// Per-query gate overhead in microseconds. Only events that carry a
    /// recorded timing (`overhead_us > 0`) are collected; legacy events
    /// written before the field existed read as 0 and are skipped so they
    /// don't pull the percentiles toward zero.
    overhead_us: Vec<u64>,
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
        if ev.overhead_us > 0 {
            self.overhead_us.push(ev.overhead_us);
        }
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

/// Nearest-rank percentile (`p` in 0.0..=100.0) over `sorted` (ascending).
/// Returns `None` for an empty slice.
fn percentile(sorted: &[u64], p: f64) -> Option<u64> {
    if sorted.is_empty() {
        return None;
    }
    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(sorted.len() - 1);
    Some(sorted[idx])
}

// All separators and table rows render to this width.
const TABLE_WIDTH: usize = 100;
const TOOL_COL: usize = 25; // For Tool Breakdown section

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
    let (hdr, reset, dim) = if crate::color::supports_color() {
        ("\x1b[1;96m", "\x1b[0m", "\x1b[2m")
    } else {
        ("", "", "")
    };
    println!();
    println!("{hdr}Gate Retro — all time{reset}");
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

    if !s.overhead_us.is_empty() {
        let mut sorted = s.overhead_us.clone();
        sorted.sort_unstable();
        let ms = |us: u64| us as f64 / 1000.0;
        let p50 = percentile(&sorted, 50.0).unwrap();
        let p95 = percentile(&sorted, 95.0).unwrap();
        let p99 = percentile(&sorted, 99.0).unwrap();
        let slowest = *sorted.last().unwrap();

        println!("{hdr}Gate Overhead — added latency per query{reset}");
        println!("{}", "─".repeat(TABLE_WIDTH));
        println!("{:<TOOL_COL$}  {:>21.2} ms", "Median (p50):", ms(p50));
        println!("{:<TOOL_COL$}  {:>21.2} ms", "p95:", ms(p95));
        println!("{:<TOOL_COL$}  {:>21.2} ms", "p99:", ms(p99));
        println!("{:<TOOL_COL$}  {:>21.2} ms", "Slowest:", ms(slowest));
        println!();
        println!(
            "{dim}Gate added a median of {:.2} ms per query (n={}). \
             The wrapped tool's own runtime is not counted.{reset}",
            ms(p50),
            sorted.len(),
        );
        println!();
    }

    if !s.tool_stats.is_empty() {
        let mut rows: Vec<(&String, &ToolStat)> = s.tool_stats.iter().collect();
        rows.sort_by(|a, b| b.1.queries.cmp(&a.1.queries).then(a.0.cmp(b.0)));

        const H_PROT: &str = "Queries protected";
        const H_PII: &str = "Queries with PII";
        const H_HR: &str = "Hit rate";

        println!("{hdr}Tool Breakdown{reset}");
        println!("{}", "─".repeat(TABLE_WIDTH));
        println!(
            "{:<TOOL_COL$}  {:>25}  {:>25}  {:>12}",
            "Tool", H_PROT, H_PII, H_HR,
        );
        println!("{}", "─".repeat(TABLE_WIDTH));
        for (name, stat) in &rows {
            let hit_rate = format!(
                "{:.1}%",
                (stat.queries_with_pii as f64 / stat.queries as f64) * 100.0
            );
            println!(
                "{:<TOOL_COL$}  {:>25}  {:>25}  {:>12}",
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

        let mut grouped: HashMap<&str, Vec<(&String, &usize)>> = HashMap::new();
        for (name, count) in &by_count {
            let tier1 = map_to_tier1_category(name);
            grouped.entry(tier1).or_default().push((name, count));
        }

        let mut tier1_sorted: Vec<&str> = grouped.keys().copied().collect();
        tier1_sorted.sort_by_key(|tier1| grouped[tier1].iter().map(|(_, c)| *c).sum::<usize>());
        tier1_sorted.reverse();

        const H_CAT: &str = "Category";
        const H_SUBCAT: &str = "Sub Category";
        const H_REDACTED: &str = "PII fields redacted";
        const H_PCT: &str = "Percentage";

        println!("{hdr}PII Breakdown{reset}");
        println!("{}", "─".repeat(TABLE_WIDTH));
        println!(
            "{:<24}  {:<22}  {:>20}        {:>16}",
            H_CAT, H_SUBCAT, H_REDACTED, H_PCT,
        );
        println!("{}", "─".repeat(TABLE_WIDTH));

        let mut row_count = 0;
        for tier1 in tier1_sorted {
            let items = &grouped[tier1];
            for (i, (name, count)) in items.iter().enumerate() {
                if row_count >= 10 {
                    break;
                }
                let pct = if total_redacted > 0 {
                    (**count as f64 / total_redacted as f64) * 100.0
                } else {
                    0.0
                };
                let cat_display = if i == 0 { tier1 } else { "" };
                println!(
                    "{:<24}  {:<22}  {:>20}        {:>15.1}%",
                    cat_display,
                    truncate_to(name, 22),
                    count,
                    pct,
                );
                row_count += 1;
            }
            if row_count >= 10 {
                break;
            }
        }
        println!();
    }

    println!(
        "{dim}{} sensitive fields never reached the model.{reset}",
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
            overhead_us: 0,
            types: m,
        }
    }

    fn ev_timed(tool: &str, fields: usize, overhead_us: u64) -> Event {
        Event {
            ts: 0,
            path: "bash".to_string(),
            tool: tool.to_string(),
            fields_redacted: fields,
            overhead_us,
            types: HashMap::new(),
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
        assert!(s.overhead_us.is_empty());
        assert_eq!(s.malformed, 0);
    }

    #[test]
    fn summary_collects_only_nonzero_overhead() {
        let mut s = Summary::default();
        s.add(ev_timed("tkpsql", 1, 500));
        s.add(ev_timed("tkpsql", 0, 0)); // legacy event: no timing recorded
        s.add(ev_timed("tkpsql", 2, 1500));
        assert_eq!(s.overhead_us, vec![500, 1500]);
    }

    #[test]
    fn percentile_nearest_rank() {
        let sorted: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&sorted, 50.0), Some(50));
        assert_eq!(percentile(&sorted, 95.0), Some(95));
        assert_eq!(percentile(&sorted, 99.0), Some(99));
        assert_eq!(percentile(&sorted, 100.0), Some(100));
    }

    #[test]
    fn percentile_empty_is_none() {
        assert_eq!(percentile(&[], 50.0), None);
    }

    #[test]
    fn percentile_single_sample() {
        assert_eq!(percentile(&[42], 50.0), Some(42));
        assert_eq!(percentile(&[42], 99.0), Some(42));
    }
}
