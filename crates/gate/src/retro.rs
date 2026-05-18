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

#[derive(Default)]
struct Summary {
    queries: usize,
    queries_with_pii: usize,
    fields_redacted: usize,
    type_counts: HashMap<String, usize>,
    malformed: usize,
}

impl Summary {
    fn add(&mut self, ev: Event) {
        self.queries += 1;
        if ev.fields_redacted > 0 {
            self.queries_with_pii += 1;
        }
        self.fields_redacted += ev.fields_redacted;
        for (k, v) in ev.types {
            *self.type_counts.entry(k).or_insert(0) += v;
        }
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
    println!("{}", "─".repeat(44));
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

    println!("Queries protected:  {:>6}", s.queries);
    println!("Queries with PII:   {:>6}", s.queries_with_pii);
    println!("PII fields redacted:{:>6}", s.fields_redacted);
    println!();
    println!("Hit rate:  {}  {:.1}%", bar, hit_pct);
    println!();

    if !s.type_counts.is_empty() {
        let mut by_count: Vec<(&String, &usize)> = s.type_counts.iter().collect();
        by_count.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let name_width = by_count
            .iter()
            .map(|(n, _)| n.len())
            .max()
            .unwrap_or(0)
            .max(20); // matches summary label column width

        println!("\x1b[1;96mTop Categories\x1b[0m");
        println!("{}", "─".repeat(44));
        for (name, count) in by_count.iter().take(10) {
            println!("{:<name_width$}{:>6}", name, count, name_width = name_width);
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
    fn summary_starts_empty() {
        let s = Summary::default();
        assert_eq!(s.queries, 0);
        assert_eq!(s.fields_redacted, 0);
        assert!(s.type_counts.is_empty());
        assert_eq!(s.malformed, 0);
    }
}
