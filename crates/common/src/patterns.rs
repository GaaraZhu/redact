use regex::Regex;

pub const COLUMN_DENYLIST: &[&str] = &[
    "email",
    "ssn",
    "dob",
    "phone",
    "npi",
    "credit_card",
    "card_number",
    "cvv",
    "passport",
    "license_number",
    "full_name",
    "first_name",
    "last_name",
    "birthdate",
];

pub struct BuiltinPattern {
    pub name: &'static str,
    pub regex: &'static str,
    pub confidence: f32,
}

pub const BUILTIN_PATTERNS: &[BuiltinPattern] = &[
    BuiltinPattern {
        name: "email",
        regex: r"(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b",
        confidence: 0.85,
    },
    BuiltinPattern {
        name: "ssn",
        regex: r"\b\d{3}-\d{2}-\d{4}\b",
        confidence: 0.95,
    },
    BuiltinPattern {
        name: "phone",
        regex: r"\b(\+?1[\s.-]?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
        confidence: 0.75,
    },
    BuiltinPattern {
        name: "credit_card",
        regex: r"\b(?:\d[ -]?){13,16}\b",
        confidence: 0.7,
    },
];

pub struct CompiledPattern {
    pub name: String,
    pub regex: Regex,
    pub confidence: f32,
}

impl CompiledPattern {
    pub fn from_builtins() -> Vec<Self> {
        BUILTIN_PATTERNS
            .iter()
            .map(|p| CompiledPattern {
                name: p.name.to_string(),
                regex: Regex::new(p.regex).expect("builtin regex is valid"),
                confidence: p.confidence,
            })
            .collect()
    }
}

pub struct Luhn;

impl Luhn {
    pub fn check(s: &str) -> bool {
        let digits: Vec<u32> = s
            .chars()
            .filter(|c| c.is_ascii_digit())
            .filter_map(|c| c.to_digit(10))
            .collect();
        if digits.len() < 13 || digits.len() > 19 {
            return false;
        }
        let sum: u32 = digits
            .iter()
            .rev()
            .enumerate()
            .map(|(i, &d)| {
                if i % 2 == 1 {
                    let v = d * 2;
                    if v > 9 {
                        v - 9
                    } else {
                        v
                    }
                } else {
                    d
                }
            })
            .sum();
        sum.is_multiple_of(10)
    }
}
