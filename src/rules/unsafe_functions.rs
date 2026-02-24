use crate::config::Config;
use crate::diagnostics::{Category, Diagnostic, Severity};
use crate::rules::Rule;
use regex::Regex;
use std::collections::HashMap;
use std::path::Path;

pub struct UnsafeFunctionsRule;

// Safe alternatives for common unsafe functions
fn safe_alternatives() -> HashMap<&'static str, &'static str> {
    let mut m = HashMap::new();
    m.insert("gets", "fgets()");
    m.insert("strcpy", "strncpy() or strlcpy()");
    m.insert("strcat", "strncat() or strlcat()");
    m.insert("sprintf", "snprintf()");
    m.insert("vsprintf", "vsnprintf()");
    m.insert("scanf", "fgets() + sscanf() with width specifiers");
    m.insert("sscanf", "sscanf() with width specifiers");
    m.insert("fscanf", "fgets() + parsing");
    m.insert("tmpnam", "mkstemp()");
    m.insert("mktemp", "mkstemp()");
    m.insert("getpw", "getpwuid_r()");
    m.insert("getlogin", "getlogin_r()");
    m.insert("atoi", "strtol() with error checking");
    m.insert("atof", "strtod() with error checking");
    m.insert("atol", "strtol() with error checking");
    m.insert("realloc", "realloc() with NULL check (ensure old pointer is preserved)");
    m
}

impl Rule for UnsafeFunctionsRule {
    fn check(&self, path: &Path, content: &str, config: &Config) -> Vec<Diagnostic> {
        if !config.unsafe_functions.enabled {
            return vec![];
        }

        let mut diagnostics = vec![];
        let banned = config.all_banned_functions();
        let alternatives = safe_alternatives();

        for (line_num, line) in content.lines().enumerate() {
            let line_num = line_num + 1;
            let trimmed = line.trim();

            // Skip comments and preprocessor directives
            if trimmed.starts_with("//") || trimmed.starts_with('#') || trimmed.starts_with('*') {
                continue;
            }

            for func_name in &banned {
                // Match function calls: func_name followed by '('
                let pattern = format!(r"\b{}\s*\(", regex::escape(func_name));
                if let Ok(re) = Regex::new(&pattern) {
                    if let Some(m) = re.find(line) {
                        let col = m.start() + 1;
                        let suggestion = alternatives
                            .get(func_name.as_str())
                            .map(|s| format!(". Use {} instead", s))
                            .unwrap_or_default();

                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            Some(col),
                            Severity::Error,
                            Category::UnsafeFunction,
                            "banned-function",
                            &format!(
                                "'{}' is banned as unsafe{}",
                                func_name, suggestion
                            ),
                        ));
                    }
                }
            }
        }

        diagnostics
    }
}
