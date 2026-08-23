use crate::config::Config;
use crate::diagnostics::{Category, Diagnostic, Severity};
use crate::rules::semantics::analyze_pointer_semantics;
use crate::rules::Rule;
use regex::Regex;
use std::path::Path;

pub struct SecurityRule;

impl Rule for SecurityRule {
    fn check(&self, path: &Path, content: &str, config: &Config) -> Vec<Diagnostic> {
        if !config.security.enabled {
            return vec![];
        }

        let mut diagnostics = analyze_pointer_semantics(path, content, config);
        let fmt_re = Regex::new(
            r"\b(printf|fprintf|syslog|snprintf|sprintf)\s*\(\s*(?:[^,]+,\s*)?(\w+)\s*\)",
        )
        .unwrap();
        let fixed_buf_re = Regex::new(r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]").unwrap();
        let dangerous_re = Regex::new(r"\b(strcpy|strcat|memcpy)\s*\(").unwrap();
        let memcpy_re = Regex::new(r"\bmemcpy\s*\(\s*(\w+)").unwrap();
        let malloc_arith_re = Regex::new(r"\bmalloc\s*\(\s*\w+\s*[\*\+]\s*\w+").unwrap();
        let narrow_re =
            Regex::new(r"\b(short|char|uint8_t|int8_t|uint16_t|int16_t)\s+\w+\s*=\s*\w+\s*[\*\+\-]")
                .unwrap();
        let sys_re = Regex::new(r"\b(system|popen|exec[lv]p?e?)\s*\(").unwrap();
        let alloca_re = Regex::new(r"\balloca\s*\(").unwrap();
        let mut in_block_comment = false;

        for (idx, line) in content.lines().enumerate() {
            let line_num = idx + 1;
            let trimmed = line.trim();

            if in_block_comment {
                if trimmed.contains("*/") {
                    in_block_comment = false;
                }
                continue;
            }

            if trimmed.starts_with("/*") {
                if !trimmed.contains("*/") {
                    in_block_comment = true;
                }
                continue;
            }

            if trimmed.starts_with("//") {
                continue;
            }

            if config.security.check_format_strings {
                if let Some(caps) = fmt_re.captures(line) {
                    let func = caps.get(1).unwrap().as_str();
                    let arg = caps.get(2).unwrap().as_str();

                    if !arg.starts_with('"')
                        && arg != "stdout"
                        && arg != "stderr"
                        && arg != "stdin"
                    {
                        let full_call = &line[caps.get(0).unwrap().start()..];
                        if !full_call.contains('"') {
                            diagnostics.push(Diagnostic::new(
                                path,
                                line_num,
                                Some(caps.get(0).unwrap().start() + 1),
                                Severity::Error,
                                Category::Security,
                                "format-string",
                                &format!(
                                    "Potential format string vulnerability: '{}' called with non-literal format string",
                                    func
                                ),
                            ));
                        }
                    }
                }
            }

            if config.security.check_buffer_overflow {
                if fixed_buf_re.is_match(line) && dangerous_re.is_match(line) {
                    diagnostics.push(Diagnostic::new(
                        path,
                        line_num,
                        None,
                        Severity::Error,
                        Category::Security,
                        "buffer-overflow",
                        "Fixed-size buffer used with potentially unsafe copy operation on the same line",
                    ));
                }

                if let Some(caps) = memcpy_re.captures(line) {
                    if line.contains("strlen")
                        && !line.contains("+ 1")
                        && !line.contains("+1")
                    {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            Some(caps.get(0).unwrap().start() + 1),
                            Severity::Warning,
                            Category::Security,
                            "buffer-overflow",
                            "memcpy with strlen() may miss null terminator (consider +1)",
                        ));
                    }
                }
            }

            if config.security.check_integer_overflow {
                if malloc_arith_re.is_match(line) {
                    diagnostics.push(Diagnostic::new(
                        path,
                        line_num,
                        None,
                        Severity::Warning,
                        Category::Security,
                        "integer-overflow",
                        "Arithmetic in malloc() argument could overflow; consider overflow check",
                    ));
                }

                if narrow_re.is_match(line) {
                    diagnostics.push(Diagnostic::new(
                        path,
                        line_num,
                        None,
                        Severity::Warning,
                        Category::Security,
                        "integer-overflow",
                        "Possible narrowing conversion with arithmetic; verify no overflow",
                    ));
                }
            }

            if config.security.ban_system_calls {
                if let Some(caps) = sys_re.captures(line) {
                    let func = caps.get(1).unwrap().as_str();
                    diagnostics.push(Diagnostic::new(
                        path,
                        line_num,
                        Some(caps.get(0).unwrap().start() + 1),
                        Severity::Error,
                        Category::Security,
                        "system-call",
                        &format!(
                            "'{}()' can be exploited for command injection; use safer alternatives",
                            func
                        ),
                    ));
                }
            }

            if alloca_re.is_match(line) {
                diagnostics.push(Diagnostic::new(
                    path,
                    line_num,
                    None,
                    Severity::Warning,
                    Category::Security,
                    "alloca",
                    "alloca() can cause stack overflow with large/untrusted sizes; prefer heap allocation",
                ));
            }
        }

        diagnostics
    }
}
