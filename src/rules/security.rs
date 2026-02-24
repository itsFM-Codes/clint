use crate::config::Config;
use crate::diagnostics::{Category, Diagnostic, Severity};
use crate::rules::Rule;
use regex::Regex;
use std::path::Path;

pub struct SecurityRule;

impl Rule for SecurityRule {
    fn check(&self, path: &Path, content: &str, config: &Config) -> Vec<Diagnostic> {
        if !config.security.enabled {
            return vec![];
        }

        let mut diagnostics = vec![];
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

            // Format string vulnerability: printf/fprintf/syslog with variable as format
            if config.security.check_format_strings {
                let fmt_re = Regex::new(
                    r"\b(printf|fprintf|syslog|snprintf|sprintf)\s*\(\s*(?:[^,]+,\s*)?(\w+)\s*\)"
                ).unwrap();
                if let Some(caps) = fmt_re.captures(line) {
                    let func = caps.get(1).unwrap().as_str();
                    let arg = caps.get(2).unwrap().as_str();
                    // If argument is not a string literal, flag it
                    if !arg.starts_with('"') && arg != "stdout" && arg != "stderr" && arg != "stdin" {
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

            // Buffer overflow: fixed-size buffer with unchecked input
            if config.security.check_buffer_overflow {
                let fixed_buf_re = Regex::new(r"\bchar\s+(\w+)\s*\[\s*(\d+)\s*\]").unwrap();
                if fixed_buf_re.is_match(line) {
                    // Check if this line also has strcpy/strcat/memcpy without size check
                    let dangerous_re = Regex::new(r"\b(strcpy|strcat|memcpy)\s*\(").unwrap();
                    if dangerous_re.is_match(line) {
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
                }

                // Detect memcpy/memmove with sizeof mismatch potential
                let memcpy_re = Regex::new(r"\bmemcpy\s*\(\s*(\w+)").unwrap();
                if let Some(caps) = memcpy_re.captures(line) {
                    if line.contains("strlen") && !line.contains("+ 1") && !line.contains("+1") {
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

            // Integer overflow: assignment patterns
            if config.security.check_integer_overflow {
                // Detect unchecked integer arithmetic before malloc/array index
                let malloc_arith_re = Regex::new(
                    r"\bmalloc\s*\(\s*\w+\s*[\*\+]\s*\w+"
                ).unwrap();
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

                // Narrowing conversion patterns
                let narrow_re = Regex::new(
                    r"\b(short|char|uint8_t|int8_t|uint16_t|int16_t)\s+\w+\s*=\s*\w+\s*[\*\+\-]"
                ).unwrap();
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

            // Null dereference: pointer used right after potentially-null source
            if config.security.check_null_deref {
                // malloc without NULL check
                let malloc_re = Regex::new(r"\b(\w+)\s*=\s*(?:malloc|calloc|realloc)\s*\(").unwrap();
                if let Some(caps) = malloc_re.captures(line) {
                    let var_name = caps.get(1).unwrap().as_str();
                    // Look ahead for usage without NULL check
                    let check_lines = content.lines().skip(idx + 1).take(3).collect::<Vec<_>>();
                    let has_null_check = check_lines.iter().any(|l| {
                        let t = l.trim();
                        t.contains(&format!("if (!{}", var_name))
                            || t.contains(&format!("if ({} == NULL", var_name))
                            || t.contains(&format!("if (NULL == {}", var_name))
                            || t.contains(&format!("if ({} == 0", var_name))
                            || t.contains(&format!("assert({})", var_name))
                            || t.contains(&format!("assert({} !=", var_name))
                    });

                    if !has_null_check {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            Some(caps.get(1).unwrap().start() + 1),
                            Severity::Warning,
                            Category::Security,
                            "null-deref",
                            &format!(
                                "Return value of allocation assigned to '{}' is not checked for NULL",
                                var_name
                            ),
                        ));
                    }
                }
            }

            // system() calls
            if config.security.ban_system_calls {
                let sys_re = Regex::new(r"\b(system|popen|exec[lv]p?e?)\s*\(").unwrap();
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

            // alloca usage
            let alloca_re = Regex::new(r"\balloca\s*\(").unwrap();
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

            // Use after free patterns (simple heuristic)
            let free_re = Regex::new(r"\bfree\s*\(\s*(\w+)\s*\)").unwrap();
            if let Some(caps) = free_re.captures(line) {
                let ptr_name = caps.get(1).unwrap().as_str();
                // Check if pointer is used in subsequent lines without being reassigned
                let next_lines: Vec<&str> = content.lines().skip(idx + 1).take(5).collect();
                for (offset, next_line) in next_lines.iter().enumerate() {
                    let nt = next_line.trim();
                    if nt.is_empty() || nt.starts_with("//") || nt.starts_with("/*") {
                        continue;
                    }
                    // If reassigned or set to NULL, it's fine
                    if nt.contains(&format!("{} = ", ptr_name))
                        || nt.contains(&format!("{} =\t", ptr_name))
                        || nt.starts_with("return")
                        || nt.starts_with('}')
                    {
                        break;
                    }
                    // Check for dereference or use
                    let use_re = Regex::new(&format!(
                        r"\b{}\s*[\[\.\->]|[\*&]\s*{}|\b{}\s*[,\)]",
                        regex::escape(ptr_name),
                        regex::escape(ptr_name),
                        regex::escape(ptr_name),
                    ))
                    .unwrap();
                    if use_re.is_match(nt) {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num + offset + 1,
                            None,
                            Severity::Error,
                            Category::Security,
                            "use-after-free",
                            &format!(
                                "Potential use-after-free: '{}' used after free()",
                                ptr_name
                            ),
                        ));
                        break;
                    }
                }
            }

            // Double-free detection (simple)
            if let Some(caps) = free_re.captures(line) {
                let ptr_name = caps.get(1).unwrap().as_str();
                let remaining: Vec<&str> = content.lines().skip(idx + 1).take(10).collect();
                for (offset, rl) in remaining.iter().enumerate() {
                    let rt = rl.trim();
                    // If reassigned, stop checking
                    if rt.contains(&format!("{} = ", ptr_name)) || rt.contains(&format!("{} =\t", ptr_name)) {
                        break;
                    }
                    let double_free_re = Regex::new(&format!(r"\bfree\s*\(\s*{}\s*\)", regex::escape(ptr_name))).unwrap();
                    if double_free_re.is_match(rt) {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num + offset + 1,
                            None,
                            Severity::Error,
                            Category::Security,
                            "double-free",
                            &format!("Potential double-free of '{}'", ptr_name),
                        ));
                        break;
                    }
                }
            }
        }

        diagnostics
    }
}
