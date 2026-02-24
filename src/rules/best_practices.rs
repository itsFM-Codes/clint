use crate::config::Config;
use crate::diagnostics::{Category, Diagnostic, Severity};
use crate::rules::Rule;
use regex::Regex;
use std::path::Path;

pub struct BestPracticesRule;

fn is_header_file(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| matches!(e, "h" | "hpp" | "hxx" | "hh"))
        .unwrap_or(false)
}

impl Rule for BestPracticesRule {
    fn check(&self, path: &Path, content: &str, config: &Config) -> Vec<Diagnostic> {
        if !config.best_practices.enabled {
            return vec![];
        }

        let mut diagnostics = vec![];
        let lines: Vec<&str> = content.lines().collect();
        let mut in_block_comment = false;
        let mut nesting_depth: i32 = 0;
        let mut in_switch = false;
        let mut switch_depth: i32 = 0;
        let mut last_case_line: Option<usize> = None;
        let mut had_break_since_case = true;


        // Include guard check for header files
        if config.best_practices.require_include_guards && is_header_file(path) {
            let has_pragma_once = lines.iter().any(|l| l.trim() == "#pragma once");
            let has_ifndef = lines.iter().any(|l| {
                let t = l.trim();
                t.starts_with("#ifndef") || t.starts_with("#if !defined")
            });
            let has_define = lines.iter().any(|l| l.trim().starts_with("#define"));

            if !has_pragma_once && !(has_ifndef && has_define) {
                diagnostics.push(Diagnostic::new(
                    path,
                    1,
                    None,
                    Severity::Warning,
                    Category::BestPractice,
                    "include-guard",
                    "Header file missing include guard (#pragma once or #ifndef/#define)",
                ));
            }
        }

        for (idx, line) in lines.iter().enumerate() {
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
                // Still check for TODO in comment
                if config.best_practices.warn_todo_comments {
                    check_todo_comment(path, line_num, trimmed, &mut diagnostics);
                }
                continue;
            }

            // TODO/FIXME/HACK in line comments
            if config.best_practices.warn_todo_comments && trimmed.starts_with("//") {
                check_todo_comment(path, line_num, trimmed, &mut diagnostics);
                continue;
            }
            if trimmed.starts_with("//") {
                continue;
            }

            // Inline TODO comments
            if config.best_practices.warn_todo_comments && line.contains("//") {
                let comment_part = line.split("//").nth(1).unwrap_or("");
                check_todo_comment(path, line_num, comment_part, &mut diagnostics);
            }

            // goto detection
            if config.best_practices.ban_goto {
                let goto_re = Regex::new(r"\bgoto\s+\w+").unwrap();
                if goto_re.is_match(trimmed) {
                    diagnostics.push(Diagnostic::new(
                        path,
                        line_num,
                        None,
                        Severity::Warning,
                        Category::BestPractice,
                        "goto",
                        "Use of 'goto' is discouraged; consider restructuring with loops or functions",
                    ));
                }
            }

            // Magic number detection
            if config.best_practices.check_magic_numbers {
                check_magic_numbers(path, line_num, trimmed, &mut diagnostics);
            }

            // Track nesting depth
            let open_braces = trimmed.chars().filter(|&c| c == '{').count() as i32;
            let close_braces = trimmed.chars().filter(|&c| c == '}').count() as i32;

            // Switch tracking
            if trimmed.starts_with("switch") || trimmed.contains("switch (") || trimmed.contains("switch(") {
                in_switch = true;
                switch_depth = nesting_depth;
            }

            nesting_depth += open_braces;
            nesting_depth -= close_braces;

            // Max nesting depth check
            if nesting_depth > config.best_practices.max_nesting_depth as i32 && open_braces > 0 {
                diagnostics.push(Diagnostic::new(
                    path,
                    line_num,
                    None,
                    Severity::Warning,
                    Category::BestPractice,
                    "nesting-depth",
                    &format!(
                        "Nesting depth {} exceeds maximum of {}",
                        nesting_depth, config.best_practices.max_nesting_depth
                    ),
                ));
            }

            // Switch analysis
            if in_switch && nesting_depth > switch_depth {
                let case_re = Regex::new(r"^\s*(case\s+.+|default)\s*:").unwrap();

                if case_re.is_match(trimmed) {
                    // Check implicit fallthrough from previous case
                    if config.best_practices.check_implicit_fallthrough
                        && !had_break_since_case
                        && last_case_line.is_some()
                    {
                        diagnostics.push(Diagnostic::new(
                            path,
                            last_case_line.unwrap(),
                            None,
                            Severity::Warning,
                            Category::BestPractice,
                            "implicit-fallthrough",
                            "Implicit fallthrough in switch case; add 'break', 'return', or '/* fallthrough */' comment",
                        ));
                    }
                    last_case_line = Some(line_num);
                    had_break_since_case = false;
                }

                if trimmed.starts_with("break")
                    || trimmed.starts_with("return")
                    || trimmed.starts_with("goto")
                    || trimmed.starts_with("exit")
                    || trimmed.starts_with("continue")
                    || trimmed.contains("/* fallthrough */")
                    || trimmed.contains("/* fall through */")
                    || trimmed.contains("// fallthrough")
                    || trimmed.contains("// fall through")
                    || trimmed.contains("[[fallthrough]]")
                {
                    had_break_since_case = true;
                }
            }

            // Check for switch end and missing default
            if in_switch && nesting_depth <= switch_depth {
                if config.best_practices.require_default_in_switch {
                    let switch_block: Vec<&str> = lines[..idx + 1]
                        .iter()
                        .rev()
                        .take(100)
                        .copied()
                        .collect();
                    let has_default = switch_block
                        .iter()
                        .any(|l| Regex::new(r"^\s*default\s*:").unwrap().is_match(l));
                    if !has_default {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            None,
                            Severity::Warning,
                            Category::BestPractice,
                            "switch-default",
                            "Switch statement missing 'default' case",
                        ));
                    }
                }
                in_switch = false;
                last_case_line = None;
                had_break_since_case = true;
            }

            // Function parameter count check
            let func_def_re = Regex::new(
                r"^(?:static\s+)?(?:inline\s+)?(?:const\s+)?[\w\s\*&:]+\w+\s*\(([^)]*)\)\s*\{?"
            ).unwrap();
            if let Some(caps) = func_def_re.captures(trimmed) {
                let params_str = caps.get(1).unwrap().as_str().trim();
                if !params_str.is_empty() && params_str != "void" {
                    let param_count = params_str.split(',').count();
                    if param_count > config.best_practices.max_function_params {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            None,
                            Severity::Warning,
                            Category::BestPractice,
                            "too-many-params",
                            &format!(
                                "Function has {} parameters (max: {}); consider using a struct",
                                param_count, config.best_practices.max_function_params
                            ),
                        ));
                    }
                }
            }
        }

        diagnostics
    }
}

fn check_todo_comment(
    path: &Path,
    line_num: usize,
    text: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let upper = text.to_uppercase();
    if upper.contains("TODO") {
        diagnostics.push(Diagnostic::new(
            path,
            line_num,
            None,
            Severity::Info,
            Category::BestPractice,
            "todo-comment",
            "TODO comment found",
        ));
    } else if upper.contains("FIXME") {
        diagnostics.push(Diagnostic::new(
            path,
            line_num,
            None,
            Severity::Warning,
            Category::BestPractice,
            "fixme-comment",
            "FIXME comment found",
        ));
    } else if upper.contains("HACK") || upper.contains("XXX") {
        diagnostics.push(Diagnostic::new(
            path,
            line_num,
            None,
            Severity::Warning,
            Category::BestPractice,
            "hack-comment",
            "HACK/XXX comment found; this should be addressed",
        ));
    }
}

fn check_magic_numbers(
    path: &Path,
    line_num: usize,
    line: &str,
    diagnostics: &mut Vec<Diagnostic>,
) {
    // Skip preprocessor, includes, and known acceptable patterns
    if line.starts_with('#') || line.starts_with("//") {
        return;
    }

    let magic_re = Regex::new(r"\b(\d+)\b").unwrap();
    for cap in magic_re.captures_iter(line) {
        let num_str = cap.get(1).unwrap().as_str();
        let num: i64 = match num_str.parse() {
            Ok(n) => n,
            Err(_) => continue,
        };

        // 0, 1, 2 are generally acceptable
        if num <= 2 {
            continue;
        }

        // Skip array sizes in declarations
        if line.contains('[') && line.contains(']') {
            continue;
        }

        // Skip enum values
        if line.trim().starts_with("case ") {
            continue;
        }

        // Skip constants and defines
        if line.contains("const ") || line.contains("#define") || line.contains("enum") {
            continue;
        }

        // Skip return values (common patterns)
        if line.trim().starts_with("return") {
            continue;
        }

        // Skip sizeof comparisons
        if line.contains("sizeof") {
            continue;
        }

        // Flag the magic number
        diagnostics.push(Diagnostic::new(
            path,
            line_num,
            None,
            Severity::Info,
            Category::BestPractice,
            "magic-number",
            &format!(
                "Magic number '{}' found; consider using a named constant",
                num
            ),
        ));
        break; // Only report once per line
    }
}
