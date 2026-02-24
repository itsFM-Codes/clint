use crate::config::Config;
use crate::diagnostics::{Category, Diagnostic, Severity};
use crate::rules::Rule;
use regex::Regex;
use std::path::Path;

pub struct StyleRule;

fn is_snake_case(name: &str) -> bool {
    let re = Regex::new(r"^[a-z][a-z0-9_]*$").unwrap();
    re.is_match(name)
}

fn is_camel_case(name: &str) -> bool {
    let re = Regex::new(r"^[a-z][a-zA-Z0-9]*$").unwrap();
    re.is_match(name)
}

fn is_pascal_case(name: &str) -> bool {
    let re = Regex::new(r"^[A-Z][a-zA-Z0-9]*$").unwrap();
    re.is_match(name)
}

fn is_upper_snake_case(name: &str) -> bool {
    let re = Regex::new(r"^[A-Z][A-Z0-9_]*$").unwrap();
    re.is_match(name)
}

fn check_naming(name: &str, convention: &str) -> bool {
    match convention {
        "snake_case" => is_snake_case(name),
        "camelCase" => is_camel_case(name),
        "PascalCase" => is_pascal_case(name),
        "UPPER_SNAKE_CASE" => is_upper_snake_case(name),
        _ => true,
    }
}

struct InCommentState {
    in_block_comment: bool,
}

impl InCommentState {
    fn new() -> Self {
        Self {
            in_block_comment: false,
        }
    }

    // Returns true if the line is effectively a comment/string and should be skipped
    fn update_and_check(&mut self, line: &str) -> bool {
        let trimmed = line.trim();

        if self.in_block_comment {
            if trimmed.contains("*/") {
                self.in_block_comment = false;
            }
            return true;
        }

        if trimmed.starts_with("/*") {
            if !trimmed.contains("*/") {
                self.in_block_comment = true;
            }
            return true;
        }

        trimmed.starts_with("//")
    }
}

impl Rule for StyleRule {
    fn check(&self, path: &Path, content: &str, config: &Config) -> Vec<Diagnostic> {
        if !config.style.enabled {
            return vec![];
        }

        let mut diagnostics = vec![];
        let mut comment_state = InCommentState::new();
        let lines: Vec<&str> = content.lines().collect();
        let mut current_func_start: Option<usize> = None;
        let mut brace_depth: i32 = 0;

        for (idx, line) in lines.iter().enumerate() {
            let line_num = idx + 1;

            // Line length check (always applies)
            if line.len() > config.style.max_line_length {
                diagnostics.push(Diagnostic::new(
                    path,
                    line_num,
                    Some(config.style.max_line_length + 1),
                    Severity::Warning,
                    Category::Style,
                    "line-length",
                    &format!(
                        "Line exceeds {} characters ({})",
                        config.style.max_line_length,
                        line.len()
                    ),
                ));
            }

            // Trailing whitespace check
            if config.style.trailing_whitespace
                && line.len() != line.trim_end().len()
                && !line.trim().is_empty()
            {
                diagnostics.push(Diagnostic::new(
                    path,
                    line_num,
                    Some(line.trim_end().len() + 1),
                    Severity::Warning,
                    Category::Style,
                    "trailing-whitespace",
                    "Trailing whitespace detected",
                ));
            }

            if comment_state.update_and_check(line) {
                continue;
            }

            let trimmed = line.trim();

            // Indentation style check
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                let leading = &line[..line.len() - line.trim_start().len()];
                match config.style.indent_style.as_str() {
                    "spaces" => {
                        if leading.contains('\t') {
                            diagnostics.push(Diagnostic::new(
                                path,
                                line_num,
                                Some(1),
                                Severity::Warning,
                                Category::Style,
                                "indent-style",
                                "Tab indentation found, expected spaces",
                            ));
                        }
                    }
                    "tabs" => {
                        if leading.contains(' ') && !leading.is_empty() {
                            let space_only = leading.chars().all(|c| c == ' ');
                            if space_only && leading.len() >= config.style.indent_width {
                                diagnostics.push(Diagnostic::new(
                                    path,
                                    line_num,
                                    Some(1),
                                    Severity::Warning,
                                    Category::Style,
                                    "indent-style",
                                    "Space indentation found, expected tabs",
                                ));
                            }
                        }
                    }
                    _ => {}
                }
            }

            // Track brace depth for function length detection
            let open_braces = trimmed.chars().filter(|&c| c == '{').count() as i32;
            let close_braces = trimmed.chars().filter(|&c| c == '}').count() as i32;

            if brace_depth == 0 && open_braces > 0 {
                // Detect function definition start (heuristic: line before '{' or line with '{')
                let prev_line = if idx > 0 { lines[idx - 1].trim() } else { "" };
                let func_re =
                    Regex::new(r"^[\w\s\*&:~]+\w+\s*\([^;]*\)\s*\{?\s*$").unwrap();
                if func_re.is_match(trimmed) || func_re.is_match(prev_line) {
                    current_func_start = Some(line_num);
                }
            }

            brace_depth += open_braces - close_braces;

            if brace_depth == 0 && current_func_start.is_some() {
                let start = current_func_start.unwrap();
                let func_len = line_num - start;
                if func_len > config.style.max_function_lines {
                    diagnostics.push(Diagnostic::new(
                        path,
                        start,
                        None,
                        Severity::Warning,
                        Category::Style,
                        "function-length",
                        &format!(
                            "Function is {} lines long (max: {})",
                            func_len, config.style.max_function_lines
                        ),
                    ));
                }
                current_func_start = None;
            }

            // Brace style check: K&R vs Allman
            if trimmed == "{" && idx > 0 {
                let prev_trimmed = lines[idx - 1].trim();
                let is_block_start = prev_trimmed.ends_with(')')
                    || prev_trimmed.starts_with("if")
                    || prev_trimmed.starts_with("else")
                    || prev_trimmed.starts_with("for")
                    || prev_trimmed.starts_with("while")
                    || prev_trimmed.starts_with("switch")
                    || prev_trimmed.starts_with("do");

                if config.style.brace_style == "k&r" && is_block_start {
                    diagnostics.push(Diagnostic::new(
                        path,
                        line_num,
                        Some(1),
                        Severity::Warning,
                        Category::Style,
                        "brace-style",
                        "Opening brace should be on the same line (K&R style)",
                    ));
                }
            }

            if config.style.brace_style == "allman" {
                let keywords = ["if", "else", "for", "while", "switch", "do"];
                for kw in &keywords {
                    if trimmed.starts_with(kw) && trimmed.ends_with('{') {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            None,
                            Severity::Warning,
                            Category::Style,
                            "brace-style",
                            "Opening brace should be on a new line (Allman style)",
                        ));
                        break;
                    }
                }
            }

            // Require braces after control flow statements
            if config.style.require_braces {
                let control_re =
                    Regex::new(r"^\s*(if|else\s+if|for|while)\s*\(.*\)\s*$").unwrap();
                if control_re.is_match(line) {
                    // Next non-empty line should have a brace
                    let next = lines.get(idx + 1).map(|l| l.trim()).unwrap_or("");
                    if !next.is_empty() && !next.starts_with('{') && !next.contains('{') {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            None,
                            Severity::Warning,
                            Category::Style,
                            "require-braces",
                            "Control flow statement without braces",
                        ));
                    }
                }

                if trimmed == "else" {
                    let next = lines.get(idx + 1).map(|l| l.trim()).unwrap_or("");
                    if !next.starts_with('{') && !next.starts_with("if") {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            None,
                            Severity::Warning,
                            Category::Style,
                            "require-braces",
                            "'else' without braces",
                        ));
                    }
                }
            }

            // Function naming convention check (simple heuristic)
            let func_def_re =
                Regex::new(r"^(?:static\s+)?(?:inline\s+)?(?:const\s+)?(?:unsigned\s+)?(?:signed\s+)?(?:long\s+)?(?:short\s+)?(?:void|int|char|float|double|bool|size_t|ssize_t|(?:struct|enum|union)\s+\w+|\w+_t)\s*\*?\s*(\w+)\s*\(").unwrap();
            if let Some(caps) = func_def_re.captures(trimmed) {
                if let Some(name_match) = caps.get(1) {
                    let func_name = name_match.as_str();
                    // Skip main and common names
                    if func_name != "main"
                        && !func_name.starts_with("__")
                        && !check_naming(func_name, &config.style.naming.functions)
                    {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            Some(name_match.start() + 1),
                            Severity::Warning,
                            Category::Style,
                            "naming-convention",
                            &format!(
                                "Function '{}' does not follow {} convention",
                                func_name, config.style.naming.functions
                            ),
                        ));
                    }
                }
            }

            // Macro naming check
            let macro_re = Regex::new(r"^#define\s+(\w+)").unwrap();
            if let Some(caps) = macro_re.captures(trimmed) {
                if let Some(name_match) = caps.get(1) {
                    let macro_name = name_match.as_str();
                    // Skip include guards and common patterns
                    if !macro_name.ends_with("_H")
                        && !macro_name.ends_with("_H_")
                        && !macro_name.ends_with("_HPP")
                        && !check_naming(macro_name, &config.style.naming.macros)
                    {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            Some(name_match.start() + 1),
                            Severity::Warning,
                            Category::Style,
                            "naming-convention",
                            &format!(
                                "Macro '{}' does not follow {} convention",
                                macro_name, config.style.naming.macros
                            ),
                        ));
                    }
                }
            }

            // Type naming check (typedef, struct, enum)
            let type_re = Regex::new(r"(?:typedef\s+(?:struct|enum|union)\s+\w*\s*\{?[^}]*\}?\s*|struct\s+|enum\s+|union\s+)(\w+)\s*[;{]").unwrap();
            if let Some(caps) = type_re.captures(trimmed) {
                if let Some(name_match) = caps.get(1) {
                    let type_name = name_match.as_str();
                    if !type_name.ends_with("_t")
                        && !check_naming(type_name, &config.style.naming.types)
                    {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            Some(name_match.start() + 1),
                            Severity::Warning,
                            Category::Style,
                            "naming-convention",
                            &format!(
                                "Type '{}' does not follow {} convention",
                                type_name, config.style.naming.types
                            ),
                        ));
                    }
                }
            }
        }

        diagnostics
    }
}
