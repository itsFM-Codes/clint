use crate::config::Config;
use crate::diagnostics::{Category, Diagnostic, Severity};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PointerState {
    MaybeNull,
    Live,
    Freed,
}

#[derive(Clone)]
struct FunctionDef {
    name: String,
    params: Vec<String>,
    start: usize,
    end: usize,
}

#[derive(Clone, Default)]
struct FunctionSummary {
    freed_params: HashSet<usize>,
}

fn clean_lines(content: &str) -> Vec<String> {
    let mut lines = Vec::new();
    let mut in_block = false;

    for raw in content.lines() {
        let mut line = raw.to_string();

        if in_block {
            if let Some(end) = line.find("*/") {
                line = line[end + 2..].to_string();
                in_block = false;
            } else {
                lines.push(String::new());
                continue;
            }
        }

        loop {
            let Some(start) = line.find("/*") else {
                break;
            };
            if let Some(end) = line[start + 2..].find("*/") {
                let end = start + 2 + end + 2;
                line.replace_range(start..end, "");
            } else {
                line.truncate(start);
                in_block = true;
                break;
            }
        }

        if let Some(start) = line.find("//") {
            line.truncate(start);
        }

        lines.push(line);
    }

    lines
}

fn brace_delta(line: &str) -> isize {
    line.chars().fold(0, |depth, c| match c {
        '{' => depth + 1,
        '}' => depth - 1,
        _ => depth,
    })
}

fn parse_params(raw: &str) -> Vec<String> {
    if raw.trim().is_empty() || raw.trim() == "void" {
        return Vec::new();
    }

    let name_re = Regex::new(r"([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?\s*$").unwrap();

    raw.split(',')
        .filter_map(|param| {
            let param = param.split('=').next().unwrap_or(param).trim();
            name_re
                .captures(param)
                .and_then(|caps| caps.get(1))
                .map(|m| m.as_str().to_string())
        })
        .collect()
}

fn parse_functions(lines: &[String]) -> Vec<FunctionDef> {
    let signature_re = Regex::new(
        r"^\s*(?:[A-Za-z_][\w:<>]*\s+)+[*&\s]*([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*(?:const\s*)?\{",
    )
    .unwrap();

    let mut functions = Vec::new();
    let mut idx = 0;

    while idx < lines.len() {
        let Some(caps) = signature_re.captures(&lines[idx]) else {
            idx += 1;
            continue;
        };

        let name = caps.get(1).unwrap().as_str().to_string();
        let params = parse_params(caps.get(2).unwrap().as_str());
        let mut depth = 0isize;
        let mut end = idx;

        for (offset, line) in lines[idx..].iter().enumerate() {
            depth += brace_delta(line);
            end = idx + offset;
            if depth <= 0 {
                break;
            }
        }

        functions.push(FunctionDef {
            name,
            params,
            start: idx,
            end,
        });
        idx = end.saturating_add(1);
    }

    functions
}

fn simple_name(value: &str) -> Option<String> {
    let mut value = value.trim();
    while value.starts_with('&') || value.starts_with('*') {
        value = value[1..].trim_start();
    }

    let name_re = Regex::new(r"^[A-Za-z_]\w*$").unwrap();
    if name_re.is_match(value) {
        Some(value.to_string())
    } else {
        None
    }
}

fn build_summaries(
    lines: &[String],
    functions: &[FunctionDef],
) -> HashMap<String, FunctionSummary> {
    let free_re = Regex::new(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)").unwrap();
    let call_re = Regex::new(r"\b([A-Za-z_]\w*)\s*\(([^(){};]*)\)").unwrap();
    let mut summaries: HashMap<String, FunctionSummary> = HashMap::new();

    for function in functions {
        let mut summary = FunctionSummary::default();

        for line in &lines[function.start..=function.end] {
            for caps in free_re.captures_iter(line) {
                let name = caps.get(1).unwrap().as_str();
                if let Some(index) = function.params.iter().position(|param| param == name) {
                    summary.freed_params.insert(index);
                }
            }
        }

        summaries.insert(function.name.clone(), summary);
    }

    loop {
        let snapshot = summaries.clone();
        let mut changed = false;

        for function in functions {
            let mut additions = HashSet::new();

            for (offset, line) in lines[function.start..=function.end].iter().enumerate() {
                for caps in call_re.captures_iter(line) {
                    let callee = caps.get(1).unwrap().as_str();

                    if offset == 0 && callee == function.name {
                        continue;
                    }

                    let Some(summary) = snapshot.get(callee) else {
                        continue;
                    };

                    let args: Vec<&str> = caps.get(2).unwrap().as_str().split(',').collect();

                    for index in &summary.freed_params {
                        let Some(arg) = args.get(*index).and_then(|arg| simple_name(arg)) else {
                            continue;
                        };
                        if let Some(param_index) =
                            function.params.iter().position(|param| param == &arg)
                        {
                            additions.insert(param_index);
                        }
                    }
                }
            }

            let summary = summaries.entry(function.name.clone()).or_default();
            let before = summary.freed_params.len();
            summary.freed_params.extend(additions);
            if summary.freed_params.len() != before {
                changed = true;
            }
        }

        if !changed {
            break;
        }
    }

    summaries
}

fn terminates(line: &str) -> bool {
    let line = line.trim();
    line.contains("return")
        || line.contains("throw")
        || line.contains("abort(")
        || line.contains("exit(")
}

fn null_guard(lines: &[String], index: usize, name: &str) -> bool {
    let escaped = regex::escape(name);
    let guard_re = Regex::new(&format!(
        r"\bif\s*\(\s*(?:!{}\b|{}\s*==\s*(?:NULL|nullptr|0)|(?:NULL|nullptr)\s*==\s*{})",
        escaped, escaped, escaped
    ))
    .unwrap();

    if !guard_re.is_match(&lines[index]) {
        return false;
    }

    if terminates(&lines[index]) {
        return true;
    }

    if lines[index].contains('{') {
        let mut depth = brace_delta(&lines[index]);
        for line in lines.iter().skip(index + 1) {
            if terminates(line) {
                return true;
            }
            depth += brace_delta(line);
            if depth <= 0 {
                break;
            }
        }
        return false;
    }

    lines
        .iter()
        .skip(index + 1)
        .find(|line| !line.trim().is_empty())
        .is_some_and(|line| terminates(line))
}

fn asserted_nonnull(line: &str, name: &str) -> bool {
    let escaped = regex::escape(name);
    Regex::new(&format!(
        r"\bassert\s*\(\s*{}\s*(?:!=\s*(?:NULL|nullptr|0))?\s*\)",
        escaped
    ))
    .unwrap()
    .is_match(line)
}

fn positive_check(line: &str, name: &str) -> bool {
    let escaped = regex::escape(name);
    Regex::new(&format!(
        r"\bif\s*\(\s*{}\s*(?:!=\s*(?:NULL|nullptr|0))?\s*\)",
        escaped
    ))
    .unwrap()
    .is_match(line)
}

fn dereferences(line: &str, name: &str) -> bool {
    if line.contains("sizeof(") || line.contains("decltype(") {
        return false;
    }

    let escaped = regex::escape(name);
    Regex::new(&format!(
        r"(?:\*\s*{}\b|\b{}\s*(?:->|\[))",
        escaped, escaped
    ))
    .unwrap()
    .is_match(line)
}

fn mark_freed(
    path: &Path,
    line_num: usize,
    name: &str,
    aliases: &HashMap<String, String>,
    states: &mut HashMap<String, PointerState>,
    diagnostics: &mut Vec<Diagnostic>,
) {
    let Some(root) = aliases.get(name) else {
        return;
    };

    if states.get(root) == Some(&PointerState::Freed) {
        diagnostics.push(Diagnostic::new(
            path,
            line_num,
            None,
            Severity::Error,
            Category::Security,
            "double-free",
            &format!("Potential double-free of '{}'", name),
        ));
    } else {
        states.insert(root.clone(), PointerState::Freed);
    }
}

fn analyze_function(
    path: &Path,
    lines: &[String],
    function: &FunctionDef,
    summaries: &HashMap<String, FunctionSummary>,
    config: &Config,
) -> Vec<Diagnostic> {
    let allocation_re = Regex::new(
        r"\b(?:[A-Za-z_][\w:<>]*\s+)*[*&\s]*([A-Za-z_]\w*)\s*=\s*(?:\([^;=]*\)\s*)?(?:malloc|calloc|realloc)\s*\(",
    )
    .unwrap();
    let alias_re = Regex::new(
        r"^\s*(?:[A-Za-z_][\w:<>]*\s+)*[*&\s]*([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;",
    )
    .unwrap();
    let assignment_re = Regex::new(
        r"^\s*(?:[A-Za-z_][\w:<>]*\s+)*[*&\s]*([A-Za-z_]\w*)\s*=",
    )
    .unwrap();
    let free_re = Regex::new(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)").unwrap();
    let call_re = Regex::new(r"\b([A-Za-z_]\w*)\s*\(([^(){};]*)\)").unwrap();

    let function_lines = &lines[function.start..=function.end];
    let mut aliases: HashMap<String, String> = HashMap::new();
    let mut states: HashMap<String, PointerState> = HashMap::new();
    let mut reported_null = HashSet::new();
    let mut reported_uaf = HashSet::new();
    let mut scoped_live: HashMap<String, isize> = HashMap::new();
    let mut depth = 0isize;
    let mut diagnostics = Vec::new();

    for param in &function.params {
        let root = format!("{}:param", param);
        aliases.insert(param.clone(), root.clone());
        states.insert(root, PointerState::Live);
    }

    for (offset, line) in function_lines.iter().enumerate() {
        let line_num = function.start + offset + 1;
        let mut assigned = HashSet::new();
        let mut allocated = HashSet::new();

        for caps in allocation_re.captures_iter(line) {
            let name = caps.get(1).unwrap().as_str().to_string();
            let root = format!("{}:{}", name, line_num);
            aliases.insert(name.clone(), root.clone());
            states.insert(root, PointerState::MaybeNull);
            assigned.insert(name.clone());
            allocated.insert(name);
        }

        if let Some(caps) = alias_re.captures(line) {
            let left = caps.get(1).unwrap().as_str().to_string();
            let right = caps.get(2).unwrap().as_str();

            if let Some(root) = aliases.get(right).cloned() {
                aliases.insert(left.clone(), root);
                assigned.insert(left);
            }
        }

        if let Some(caps) = assignment_re.captures(line) {
            let name = caps.get(1).unwrap().as_str().to_string();
            if !assigned.contains(&name) {
                aliases.remove(&name);
            }
        }

        let names: Vec<String> = aliases.keys().cloned().collect();

        for name in &names {
            let Some(root) = aliases.get(name).cloned() else {
                continue;
            };

            if null_guard(function_lines, offset, name) || asserted_nonnull(line, name) {
                if states.get(&root) == Some(&PointerState::MaybeNull) {
                    states.insert(root.clone(), PointerState::Live);
                }
            }

            if positive_check(line, name) && line.contains('{') {
                scoped_live.insert(root, depth + 1);
            }
        }

        for caps in free_re.captures_iter(line) {
            mark_freed(
                path,
                line_num,
                caps.get(1).unwrap().as_str(),
                &aliases,
                &mut states,
                &mut diagnostics,
            );
        }

        for caps in call_re.captures_iter(line) {
            let callee = caps.get(1).unwrap().as_str();

            if offset == 0 && callee == function.name {
                continue;
            }

            let Some(summary) = summaries.get(callee) else {
                continue;
            };

            let args: Vec<&str> = caps.get(2).unwrap().as_str().split(',').collect();

            for index in &summary.freed_params {
                let Some(name) = args.get(*index).and_then(|arg| simple_name(arg)) else {
                    continue;
                };
                mark_freed(
                    path,
                    line_num,
                    &name,
                    &aliases,
                    &mut states,
                    &mut diagnostics,
                );
            }
        }

        let names: Vec<String> = aliases.keys().cloned().collect();

        for name in names {
            if allocated.contains(&name) || !dereferences(line, &name) {
                continue;
            }

            let Some(root) = aliases.get(&name).cloned() else {
                continue;
            };
            let state = states.get(&root).copied().unwrap_or(PointerState::Live);
            let live_in_scope = scoped_live
                .get(&root)
                .is_some_and(|scope_depth| depth >= *scope_depth);

            if state == PointerState::Freed && reported_uaf.insert(root.clone()) {
                diagnostics.push(Diagnostic::new(
                    path,
                    line_num,
                    None,
                    Severity::Error,
                    Category::Security,
                    "use-after-free",
                    &format!("Potential use-after-free: '{}' used after release", name),
                ));
            } else if state == PointerState::MaybeNull
                && config.security.check_null_deref
                && !live_in_scope
                && !positive_check(line, &name)
                && reported_null.insert(root)
            {
                diagnostics.push(Diagnostic::new(
                    path,
                    line_num,
                    None,
                    Severity::Warning,
                    Category::Security,
                    "null-deref",
                    &format!("Potential NULL dereference of '{}'", name),
                ));
            }
        }

        depth += brace_delta(line);
        scoped_live.retain(|_, scope_depth| depth >= *scope_depth);
    }

    diagnostics
}

pub fn analyze_pointer_semantics(
    path: &Path,
    content: &str,
    config: &Config,
) -> Vec<Diagnostic> {
    let lines = clean_lines(content);
    let functions = parse_functions(&lines);
    let summaries = build_summaries(&lines, &functions);
    let mut diagnostics = Vec::new();

    for function in &functions {
        diagnostics.extend(analyze_function(
            path,
            &lines,
            function,
            &summaries,
            config,
        ));
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rules(source: &str) -> Vec<String> {
        analyze_pointer_semantics(Path::new("test.c"), source, &Config::default())
            .into_iter()
            .map(|diagnostic| diagnostic.rule)
            .collect()
    }

    #[test]
    fn catches_long_distance_use_after_free() {
        let source = r#"
void f() {
    char *p = malloc(16);
    if (!p) return;
    free(p);
    int a = 1;
    int b = 2;
    int c = 3;
    int d = 4;
    int e = 5;
    int f = 6;
    p[0] = 'x';
}
"#;
        assert!(rules(source).contains(&"use-after-free".to_string()));
    }

    #[test]
    fn catches_alias_use_after_free() {
        let source = r#"
void f() {
    char *p = malloc(16);
    if (!p) return;
    char *q = p;
    free(q);
    p[0] = 'x';
}
"#;
        assert!(rules(source).contains(&"use-after-free".to_string()));
    }

    #[test]
    fn catches_long_distance_double_free() {
        let source = r#"
void f() {
    char *p = malloc(16);
    if (!p) return;
    free(p);
    int a = 1;
    int b = 2;
    int c = 3;
    int d = 4;
    int e = 5;
    int f = 6;
    free(p);
}
"#;
        assert!(rules(source).contains(&"double-free".to_string()));
    }

    #[test]
    fn propagates_release_through_function_summary() {
        let source = r#"
void release(char *p) {
    free(p);
}

void release_wrapper(char *p) {
    release(p);
}

void f() {
    char *p = malloc(16);
    if (!p) return;
    release_wrapper(p);
    p[0] = 'x';
}
"#;
        assert!(rules(source).contains(&"use-after-free".to_string()));
    }

    #[test]
    fn accepts_terminating_null_guard() {
        let source = r#"
void f() {
    char *p = malloc(16);
    if (!p) {
        return;
    }
    p[0] = 'x';
}
"#;
        assert!(!rules(source).contains(&"null-deref".to_string()));
    }

    #[test]
    fn catches_dereference_before_null_check() {
        let source = r#"
void f() {
    char *p = malloc(16);
    p[0] = 'x';
}
"#;
        assert!(rules(source).contains(&"null-deref".to_string()));
    }
}
