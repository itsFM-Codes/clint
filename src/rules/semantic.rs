use crate::config::Config;
use crate::diagnostics::{Category, Diagnostic, Severity};
use regex::Regex;
use std::collections::{HashMap, HashSet};
use std::path::Path;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PointerState {
    MaybeNull,
    NonNull,
    Null,
    Freed,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct FunctionKey {
    name: String,
    arity: usize,
}

#[derive(Clone)]
struct FunctionSpan {
    name: String,
    params: Vec<String>,
    start: usize,
    end: usize,
}

impl FunctionSpan {
    fn key(&self) -> FunctionKey {
        FunctionKey {
            name: self.name.clone(),
            arity: self.params.len(),
        }
    }
}

#[derive(Clone, Default, PartialEq, Eq)]
struct FunctionSummary {
    freed_params: HashSet<usize>,
}

struct PointerFacts {
    variables: HashMap<String, usize>,
    states: HashMap<usize, PointerState>,
    next_id: usize,
}

impl PointerFacts {
    fn new() -> Self {
        Self {
            variables: HashMap::new(),
            states: HashMap::new(),
            next_id: 0,
        }
    }

    fn bind(&mut self, name: &str, state: PointerState) {
        let id = self.next_id;
        self.next_id += 1;
        self.variables.insert(name.to_string(), id);
        self.states.insert(id, state);
    }

    fn alias(&mut self, target: &str, source: &str) {
        if let Some(id) = self.variables.get(source).copied() {
            self.variables.insert(target.to_string(), id);
        } else {
            self.variables.remove(target);
        }
    }

    fn clear(&mut self, name: &str) {
        self.variables.remove(name);
    }

    fn state(&self, name: &str) -> Option<PointerState> {
        let id = self.variables.get(name)?;
        self.states.get(id).copied()
    }

    fn set_state(&mut self, name: &str, state: PointerState) {
        if let Some(id) = self.variables.get(name).copied() {
            self.states.insert(id, state);
        }
    }

    fn group(&self, name: &str) -> Option<usize> {
        self.variables.get(name).copied()
    }

    fn set_group_state(&mut self, id: usize, state: PointerState) {
        self.states.insert(id, state);
    }
}

fn sanitize_source(content: &str) -> String {
    let chars: Vec<char> = content.chars().collect();
    let mut output = String::with_capacity(content.len());
    let mut index = 0;
    let mut block_comment = false;
    let mut line_comment = false;
    let mut string_literal = false;
    let mut char_literal = false;
    let mut escaped = false;

    while index < chars.len() {
        let ch = chars[index];
        let next = chars.get(index + 1).copied();

        if line_comment {
            if ch == '\n' {
                output.push('\n');
                line_comment = false;
            } else {
                output.push(' ');
            }
            index += 1;
            continue;
        }

        if block_comment {
            if ch == '*' && next == Some('/') {
                output.push(' ');
                output.push(' ');
                index += 2;
                block_comment = false;
                continue;
            }
            if ch == '\n' {
                output.push('\n');
            } else {
                output.push(' ');
            }
            index += 1;
            continue;
        }

        if string_literal {
            if ch == '\n' {
                output.push('\n');
                escaped = false;
                index += 1;
                continue;
            }
            output.push(' ');
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                string_literal = false;
            }
            index += 1;
            continue;
        }

        if char_literal {
            if ch == '\n' {
                output.push('\n');
                escaped = false;
                index += 1;
                continue;
            }
            output.push(' ');
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '\'' {
                char_literal = false;
            }
            index += 1;
            continue;
        }

        if ch == '/' && next == Some('/') {
            output.push(' ');
            output.push(' ');
            index += 2;
            line_comment = true;
            continue;
        }

        if ch == '/' && next == Some('*') {
            output.push(' ');
            output.push(' ');
            index += 2;
            block_comment = true;
            continue;
        }

        if ch == '"' {
            output.push(' ');
            string_literal = true;
            escaped = false;
            index += 1;
            continue;
        }

        if ch == '\'' {
            output.push(' ');
            char_literal = true;
            escaped = false;
            index += 1;
            continue;
        }

        output.push(ch);
        index += 1;
    }

    output
}

fn parameter_names(raw: &str) -> Vec<String> {
    let ident_re = Regex::new(r"[A-Za-z_]\w*").unwrap();

    raw.split(',')
        .filter_map(|part| {
            let value = part.split('=').next().unwrap_or("").trim();
            if value.is_empty() || value == "void" {
                return None;
            }

            ident_re
                .find_iter(value)
                .map(|m| m.as_str())
                .filter(|name| {
                    !matches!(
                        *name,
                        "const"
                            | "volatile"
                            | "unsigned"
                            | "signed"
                            | "struct"
                            | "class"
                            | "typename"
                    )
                })
                .last()
                .map(str::to_string)
        })
        .collect()
}

fn function_spans(lines: &[&str]) -> Vec<FunctionSpan> {
    let signature_re = Regex::new(
        r"^\s*(?:template\s*<[^>]+>\s*)?(?:[A-Za-z_]\w*(?:::\w+)*(?:<[^;{}()]+>)?\s*[*&]*\s+)+(?:[*&]\s*)?([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*(?:const\s*)?(?:noexcept\s*)?\{",
    )
    .unwrap();
    let mut spans = Vec::new();
    let mut index = 0;

    while index < lines.len() {
        let Some(caps) = signature_re.captures(lines[index]) else {
            index += 1;
            continue;
        };

        let name = caps.get(1).unwrap().as_str().to_string();
        let params = parameter_names(caps.get(2).unwrap().as_str());
        let mut depth = 0isize;
        let mut end = index;

        for (offset, line) in lines[index..].iter().enumerate() {
            depth += line.chars().filter(|c| *c == '{').count() as isize;
            depth -= line.chars().filter(|c| *c == '}').count() as isize;
            end = index + offset;
            if depth == 0 {
                break;
            }
        }

        spans.push(FunctionSpan {
            name,
            params,
            start: index,
            end,
        });
        index = end.saturating_add(1);
    }

    spans
}

fn split_args(raw: &str) -> Vec<String> {
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0isize;

    for ch in raw.chars() {
        match ch {
            '(' | '[' | '{' | '<' => {
                depth += 1;
                current.push(ch);
            }
            ')' | ']' | '}' | '>' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                args.push(current.trim().to_string());
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    if !current.trim().is_empty() {
        args.push(current.trim().to_string());
    }

    args
}

fn simple_identifier(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .all(|c| c == '_' || c.is_ascii_alphanumeric())
        || matches!(trimmed.chars().next(), Some(c) if c.is_ascii_digit())
    {
        return None;
    }
    Some(trimmed)
}

fn function_summaries(
    lines: &[&str],
    spans: &[FunctionSpan],
) -> HashMap<FunctionKey, FunctionSummary> {
    let free_re = Regex::new(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)").unwrap();
    let delete_re =
        Regex::new(r"\bdelete\s*(?:\[\s*\])?\s*([A-Za-z_]\w*)\s*;").unwrap();
    let call_re = Regex::new(r"\b([A-Za-z_]\w*)\s*\(([^()]*)\)").unwrap();
    let mut key_counts: HashMap<FunctionKey, usize> = HashMap::new();

    for span in spans {
        *key_counts.entry(span.key()).or_insert(0) += 1;
    }

    let unique_keys: HashSet<FunctionKey> = key_counts
        .iter()
        .filter_map(|(key, count)| (*count == 1).then_some(key.clone()))
        .collect();

    let mut summaries: Vec<FunctionSummary> = spans
        .iter()
        .map(|span| {
            let mut summary = FunctionSummary::default();

            for line in &lines[span.start..=span.end] {
                for caps in free_re.captures_iter(line) {
                    let name = caps.get(1).unwrap().as_str();
                    if let Some(pos) = span.params.iter().position(|param| param == name) {
                        summary.freed_params.insert(pos);
                    }
                }

                for caps in delete_re.captures_iter(line) {
                    let name = caps.get(1).unwrap().as_str();
                    if let Some(pos) = span.params.iter().position(|param| param == name) {
                        summary.freed_params.insert(pos);
                    }
                }
            }

            summary
        })
        .collect();

    loop {
        let resolved: HashMap<FunctionKey, FunctionSummary> = spans
            .iter()
            .enumerate()
            .filter_map(|(index, span)| {
                let key = span.key();
                unique_keys
                    .contains(&key)
                    .then_some((key, summaries[index].clone()))
            })
            .collect();
        let snapshot = summaries.clone();
        let mut changed = false;

        for (index, span) in spans.iter().enumerate() {
            let mut summary = snapshot[index].clone();

            for line in &lines[span.start..=span.end] {
                for caps in call_re.captures_iter(line) {
                    let callee = caps.get(1).unwrap().as_str();
                    let args = split_args(caps.get(2).unwrap().as_str());
                    let key = FunctionKey {
                        name: callee.to_string(),
                        arity: args.len(),
                    };
                    let Some(callee_summary) = resolved.get(&key) else {
                        continue;
                    };

                    for param_index in &callee_summary.freed_params {
                        let Some(arg) = args.get(*param_index) else {
                            continue;
                        };
                        let Some(arg_name) = simple_identifier(arg) else {
                            continue;
                        };
                        if let Some(pos) = span.params.iter().position(|param| param == arg_name) {
                            if summary.freed_params.insert(pos) {
                                changed = true;
                            }
                        }
                    }
                }
            }

            summaries[index] = summary;
        }

        if !changed {
            break;
        }
    }

    spans
        .iter()
        .enumerate()
        .filter_map(|(index, span)| {
            let key = span.key();
            unique_keys
                .contains(&key)
                .then_some((key, summaries[index].clone()))
        })
        .collect()
}

fn has_terminator(line: &str) -> bool {
    let trimmed = line.trim();
    trimmed.starts_with("return")
        || trimmed.starts_with("throw")
        || trimmed.starts_with("goto ")
        || trimmed.starts_with("abort(")
        || trimmed.starts_with("exit(")
}

fn guard_end(lines: &[&str], index: usize, function_end: usize, match_end: usize) -> Option<usize> {
    let tail = lines[index].get(match_end..).unwrap_or("").trim();

    if has_terminator(tail) {
        return Some(index);
    }

    if tail.contains('{') {
        let mut depth = tail.chars().filter(|c| *c == '{').count() as isize
            - tail.chars().filter(|c| *c == '}').count() as isize;
        let mut end = index;
        let mut last_statement = "";

        if let Some(before_close) = tail.split('}').next() {
            let value = before_close.trim_matches(|c| c == '{' || c == ' ').trim();
            if !value.is_empty() {
                last_statement = value;
            }
        }

        if depth == 0 {
            return has_terminator(last_statement).then_some(index);
        }

        for (line_index, line) in lines
            .iter()
            .enumerate()
            .take(function_end.saturating_add(1))
            .skip(index + 1)
        {
            let open = line.chars().filter(|c| *c == '{').count() as isize;
            let close = line.chars().filter(|c| *c == '}').count() as isize;
            let before_close = line.split('}').next().unwrap_or("").trim();

            if !before_close.is_empty() {
                last_statement = before_close;
            }

            depth += open;
            depth -= close;
            end = line_index;

            if depth <= 0 {
                break;
            }
        }

        return has_terminator(last_statement).then_some(end);
    }

    for (line_index, line) in lines
        .iter()
        .enumerate()
        .take(function_end.saturating_add(1))
        .skip(index + 1)
    {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        return has_terminator(trimmed).then_some(line_index);
    }

    None
}

fn release_pointer(
    path: &Path,
    diagnostics: &mut Vec<Diagnostic>,
    facts: &mut PointerFacts,
    var: &str,
    line_num: usize,
    column: Option<usize>,
    via: Option<&str>,
) {
    if facts.state(var) == Some(PointerState::Freed) {
        let message = match via {
            Some(name) => format!("Potential double-free of '{}' through '{}'", var, name),
            None => format!("Potential double-free of '{}'", var),
        };
        diagnostics.push(Diagnostic::new(
            path,
            line_num,
            column,
            Severity::Error,
            Category::Security,
            "double-free",
            &message,
        ));
        return;
    }

    if facts.group(var).is_some() {
        facts.set_state(var, PointerState::Freed);
    } else {
        facts.bind(var, PointerState::Freed);
    }
}

fn is_assignment_target(line: &str, end: usize) -> bool {
    let tail = line.get(end..).unwrap_or("").trim_start();
    tail.starts_with('=') && !tail.starts_with("==")
}

fn release_names(
    line: &str,
    summaries: &HashMap<FunctionKey, FunctionSummary>,
    free_re: &Regex,
    delete_re: &Regex,
    call_re: &Regex,
) -> HashSet<String> {
    let mut names = HashSet::new();

    for caps in free_re.captures_iter(line) {
        names.insert(caps.get(1).unwrap().as_str().to_string());
    }

    for caps in delete_re.captures_iter(line) {
        names.insert(caps.get(1).unwrap().as_str().to_string());
    }

    for caps in call_re.captures_iter(line) {
        let callee = caps.get(1).unwrap().as_str();
        let args = split_args(caps.get(2).unwrap().as_str());
        let key = FunctionKey {
            name: callee.to_string(),
            arity: args.len(),
        };
        let Some(summary) = summaries.get(&key) else {
            continue;
        };

        for param_index in &summary.freed_params {
            let Some(arg) = args.get(*param_index) else {
                continue;
            };
            if let Some(name) = simple_identifier(arg) {
                names.insert(name.to_string());
            }
        }
    }

    names
}

pub fn analyze(path: &Path, content: &str, config: &Config) -> Vec<Diagnostic> {
    let sanitized = sanitize_source(content);
    let lines: Vec<&str> = sanitized.lines().collect();
    let spans = function_spans(&lines);
    let summaries = function_summaries(&lines, &spans);
    let allocation_re =
        Regex::new(r"\b([A-Za-z_]\w*)\s*=\s*(?:\([^;=]*\)\s*)?(?:malloc|calloc|realloc)\s*\(")
            .unwrap();
    let new_re = Regex::new(r"\b([A-Za-z_]\w*)\s*=\s*new\b").unwrap();
    let alias_re =
        Regex::new(r"\b([A-Za-z_]\w*)\s*=\s*([A-Za-z_]\w*)\s*;").unwrap();
    let assignment_re = Regex::new(r"\b([A-Za-z_]\w*)\s*=\s*[^=]").unwrap();
    let null_assign_re =
        Regex::new(r"\b([A-Za-z_]\w*)\s*=\s*(?:NULL|nullptr|0)\s*;").unwrap();
    let null_guard_re = Regex::new(
        r"\bif\s*\(\s*(?:!\s*([A-Za-z_]\w*)|([A-Za-z_]\w*)\s*==\s*(?:NULL|nullptr|0)|(?:NULL|nullptr|0)\s*==\s*([A-Za-z_]\w*))\s*\)",
    )
    .unwrap();
    let free_re = Regex::new(r"\bfree\s*\(\s*([A-Za-z_]\w*)\s*\)").unwrap();
    let delete_re =
        Regex::new(r"\bdelete\s*(?:\[\s*\])?\s*([A-Za-z_]\w*)\s*;").unwrap();
    let call_re = Regex::new(r"\b([A-Za-z_]\w*)\s*\(([^()]*)\)").unwrap();
    let arrow_index_re = Regex::new(r"\b([A-Za-z_]\w*)\s*(?:->|\[)").unwrap();
    let paren_deref_re = Regex::new(r"\(\s*\*\s*([A-Za-z_]\w*)\s*\)").unwrap();
    let unary_deref_re =
        Regex::new(r"(?:^|[=,(])\s*\*\s*([A-Za-z_]\w*)\b").unwrap();
    let ident_re = Regex::new(r"\b[A-Za-z_]\w*\b").unwrap();
    let mut diagnostics = Vec::new();

    for span in spans {
        let mut facts = PointerFacts::new();
        let mut pending_nonnull: Vec<(usize, usize)> = Vec::new();

        for index in span.start..=span.end {
            let line = lines[index];
            let line_num = index + 1;
            let mut retained = Vec::new();

            for (end, group) in pending_nonnull.drain(..) {
                if index > end {
                    facts.set_group_state(group, PointerState::NonNull);
                } else {
                    retained.push((end, group));
                }
            }
            pending_nonnull = retained;

            let releasing = release_names(line, &summaries, &free_re, &delete_re, &call_re);
            let mut reported_uaf = HashSet::new();

            for ident in ident_re.find_iter(line) {
                let name = ident.as_str();
                if facts.state(name) != Some(PointerState::Freed) {
                    continue;
                }
                if releasing.contains(name) || is_assignment_target(line, ident.end()) {
                    continue;
                }
                if reported_uaf.insert(name.to_string()) {
                    diagnostics.push(Diagnostic::new(
                        path,
                        line_num,
                        Some(ident.start() + 1),
                        Severity::Error,
                        Category::Security,
                        "use-after-free",
                        &format!("Potential use-after-free: '{}' used after release", name),
                    ));
                }
            }

            let mut handled_assignments = HashSet::new();

            if let Some(caps) = allocation_re.captures(line) {
                let var = caps.get(1).unwrap().as_str();
                facts.bind(var, PointerState::MaybeNull);
                handled_assignments.insert(var.to_string());
            } else if let Some(caps) = new_re.captures(line) {
                let var = caps.get(1).unwrap().as_str();
                let state = if line.contains("nothrow") {
                    PointerState::MaybeNull
                } else {
                    PointerState::NonNull
                };
                facts.bind(var, state);
                handled_assignments.insert(var.to_string());
            } else if let Some(caps) = null_assign_re.captures(line) {
                let var = caps.get(1).unwrap().as_str();
                facts.bind(var, PointerState::Null);
                handled_assignments.insert(var.to_string());
            } else if let Some(caps) = alias_re.captures(line) {
                let target = caps.get(1).unwrap().as_str();
                let source = caps.get(2).unwrap().as_str();
                if target != source {
                    facts.alias(target, source);
                }
                handled_assignments.insert(target.to_string());
            }

            for caps in assignment_re.captures_iter(line) {
                let target = caps.get(1).unwrap().as_str();
                if !handled_assignments.contains(target) {
                    facts.clear(target);
                }
            }

            if let Some(caps) = null_guard_re.captures(line) {
                let var = caps
                    .get(1)
                    .or_else(|| caps.get(2))
                    .or_else(|| caps.get(3))
                    .map(|m| m.as_str())
                    .unwrap();

                if let Some(group) = facts.group(var) {
                    if let Some(end) =
                        guard_end(&lines, index, span.end, caps.get(0).unwrap().end())
                    {
                        pending_nonnull.push((end, group));
                    }
                }
            }

            let mut dereferenced = HashSet::new();

            for caps in arrow_index_re.captures_iter(line) {
                dereferenced.insert(caps.get(1).unwrap().as_str().to_string());
            }
            for caps in paren_deref_re.captures_iter(line) {
                dereferenced.insert(caps.get(1).unwrap().as_str().to_string());
            }
            for caps in unary_deref_re.captures_iter(line) {
                dereferenced.insert(caps.get(1).unwrap().as_str().to_string());
            }

            for var in dereferenced {
                match facts.state(&var) {
                    Some(PointerState::Freed) if !reported_uaf.contains(&var) => {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            None,
                            Severity::Error,
                            Category::Security,
                            "use-after-free",
                            &format!(
                                "Potential use-after-free: '{}' is dereferenced after release",
                                var
                            ),
                        ));
                    }
                    Some(PointerState::MaybeNull) if config.security.check_null_deref => {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            None,
                            Severity::Warning,
                            Category::Security,
                            "null-deref",
                            &format!("Potential NULL dereference: '{}' may be NULL on this path", var),
                        ));
                    }
                    Some(PointerState::Null) if config.security.check_null_deref => {
                        diagnostics.push(Diagnostic::new(
                            path,
                            line_num,
                            None,
                            Severity::Error,
                            Category::Security,
                            "null-deref",
                            &format!("NULL pointer '{}' is dereferenced", var),
                        ));
                    }
                    _ => {}
                }
            }

            for caps in free_re.captures_iter(line) {
                let var = caps.get(1).unwrap().as_str();
                release_pointer(
                    path,
                    &mut diagnostics,
                    &mut facts,
                    var,
                    line_num,
                    Some(caps.get(1).unwrap().start() + 1),
                    None,
                );
            }

            for caps in delete_re.captures_iter(line) {
                let var = caps.get(1).unwrap().as_str();
                release_pointer(
                    path,
                    &mut diagnostics,
                    &mut facts,
                    var,
                    line_num,
                    Some(caps.get(1).unwrap().start() + 1),
                    None,
                );
            }

            for caps in call_re.captures_iter(line) {
                let callee = caps.get(1).unwrap().as_str();
                let args = split_args(caps.get(2).unwrap().as_str());
                let key = FunctionKey {
                    name: callee.to_string(),
                    arity: args.len(),
                };
                let Some(summary) = summaries.get(&key) else {
                    continue;
                };

                for param_index in &summary.freed_params {
                    let Some(arg) = args.get(*param_index) else {
                        continue;
                    };
                    let Some(var) = simple_identifier(arg) else {
                        continue;
                    };

                    release_pointer(
                        path,
                        &mut diagnostics,
                        &mut facts,
                        var,
                        line_num,
                        Some(caps.get(0).unwrap().start() + 1),
                        Some(callee),
                    );
                }
            }
        }
    }

    diagnostics
}

#[cfg(test)]
mod tests {
    use super::*;

    fn diagnostics(source: &str) -> Vec<Diagnostic> {
        analyze(Path::new("test.c"), source, &Config::default())
    }

    #[test]
    fn tracks_alias_use_after_free_across_function() {
        let source = r#"
void test(void) {
    char *p = malloc(32);
    char *q = p;
    if (!p) {
        return;
    }
    free(q);
    int a = 1;
    int b = 2;
    int c = 3;
    int d = 4;
    int e = 5;
    int f = 6;
    p[0] = 'x';
}
"#;

        assert!(diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "use-after-free"));
    }

    #[test]
    fn understands_nonnull_guard() {
        let source = r#"
void test(void) {
    char *p = malloc(32);
    if (!p) {
        return;
    }
    p[0] = 'x';
}
"#;

        assert!(!diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "null-deref"));
    }

    #[test]
    fn follows_freeing_function_summary() {
        let source = r#"
void destroy(char *p) {
    free(p);
}

void test(void) {
    char *p = malloc(32);
    if (!p) {
        return;
    }
    destroy(p);
    p[0] = 'x';
}
"#;

        assert!(diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "use-after-free"));
    }

    #[test]
    fn detects_double_free_through_alias() {
        let source = r#"
void test(void) {
    char *p = malloc(32);
    char *q = p;
    free(q);
    free(p);
}
"#;

        assert!(diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "double-free"));
    }

    #[test]
    fn ignores_line_comment_release() {
        let source = r#"
void test(void) {
    char *p = malloc(32);
    if (!p) {
        return;
    }
    // free(p);
    p[0] = 'x';
}
"#;

        assert!(!diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "use-after-free"));
    }

    #[test]
    fn ignores_block_comment_release() {
        let source = r#"
void test(void) {
    char *p = malloc(32);
    if (!p) {
        return;
    }
    /* free(p); */
    p[0] = 'x';
}
"#;

        assert!(!diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "use-after-free"));
    }

    #[test]
    fn ignores_string_release() {
        let source = r#"
void test(void) {
    char *p = malloc(32);
    if (!p) {
        return;
    }
    const char *text = "free(p);";
    p[0] = 'x';
}
"#;

        assert!(!diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "use-after-free"));
    }

    #[test]
    fn reassignment_clears_freed_state() {
        let source = r#"
void test(void) {
    char *p = malloc(32);
    free(p);
    p = malloc(64);
    if (!p) {
        return;
    }
    p[0] = 'x';
}
"#;

        let found = diagnostics(source);
        assert!(!found
            .iter()
            .any(|diag| diag.rule == "use-after-free" && diag.line > 5));
    }

    #[test]
    fn assert_does_not_prove_nonnull() {
        let source = r#"
void test(void) {
    char *p = malloc(32);
    assert(p);
    p[0] = 'x';
}
"#;

        assert!(diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "null-deref"));
    }

    #[test]
    fn ambiguous_overload_summary_is_ignored() {
        let source = r#"
void destroy(char *p) {
    free(p);
}

void destroy(int *p) {
    int value = 1;
}

void test(void) {
    char *p = malloc(32);
    if (!p) {
        return;
    }
    destroy(p);
    p[0] = 'x';
}
"#;

        assert!(!diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "use-after-free"));
    }

    #[test]
    fn detects_general_use_after_release() {
        let source = r#"
void consume(char *p) {
    int value = 1;
}

void test(void) {
    char *p = malloc(32);
    if (!p) {
        return;
    }
    free(p);
    consume(p);
}
"#;

        assert!(diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "use-after-free"));
    }

    #[test]
    fn safe_use_before_release_is_not_flagged() {
        let source = r#"
void consume(char *p) {
    int value = 1;
}

void test(void) {
    char *p = malloc(32);
    if (!p) {
        return;
    }
    consume(p);
    free(p);
}
"#;

        assert!(!diagnostics(source)
            .iter()
            .any(|diag| diag.rule == "use-after-free"));
    }
}
