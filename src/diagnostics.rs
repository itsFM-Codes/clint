use colored::Colorize;
use std::fmt;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Info => write!(f, "info"),
            Severity::Warning => write!(f, "warning"),
            Severity::Error => write!(f, "error"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Category {
    UnsafeFunction,
    Style,
    Security,
    BestPractice,
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::UnsafeFunction => write!(f, "unsafe-function"),
            Category::Style => write!(f, "style"),
            Category::Security => write!(f, "security"),
            Category::BestPractice => write!(f, "best-practice"),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Diagnostic {
    pub file: PathBuf,
    pub line: usize,
    pub column: Option<usize>,
    pub severity: Severity,
    pub category: Category,
    pub rule: String,
    pub message: String,
}

impl Diagnostic {
    pub fn new(
        file: &Path,
        line: usize,
        column: Option<usize>,
        severity: Severity,
        category: Category,
        rule: &str,
        message: &str,
    ) -> Self {
        Self {
            file: file.to_path_buf(),
            line,
            column,
            severity,
            category,
            rule: rule.to_string(),
            message: message.to_string(),
        }
    }

    pub fn format_colored(&self) -> String {
        let location = match self.column {
            Some(col) => format!("{}:{}:{}", self.file.display(), self.line, col),
            None => format!("{}:{}", self.file.display(), self.line),
        };

        let severity_str = match self.severity {
            Severity::Error => "error".red().bold().to_string(),
            Severity::Warning => "warning".yellow().bold().to_string(),
            Severity::Info => "info".blue().bold().to_string(),
        };

        format!(
            "{}: {} [{}:{}] {}",
            location.white().bold(),
            severity_str,
            self.category.to_string().dimmed(),
            self.rule.dimmed(),
            self.message
        )
    }

    pub fn format_plain(&self) -> String {
        let location = match self.column {
            Some(col) => format!("{}:{}:{}", self.file.display(), self.line, col),
            None => format!("{}:{}", self.file.display(), self.line),
        };

        format!(
            "{}: {} [{}:{}] {}",
            location,
            self.severity,
            self.category,
            self.rule,
            self.message
        )
    }
}

#[derive(Debug, Default)]
pub struct DiagnosticCollection {
    pub diagnostics: Vec<Diagnostic>,
}

impl DiagnosticCollection {
    pub fn new() -> Self {
        Self {
            diagnostics: Vec::new(),
        }
    }

    #[allow(dead_code)]
    pub fn add(&mut self, diag: Diagnostic) {
        self.diagnostics.push(diag);
    }

    pub fn extend(&mut self, diags: Vec<Diagnostic>) {
        self.diagnostics.extend(diags);
    }

    pub fn error_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Error)
            .count()
    }

    pub fn warning_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Warning)
            .count()
    }

    pub fn info_count(&self) -> usize {
        self.diagnostics
            .iter()
            .filter(|d| d.severity == Severity::Info)
            .count()
    }

    pub fn total(&self) -> usize {
        self.diagnostics.len()
    }

    pub fn sort(&mut self) {
        self.diagnostics.sort_by(|a, b| {
            a.file
                .cmp(&b.file)
                .then(a.line.cmp(&b.line))
                .then(a.severity.cmp(&b.severity))
        });
    }

    pub fn print_colored(&self) {
        for d in &self.diagnostics {
            println!("{}", d.format_colored());
        }
    }

    pub fn print_plain(&self) {
        for d in &self.diagnostics {
            println!("{}", d.format_plain());
        }
    }

    pub fn print_summary(&self) {
        let errors = self.error_count();
        let warnings = self.warning_count();
        let infos = self.info_count();

        println!();
        if self.total() == 0 {
            println!("{}", "No issues found.".green().bold());
        } else {
            println!(
                "{} {} found: {} {}, {} {}, {} {}",
                self.total().to_string().bold(),
                if self.total() == 1 { "issue" } else { "issues" },
                errors.to_string().red().bold(),
                if errors == 1 { "error" } else { "errors" },
                warnings.to_string().yellow().bold(),
                if warnings == 1 { "warning" } else { "warnings" },
                infos.to_string().blue().bold(),
                if infos == 1 { "info" } else { "infos" },
            );
        }
    }
}
