use crate::config::Config;
use crate::diagnostics::DiagnosticCollection;
use crate::rules::best_practices::BestPracticesRule;
use crate::rules::security::SecurityRule;
use crate::rules::style::StyleRule;
use crate::rules::unsafe_functions::UnsafeFunctionsRule;
use crate::rules::Rule;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

pub struct Linter {
    config: Config,
    root: PathBuf,
    rules: Vec<Box<dyn Rule>>,
}

impl Linter {
    pub fn new(config: Config, root: PathBuf) -> Self {
        let rules: Vec<Box<dyn Rule>> = vec![
            Box::new(UnsafeFunctionsRule),
            Box::new(StyleRule),
            Box::new(SecurityRule),
            Box::new(BestPracticesRule),
        ];

        Self {
            config,
            root,
            rules,
        }
    }

    pub fn lint_files(&self, paths: &[PathBuf]) -> DiagnosticCollection {
        let mut collection = DiagnosticCollection::new();

        for path in paths {
            if path.is_file() {
                if self.config.should_lint(path) && !self.config.is_excluded(path, &self.root) {
                    self.lint_file(path, &mut collection);
                }
            } else if path.is_dir() {
                self.lint_directory(path, &mut collection);
            }
        }

        collection.sort();
        collection
    }

    pub fn lint_all(&self) -> DiagnosticCollection {
        let mut collection = DiagnosticCollection::new();
        self.lint_directory(&self.root, &mut collection);
        collection.sort();
        collection
    }

    fn lint_directory(&self, dir: &Path, collection: &mut DiagnosticCollection) {
        for entry in WalkDir::new(dir)
            .into_iter()
            .filter_entry(|e| {
                let path = e.path();
                // Skip hidden directories (except .clint itself is fine to skip)
                if path.is_dir() {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        if name.starts_with('.') {
                            return false;
                        }
                    }
                }
                !self.config.is_excluded(path, &self.root)
            })
            .filter_map(|e| e.ok())
        {
            let path = entry.path();
            if path.is_file() && self.config.should_lint(path) {
                self.lint_file(path, collection);
            }
        }
    }

    fn lint_file(&self, path: &Path, collection: &mut DiagnosticCollection) {
        let content = match std::fs::read_to_string(path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Warning: could not read '{}': {}", path.display(), e);
                return;
            }
        };

        for rule in &self.rules {
            let diags = rule.check(path, &content, &self.config);
            collection.extend(diags);
        }
    }
}
