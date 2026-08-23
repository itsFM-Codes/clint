pub mod unsafe_functions;
pub mod style;
pub mod security;
pub mod best_practices;
pub mod semantics;

use crate::config::Config;
use crate::diagnostics::Diagnostic;
use std::path::Path;

pub trait Rule {
    fn check(&self, path: &Path, content: &str, config: &Config) -> Vec<Diagnostic>;
}
