use serde::Deserialize;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct Config {
    pub general: GeneralConfig,
    pub unsafe_functions: UnsafeFunctionsConfig,
    pub style: StyleConfig,
    pub security: SecurityConfig,
    pub best_practices: BestPracticesConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct GeneralConfig {
    pub enabled: bool,
    pub extensions: Vec<String>,
    pub exclude: Vec<String>,
    pub severity_level: String, // "error", "warning", "info"
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct UnsafeFunctionsConfig {
    pub enabled: bool,
    pub banned: Vec<String>,
    pub extra_banned: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct StyleConfig {
    pub enabled: bool,
    pub max_line_length: usize,
    pub indent_width: usize,
    pub indent_style: String, // "spaces" or "tabs"
    pub brace_style: String,  // "k&r" or "allman"
    pub trailing_whitespace: bool,
    pub require_braces: bool,
    pub max_function_lines: usize,
    pub naming: NamingConfig,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct NamingConfig {
    pub functions: String,       // "snake_case", "camelCase", "PascalCase"
    pub variables: String,       // "snake_case", "camelCase"
    pub macros: String,          // "UPPER_SNAKE_CASE"
    pub types: String,           // "PascalCase", "snake_case"
    pub constants: String,       // "UPPER_SNAKE_CASE", "k_prefixed"
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub check_format_strings: bool,
    pub check_buffer_overflow: bool,
    pub check_integer_overflow: bool,
    pub check_null_deref: bool,
    pub ban_system_calls: bool,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(default)]
pub struct BestPracticesConfig {
    pub enabled: bool,
    pub require_include_guards: bool,
    pub ban_goto: bool,
    pub check_magic_numbers: bool,
    pub max_nesting_depth: usize,
    pub require_default_in_switch: bool,
    pub check_implicit_fallthrough: bool,
    pub warn_todo_comments: bool,
    pub max_function_params: usize,
    pub check_unused_includes: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            unsafe_functions: UnsafeFunctionsConfig::default(),
            style: StyleConfig::default(),
            security: SecurityConfig::default(),
            best_practices: BestPracticesConfig::default(),
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            extensions: vec![
                "c".into(), "h".into(), "cpp".into(), "hpp".into(),
                "cc".into(), "cxx".into(), "hxx".into(), "c++".into(),
            ],
            exclude: vec!["build".into(), "vendor".into(), "third_party".into()],
            severity_level: "warning".into(),
        }
    }
}

impl Default for UnsafeFunctionsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            banned: vec![
                "gets".into(), "strcpy".into(), "strcat".into(),
                "sprintf".into(), "vsprintf".into(), "scanf".into(),
                "sscanf".into(), "fscanf".into(), "tmpnam".into(),
                "mktemp".into(), "getpw".into(), "getlogin".into(),
            ],
            extra_banned: vec![],
        }
    }
}

impl Default for StyleConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_line_length: 120,
            indent_width: 4,
            indent_style: "spaces".into(),
            brace_style: "k&r".into(),
            trailing_whitespace: true,
            require_braces: true,
            max_function_lines: 100,
            naming: NamingConfig::default(),
        }
    }
}

impl Default for NamingConfig {
    fn default() -> Self {
        Self {
            functions: "snake_case".into(),
            variables: "snake_case".into(),
            macros: "UPPER_SNAKE_CASE".into(),
            types: "PascalCase".into(),
            constants: "UPPER_SNAKE_CASE".into(),
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            check_format_strings: true,
            check_buffer_overflow: true,
            check_integer_overflow: true,
            check_null_deref: true,
            ban_system_calls: false,
        }
    }
}

impl Default for BestPracticesConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            require_include_guards: true,
            ban_goto: true,
            check_magic_numbers: true,
            max_nesting_depth: 4,
            require_default_in_switch: true,
            check_implicit_fallthrough: true,
            warn_todo_comments: true,
            max_function_params: 6,
            check_unused_includes: false,
        }
    }
}

impl Config {
    pub fn load(project_root: &Path) -> Result<Self, String> {
        let config_path = project_root.join(".clint").join("config.toml");
        if !config_path.exists() {
            return Err(format!(
                "No .clint/config.toml found at '{}'. Create a .clint directory with a config.toml file.",
                config_path.display()
            ));
        }

        let content = std::fs::read_to_string(&config_path)
            .map_err(|e| format!("Failed to read config: {}", e))?;

        let config: Config = toml::from_str(&content)
            .map_err(|e| format!("Failed to parse config: {}", e))?;

        Ok(config)
    }

    pub fn all_banned_functions(&self) -> HashSet<String> {
        let mut set: HashSet<String> = self.unsafe_functions.banned.iter().cloned().collect();
        set.extend(self.unsafe_functions.extra_banned.iter().cloned());
        set
    }

    pub fn should_lint(&self, path: &Path) -> bool {
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            self.general.extensions.contains(&ext.to_lowercase())
        } else {
            false
        }
    }

    pub fn is_excluded(&self, path: &Path, root: &Path) -> bool {
        if let Ok(rel) = path.strip_prefix(root) {
            let rel_str = rel.to_string_lossy();
            for pattern in &self.general.exclude {
                if rel_str.starts_with(pattern) || rel_str.contains(&format!("/{}/", pattern)) {
                    return true;
                }
            }
        }
        false
    }

    pub fn find_project_root() -> Result<PathBuf, String> {
        let mut dir = std::env::current_dir()
            .map_err(|e| format!("Cannot determine current directory: {}", e))?;

        loop {
            if dir.join(".clint").is_dir() {
                return Ok(dir);
            }
            if !dir.pop() {
                break;
            }
        }

        Err("No .clint directory found in current or parent directories.".into())
    }
}
