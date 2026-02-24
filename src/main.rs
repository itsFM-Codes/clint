mod config;
mod diagnostics;
mod linter;
mod rules;

use clap::{Parser, Subcommand};
use colored::Colorize;
use config::Config;
use linter::Linter;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(name = "clint", version, about = "A fast C/C++ linter")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Files or directories to lint (defaults to current directory)
    #[arg(global = true)]
    paths: Vec<PathBuf>,

    /// Disable colored output
    #[arg(long, global = true)]
    no_color: bool,

    /// Treat warnings as errors
    #[arg(long, short = 'W', global = true)]
    werror: bool,

    /// Output format: "pretty" or "plain"
    #[arg(long, default_value = "pretty", global = true)]
    format: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a .clint directory with a default config
    Init,
    /// Check files (default action)
    Check {
        /// Files or directories to lint
        paths: Vec<PathBuf>,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Init) => cmd_init(),
        Some(Commands::Check { ref paths }) => cmd_check(&cli, paths),
        None => {
            if cli.paths.is_empty() {
                cmd_check(&cli, &[]);
            } else {
                cmd_check(&cli, &cli.paths);
            }
        }
    }
}

fn cmd_init() {
    let cwd = std::env::current_dir().expect("Cannot determine current directory");
    let clint_dir = cwd.join(".clint");

    if clint_dir.exists() {
        eprintln!(
            "{} .clint directory already exists",
            "error:".red().bold()
        );
        process::exit(1);
    }

    std::fs::create_dir_all(&clint_dir).expect("Failed to create .clint directory");
    let config_content = include_str!("default_config.toml");
    std::fs::write(clint_dir.join("config.toml"), config_content)
        .expect("Failed to write config.toml");

    println!(
        "{} Created .clint/config.toml with default settings",
        "done:".green().bold()
    );
    println!("Edit .clint/config.toml to customize rules for your project.");
}

fn cmd_check(cli: &Cli, paths: &[PathBuf]) {
    let root = match Config::find_project_root() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            eprintln!("Run 'clint init' to create a default configuration.");
            process::exit(1);
        }
    };

    let config = match Config::load(&root) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{} {}", "error:".red().bold(), e);
            process::exit(1);
        }
    };

    if !config.general.enabled {
        println!("Linting is disabled in config.");
        return;
    }

    let linter = Linter::new(config, root.clone());

    let collection = if paths.is_empty() {
        linter.lint_all()
    } else {
        let abs_paths: Vec<PathBuf> = paths
            .iter()
            .map(|p| {
                if p.is_absolute() {
                    p.clone()
                } else {
                    std::env::current_dir().unwrap().join(p)
                }
            })
            .collect();
        linter.lint_files(&abs_paths)
    };

    if cli.no_color || cli.format == "plain" {
        collection.print_plain();
    } else {
        collection.print_colored();
    }
    collection.print_summary();

    let exit_code = if collection.error_count() > 0 {
        1
    } else if cli.werror && collection.warning_count() > 0 {
        1
    } else {
        0
    };

    process::exit(exit_code);
}
