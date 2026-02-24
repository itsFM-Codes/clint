# clint

A fast C/C++ linter for detecting errors, enforcing style, finding security vulnerabilities, and checking best practices.

## Installation

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
# Binary is at target/release/clint (or clint.exe on Windows)
```

## Quick Start

```bash
# Initialize config in your C/C++ project
cd your-project
clint init

# Run the linter
clint

# Lint specific files
clint check src/main.c src/utils.h

# Treat warnings as errors (for CI)
clint -W
```

## Configuration

`clint` requires a `.clint/config.toml` file in your project root. Run `clint init` to generate one with defaults.

### Config Sections

**`[general]`** — Global settings: file extensions, exclusions, severity level.

**`[unsafe_functions]`** — Ban dangerous C functions (`gets`, `strcpy`, `sprintf`, etc.) with suggestions for safe alternatives. Add custom banned functions via `extra_banned`.

**`[style]`** — Line length, indentation (tabs/spaces), brace style (K&R/Allman), trailing whitespace, function length limits, required braces for control flow, and naming conventions for functions/variables/macros/types.

**`[security]`** — Format string vulnerabilities, buffer overflow patterns, integer overflow risks, NULL dereference detection, use-after-free, double-free, and optional system call banning.

**`[best_practices]`** — Include guards, goto detection, magic numbers, nesting depth limits, switch/case completeness, TODO/FIXME flagging, and function parameter count limits.

### Example Config

```toml
[general]
enabled = true
extensions = ["c", "h", "cpp", "hpp"]
exclude = ["build", "vendor"]

[unsafe_functions]
enabled = true
banned = ["gets", "strcpy", "strcat", "sprintf"]
extra_banned = ["my_legacy_func"]

[style]
enabled = true
max_line_length = 100
indent_width = 4
indent_style = "spaces"
brace_style = "k&r"
max_function_lines = 80

[style.naming]
functions = "snake_case"
macros = "UPPER_SNAKE_CASE"

[security]
enabled = true
ban_system_calls = true

[best_practices]
enabled = true
max_nesting_depth = 4
max_function_params = 5
```

## Rules

| Category | Rule | Severity | Description |
|----------|------|----------|-------------|
| unsafe-function | banned-function | error | Banned unsafe C function call |
| style | line-length | warning | Line exceeds max length |
| style | trailing-whitespace | warning | Trailing whitespace |
| style | indent-style | warning | Wrong indentation style |
| style | brace-style | warning | Wrong brace placement |
| style | require-braces | warning | Missing braces on control flow |
| style | function-length | warning | Function too long |
| style | naming-convention | warning | Name doesn't match convention |
| security | format-string | error | Non-literal format string |
| security | buffer-overflow | error/warning | Buffer overflow risk |
| security | integer-overflow | warning | Integer overflow risk |
| security | null-deref | warning | Missing NULL check |
| security | use-after-free | error | Use after free() |
| security | double-free | error | Double free() |
| security | system-call | error | Dangerous system call |
| security | alloca | warning | Stack overflow risk with alloca |
| best-practice | include-guard | warning | Missing header guard |
| best-practice | goto | warning | goto usage |
| best-practice | magic-number | info | Magic number literal |
| best-practice | nesting-depth | warning | Excessive nesting |
| best-practice | switch-default | warning | Missing default case |
| best-practice | implicit-fallthrough | warning | Missing break in case |
| best-practice | todo-comment | info/warning | TODO/FIXME/HACK comment |
| best-practice | too-many-params | warning | Too many function params |

## CLI Options

```
clint [OPTIONS] [PATHS...] [COMMAND]

Commands:
  init     Create .clint/config.toml with defaults
  check    Lint specific files/directories

Options:
  --no-color     Disable colored output
  -W, --werror   Treat warnings as errors
  --format       Output format: "pretty" or "plain"
  -h, --help     Print help
  -V, --version  Print version
```

## Troubleshooting

### Output Not Displaying

If running `clint check` produces no visible output, it's likely due to output buffering. Force output to display by redirecting stderr and explicitly capturing it:

```bash
# PowerShell
$output = & clint check 2>&1; $output

# Bash/Unix
clint check 2>&1 | cat
```

This is a known issue with large outputs in some terminal environments. The linter still runs correctly; the output just isn't flushed to the display.

## License

MIT
