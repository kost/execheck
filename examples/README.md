# ExeCheck Library Examples

This directory contains examples demonstrating how to use ExeCheck as a Rust library.

## Running Examples

```bash
# Simple file analysis
cargo run --example simple_analysis

# Directory scanning with filtering  
cargo run --example directory_scan

# JSON output for programmatic use
cargo run --example json_output

# Custom filtering and analysis
cargo run --example custom_filter
```

## Example Descriptions

### `simple_analysis.rs`
Demonstrates basic file analysis functionality:
- Analyzing a single executable file
- Accessing security check results
- Creating and printing reports

### `directory_scan.rs` 
Shows directory scanning capabilities:
- Configuring scan options
- Filtering for issues-only results
- Processing scan summaries

### `json_output.rs`
Illustrates programmatic usage:
- Analyzing multiple files
- Generating JSON output
- Error handling for batch processing

### `custom_filter.rs`
Advanced usage patterns:
- Custom filtering of results
- Security score calculations  
- Targeted analysis of specific security features

## Library Integration Patterns

### Basic Analysis
```rust
use execheck::{analyze_file, SecurityCheck};
use std::path::PathBuf;

let result = analyze_file(&PathBuf::from("/bin/ls"))?;
println!("Security status: {}", result.overall_status);
```

### Batch Processing
```rust
use execheck::{analyze_files, ScanOptions};

let options = ScanOptions {
    recursive: true,
    issues_only: false,
    strict: false,
};

let report = analyze_files(file_list, &options)?;
```

### Custom Output Handling
```rust
use execheck::{print_report, OutputFormat};

// Print to stdout
print_report(&report, &OutputFormat::Json, None)?;

// Save to file
print_report(&report, &OutputFormat::Yaml, Some(&PathBuf::from("report.yaml")))?;
```

## Error Handling

All examples include proper error handling patterns. The library returns `anyhow::Result` types, making error propagation and handling straightforward.

## Integration with Other Tools

The JSON and CSV output formats make it easy to integrate ExeCheck with:
- CI/CD pipelines
- Security monitoring systems
- Compliance reporting tools
- Data analysis workflows