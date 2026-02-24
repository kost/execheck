# ExeCheck Library Usage Guide

ExeCheck can be used both as a command-line tool and as a Rust library. This guide covers using it as a library in your own Rust projects.

## Adding ExeCheck as a Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
execheck = "0.2.0"
```

## Core Concepts

### SecurityCheck
The `SecurityCheck` struct represents the analysis result for a single executable:

```rust
pub struct SecurityCheck {
    pub file_path: String,
    pub file_type: String,          // "ELF", "PE", "Mach-O"
    pub checks: HashMap<String, String>,
    pub overall_status: String,     // "Secure", "Mostly Secure", "Insecure"
}
```

### SecurityReport
The `SecurityReport` struct contains analysis results for multiple files:

```rust
pub struct SecurityReport {
    pub files: Vec<SecurityCheck>,
    pub summary: ReportSummary,
}
```

### ScanOptions
Configuration for directory scanning:

```rust
pub struct ScanOptions {
    pub recursive: bool,        // Recursive directory traversal
    pub issues_only: bool,      // Only return files with issues
    pub strict: bool,           // Enable strict error handling
    pub file_filter: FileFilter, // File type filtering
    pub one_filesystem: bool,   // Stay within single filesystem (Unix)
}
```

### FileFilter
File type filtering options:

```rust
pub enum FileFilter {
    All,                                    // All executable files (default)
    WindowsExecutables,                     // Only .exe files
    WindowsDlls,                           // Only .dll files  
    WindowsExecutablesAndDlls,             // Both .exe and .dll files
    Extensions(Vec<String>),               // Custom file extensions
    Custom(fn(&std::path::Path) -> bool),  // Custom predicate function
}
```

## Basic Usage

### Analyze a Single File

```rust
use execheck::analyze_file;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let result = analyze_file(&PathBuf::from("/bin/ls"))?;
    
    println!("File: {}", result.file_path);
    println!("Type: {}", result.file_type);
    println!("Status: {}", result.overall_status);
    
    // Check specific security features
    if let Some(canary) = result.checks.get("canary") {
        println!("Stack canary: {}", canary);
    }
    
    Ok(())
}
```

### Scan a Directory

```rust
use execheck::{scan_directory, ScanOptions, FileFilter};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let options = ScanOptions {
        recursive: true,
        issues_only: false,
        strict: false,
        file_filter: FileFilter::All,
        one_filesystem: false,
    };
    
    let report = scan_directory(&PathBuf::from("/usr/bin"), &options)?;
    
    println!("Analyzed {} files", report.summary.total_files);
    println!("Secure: {}, Issues: {}", 
        report.summary.secure_files, 
        report.summary.insecure_files);
    
    Ok(())
}
```

## Advanced Usage

### File Type Filtering

The library supports advanced file filtering for targeted analysis:

```rust
use execheck::{collect_executable_files, ScanOptions, FileFilter};
use std::path::PathBuf;

// Filter only Windows executables
let exe_options = ScanOptions {
    recursive: true,
    file_filter: FileFilter::WindowsExecutables,
    ..Default::default()
};

// Filter only DLLs
let dll_options = ScanOptions {
    recursive: true,
    file_filter: FileFilter::WindowsDlls,
    ..Default::default()
};

// Custom extension filtering
let custom_options = ScanOptions {
    recursive: true,
    file_filter: FileFilter::Extensions(vec![
        "exe".to_string(),
        "dll".to_string(),
        "so".to_string(),
    ]),
    ..Default::default()
};

// Custom predicate filtering
let lib_filter = |path: &std::path::Path| {
    path.file_name()
        .and_then(|name| name.to_str())
        .map_or(false, |name| name.contains("lib"))
};

let predicate_options = ScanOptions {
    recursive: true,
    file_filter: FileFilter::Custom(lib_filter),
    ..Default::default()
};
```

### Filesystem Boundaries (Unix Only)

On Unix-like systems, you can restrict scanning to a single filesystem:

```rust
use execheck::{scan_directory, ScanOptions, FileFilter};
use std::path::PathBuf;

let options = ScanOptions {
    recursive: true,
    one_filesystem: true,  // Don't cross filesystem boundaries
    file_filter: FileFilter::All,
    ..Default::default()
};

// This will scan /usr but won't cross into /proc, /sys, mounted drives, etc.
let report = scan_directory(&PathBuf::from("/usr"), &options)?;
```

### Advanced Usage Patterns

### Custom File Collection

```rust
use execheck::{collect_executable_files, analyze_files, ScanOptions};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Collect files from multiple directories
    let mut all_files = Vec::new();
    let options = ScanOptions {
        recursive: false,
        ..Default::default()
    };
    all_files.extend(collect_executable_files(&PathBuf::from("/bin"), &options)?);
    all_files.extend(collect_executable_files(&PathBuf::from("/usr/bin"), &options)?);
    
    // Analyze with the same options
    let report = analyze_files(all_files, &options)?;
    
    // Process results...
    Ok(())
}
```

### Custom Filtering

```rust
use execheck::{analyze_files, SecurityCheck};

fn find_files_missing_pie(results: &[SecurityCheck]) -> Vec<&SecurityCheck> {
    results.iter()
        .filter(|check| {
            check.checks.get("pie")
                .map_or(false, |v| v.contains("Disabled"))
        })
        .collect()
}

fn calculate_security_score(results: &[SecurityCheck]) -> f64 {
    if results.is_empty() {
        return 0.0;
    }
    
    let secure_count = results.iter()
        .filter(|check| check.overall_status == "Secure")
        .count();
        
    (secure_count as f64 / results.len() as f64) * 100.0
}
```

## Output Formats

### Generate Reports

```rust
use execheck::{print_report, OutputFormat};
use std::path::PathBuf;

// Print to stdout
print_report(&report, &OutputFormat::Human, None)?;

// Save to file
print_report(&report, &OutputFormat::Json, 
    Some(&PathBuf::from("security_report.json")))?;

// Available formats: Human, Json, Yaml, Xml, Csv
```

### Direct JSON Serialization

```rust
use serde_json;

let json = serde_json::to_string_pretty(&report)?;
println!("{}", json);
```

## Platform-Specific Checks

### Linux ELF
- `canary`: Stack canary protection
- `nx`: Non-executable stack
- `pie`: Position Independent Executable
- `relro`: Relocation Read-Only (Full/Partial)
- `rpath`/`runpath`: Runtime library paths
- `symbols`: Symbol table presence
- `fortified`: Number of fortified functions
- `fortifyable`: Number of fortifiable functions
- `cet`: Control-flow Enforcement Technology

### Windows PE
- `dynamic_base`: ASLR support
- `high_entropy_va`: 64-bit ASLR
- `force_integrity`: Code integrity
- `isolation`: Process isolation
- `nx`: Data Execution Prevention
- `seh`: Structured Exception Handling
- `cfg`: Control Flow Guard
- `rfg`: Return Flow Guard
- `safe_seh`: Safe SEH
- `gs`: Stack cookies
- `authenticode`: Code signing
- `dotnet`: .NET runtime

### macOS Mach-O
- `pie`: Position Independent Executable
- `canary`: Stack protection
- `nx`: Non-executable memory
- `arc`: Automatic Reference Counting
- `encrypted`: Binary encryption
- `code_signature`: Code signing

## Error Handling

All functions return `anyhow::Result` types:

```rust
use anyhow::Result;

fn analyze_with_error_handling() -> Result<()> {
    match analyze_file(&PathBuf::from("/some/file")) {
        Ok(result) => {
            println!("Analysis successful: {}", result.overall_status);
        }
        Err(e) => {
            eprintln!("Analysis failed: {}", e);
            // Handle error appropriately
        }
    }
    Ok(())
}
```

## Performance Considerations

### Large Directories
For large directories, consider:
- Using `issues_only: true` to reduce output
- Processing files in batches
- Implementing custom progress reporting

```rust
use execheck::{collect_executable_files, analyze_file};

fn analyze_large_directory(dir: &PathBuf) -> Result<()> {
    let files = collect_executable_files(dir, true)?;
    
    println!("Found {} files to analyze", files.len());
    
    for (i, file) in files.iter().enumerate() {
        if i % 100 == 0 {
            println!("Progress: {}/{}", i, files.len());
        }
        
        match analyze_file(file) {
            Ok(result) => {
                if result.overall_status != "Secure" {
                    println!("Issue in {}: {}", file.display(), result.overall_status);
                }
            }
            Err(e) => {
                eprintln!("Failed to analyze {}: {}", file.display(), e);
            }
        }
    }
    
    Ok(())
}
```

### Memory Usage
The library loads entire files into memory for analysis. For very large binaries or when processing many files simultaneously, monitor memory usage and consider processing files in smaller batches.

## Integration Patterns

### CI/CD Integration

```rust
use execheck::{scan_directory, ScanOptions};

fn ci_security_check() -> Result<()> {
    let options = ScanOptions {
        recursive: true,
        issues_only: true,
        strict: true,
    };
    
    let report = scan_directory(&PathBuf::from("./target/release"), &options)?;
    
    if report.summary.insecure_files > 0 {
        eprintln!("Security issues found in {} files", report.summary.insecure_files);
        std::process::exit(1);
    }
    
    println!("All binaries passed security checks!");
    Ok(())
}
```

### Custom Reporting

```rust
use execheck::{SecurityCheck, SecurityReport};

fn generate_custom_report(report: &SecurityReport) {
    println!("=== Security Analysis Report ===");
    
    // Summary
    println!("Total files: {}", report.summary.total_files);
    println!("Security score: {:.1}%", 
        (report.summary.secure_files as f64 / report.summary.total_files as f64) * 100.0);
    
    // Group by file type
    let mut elf_count = 0;
    let mut pe_count = 0;
    let mut macho_count = 0;
    
    for check in &report.files {
        match check.file_type.as_str() {
            "ELF" => elf_count += 1,
            "PE" => pe_count += 1,
            "Mach-O" => macho_count += 1,
            _ => {}
        }
    }
    
    println!("File types: ELF: {}, PE: {}, Mach-O: {}", elf_count, pe_count, macho_count);
}
```

This comprehensive library interface makes ExeCheck suitable for integration into larger security analysis workflows, CI/CD pipelines, and custom security tooling.