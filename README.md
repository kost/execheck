# ExeCheck - Multi-Platform Executable Security Checker

A comprehensive security checker for Linux (ELF), Windows (PE), and macOS (Mach-O) executables, written in Rust. ExeCheck can be used both as a **command-line tool** and as a **Rust library** for integration into other projects.

[![Crates.io](https://img.shields.io/crates/v/execheck.svg)](https://crates.io/crates/execheck)
[![Documentation](https://docs.rs/execheck/badge.svg)](https://docs.rs/execheck)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE)

## Quick Start

### As a Library
```toml
[dependencies]
execheck = "0.2.0"
```

```rust
use execheck::{analyze_file, print_report, OutputFormat};
use std::path::PathBuf;

let result = analyze_file(&PathBuf::from("/bin/ls"))?;
println!("Security status: {}", result.overall_status);
```

### As a CLI Tool
```bash
# Install from source
cargo install --path .

# Analyze a single file
execheck /bin/ls

# Scan directory with JSON output
execheck /usr/bin --recursive --output json
```

## Features

### Supported Platforms
- **Linux ELF**: Complete security analysis
- **Windows PE**: Comprehensive Windows-specific security checks  
- **macOS Mach-O**: Basic security analysis (some features simplified)

### Security Checks

#### Linux ELF
- **Stack Canary**: Detects stack smashing protection (`__stack_chk_fail`)
- **NX/DEP**: Non-executable stack protection
- **PIE**: Position Independent Executable
- **RELRO**: Relocation Read-Only (Partial/Full)
- **RPATH/RUNPATH**: Runtime library path analysis
- **Symbol Stripping**: Checks if symbols are stripped
- **FORTIFY**: Source fortification analysis (fortified/fortifiable functions)
- **CET**: Control-flow Enforcement Technology (IBT/SHSTK)

#### Windows PE
- **Dynamic Base**: ASLR support (`/DYNAMICBASE`)
- **High Entropy VA**: 64-bit ASLR (`/HIGHENTROPYVA`)
- **Force Integrity**: Code integrity (`/INTEGRITYCHECK`)
- **Isolation**: Process isolation (`/ALLOWISOLATION`)
- **NX/DEP**: Data Execution Prevention (`/NXCOMPAT`)
- **SEH**: Structured Exception Handling
- **CFG**: Control Flow Guard
- **RFG**: Return Flow Guard
- **SafeSEH**: Safe Structured Exception Handling
- **GS**: Stack Cookie (`/GS`)
- **Authenticode**: Code signing verification
- **.NET**: Managed code detection

#### macOS Mach-O
- **PIE**: Position Independent Executable
- **Stack Canary**: Stack protection detection
- **NX**: Non-executable memory protection
- **ARC**: Automatic Reference Counting
- **Encryption**: Binary encryption analysis
- **Code Signature**: Code signing verification
- **Fat Binaries**: Complete support for universal binaries with per-architecture analysis

### Output Formats
- **Human-readable** (default): Colored, formatted output with security status indicators
- **JSON**: Machine-readable JSON format
- **YAML**: YAML format for configuration files
- **XML**: Structured XML output
- **CSV**: Comma-separated values for spreadsheet analysis

### Scanning Options
- **Single file analysis**: Analyze individual executables
- **Directory scanning**: Scan directories with optional recursion
- **Issues-only mode**: Show only files with security issues
- **Strict mode**: Exit with non-zero code if security issues found

## Installation

### Library Usage
Add to your `Cargo.toml`:
```toml
[dependencies]
execheck = "0.2.0"
```

### Command Line Tool

#### Install from Crates.io
```bash
cargo install execheck
```

#### Build from Source
```bash
git clone <repository-url>
cd execheck
cargo build --release
```

The compiled binary will be available at `target/release/execheck`.

### Prerequisites
- Rust toolchain (1.70+ recommended)
- Cargo package manager

## Usage

### Library Usage

See the [Library Usage Guide](docs/LIBRARY_USAGE.md) for comprehensive documentation and examples.

```rust
use execheck::{analyze_file, scan_directory, ScanOptions, OutputFormat};
use std::path::PathBuf;

// Analyze a single file
let result = analyze_file(&PathBuf::from("/bin/ls"))?;
println!("Security status: {}", result.overall_status);

// Scan a directory
let options = ScanOptions { recursive: true, issues_only: false, strict: false };
let report = scan_directory(&PathBuf::from("/usr/bin"), &options)?;
println!("Found {} files with issues", report.summary.insecure_files);
```

### Command Line Usage

### Basic Usage
```bash
# Analyze a single binary
./execheck /bin/ls

# Analyze multiple paths
./execheck /bin/ls /usr/bin/python3

# Analyze with JSON output
./execheck /bin/ls --output json

# Recursive directory scan
./execheck /usr/bin --recursive

# Multiple directories recursive scan
./execheck /usr/bin /usr/sbin --recursive

# Show only files with security issues
./execheck /usr/bin --recursive --issues-only

# Save output to file
./execheck /bin/ls --output json --output-file results.json

# Strict mode (exit code 1 if issues found)  
./execheck /usr/bin --strict
```

### Advanced Filtering Options
```bash
# Filter only Windows executables (.exe files)
./execheck /path/to/files --filter exe --recursive

# Filter only Windows DLLs (.dll files)
./execheck /path/to/files --filter dll --recursive

# Filter both .exe and .dll files
./execheck /path/to/files --filter exe-dll --recursive

# Custom file extensions
./execheck /path/to/files --filter custom --extensions exe,dll,so --recursive

# Stay within single filesystem (Unix only)
./execheck /usr --recursive -x

# Combine filters with other options
./execheck /path/to/files --filter exe --recursive --issues-only --output json
```

### Command Line Options
```
USAGE:
    execheck [OPTIONS] <PATHS>...

ARGUMENTS:
    <PATHS>...    Path(s) to binary or directory to analyze

OPTIONS:
    -r, --recursive                  Recursive directory scanning
    -o, --output <OUTPUT>            Output format [default: human]
                                     [possible values: human, json, yaml, xml, csv]
    -f, --output-file <OUTPUT_FILE>  Output file (stdout if not specified)
        --strict                     Exit non-zero if any security feature is missing
        --issues-only                Show only files with security issues
        --filter <FILTER>            File type filter [default: all]
                                     [possible values: all, exe, dll, exe-dll, custom]
        --extensions <EXTENSIONS>    Custom file extensions (comma-separated)
    -x, --one-filesystem             Stay within single filesystem (Unix only)
    -h, --help                       Print help
    -V, --version                    Print version
```

## Example Output

### Human-Readable Format
```
Security Check Report
====================

Summary:
  Total files: 1
  Secure files: 1
  Insecure files: 0
  Unsupported files: 0

File: /bin/ls
Type: ELF
Status: ✓ Secure
Security Checks:
  RELRO          : ✓ Full RELRO
  Stack Canary   : ✓ Canary Found
  NX             : ✓ NX enabled
  PIE            : ✓ PIE Enabled
  RPATH          : ✓ No RPATH
  RUNPATH        : ✓ No RUNPATH
  Symbols        : ✓ No Symbols
  FORTIFY        : Yes
  Fortified      : 10
  Fortifiable    : 3
  CET            : Full CET (IBT+SHSTK)
```

### Fat Binary Format (macOS Universal Binary)
```
File: /Applications/App.app/Contents/MacOS/App
Type: Mach-O Fat (2 archs)
Status: ⚠ Mixed
Security Checks:
  X86_64 Architecture:
    PIE           : ✓ PIE Enabled
    Stack Canary  : ✓ Canary Found
    NX            : ✓ NX enabled
  
  ARM64 Architecture:
    PIE           : ✓ PIE Enabled
    Stack Canary  : ✗ No Canary Found
    NX            : ✓ NX enabled
```

### JSON Format
```json
{
  "files": [
    {
      "file_path": "/bin/ls",
      "file_type": "ELF", 
      "checks": {
        "canary": "Canary Found",
        "fortified": "10",
        "fortify_source": "Yes",
        "fortifyable": "3",
        "nx": "NX enabled",
        "pie": "PIE Enabled",
        "relro": "Full RELRO",
        "rpath": "No RPATH",
        "runpath": "No RUNPATH",
        "symbols": "No Symbols",
        "cet": "Full CET (IBT+SHSTK)"
      },
      "overall_status": "Secure"
    }
  ],
  "summary": {
    "total_files": 1,
    "secure_files": 1,
    "insecure_files": 0,
    "unsupported_files": 0
  }
}
```

## Examples

### Library Examples

The `examples/` directory contains comprehensive examples:

```bash
# Basic file analysis
cargo run --example simple_analysis

# Directory scanning
cargo run --example directory_scan

# JSON output for automation
cargo run --example json_output

# Custom filtering and analysis
cargo run --example custom_filter
```

### Integration Examples

### CI/CD Integration
```bash
#!/bin/bash
# Check all binaries in build output
./execheck ./build/bin --recursive --strict --output json > security_report.json

if [ $? -ne 0 ]; then
    echo "Security issues found in binaries!"
    exit 1
fi
```

### Security Monitoring
```bash
# Weekly security scan
./execheck /usr/bin /usr/sbin --recursive --issues-only --output csv > weekly_security_report.csv
```

## Architecture

ExeCheck is built with a modular architecture supporting both library and CLI usage:
- `src/lib.rs`: Public library API and core functionality
- `src/main.rs`: CLI interface and argument parsing
- `src/checks.rs`: Platform-specific security analysis
- `src/output.rs`: Multiple output format support
- `examples/`: Library usage examples
- `docs/`: Comprehensive documentation

### Platform Detection
Automatically detects executable format based on magic bytes:
- ELF: `0x7F454C46` (`\x7fELF`)
- PE: `0x4D5A` (`MZ`)  
- Mach-O: Various magic numbers for different architectures

## Limitations

### Current Limitations
- **Mach-O symbol analysis**: Simplified implementation (symbol string table lookup not fully implemented)
- **PE advanced features**: Some Windows-specific checks are placeholder implementations
- **Performance**: Large directory scans may be slow on systems with many files

### Future Enhancements
- Complete Mach-O symbol table analysis
- Advanced PE load configuration parsing
- Parallel processing for directory scans
- Additional security feature detection
- Plugin architecture for custom checks

## Documentation

- [Library Usage Guide](docs/LIBRARY_USAGE.md) - Comprehensive guide for using ExeCheck as a library
- [Examples](examples/) - Working examples for common use cases
- [API Documentation](https://docs.rs/execheck) - Full API reference

## Contributing

Contributions are welcome! Areas of particular interest:
- Enhanced Mach-O analysis
- Additional Windows PE checks
- Performance improvements
- Test coverage expansion
- Documentation improvements
- Library API enhancements
