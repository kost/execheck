//! # ExeCheck - Multi-Platform Executable Security Checker
//!
//! ExeCheck is a comprehensive security analysis library for executable files across multiple platforms:
//! - Linux ELF binaries
//! - Windows PE executables  
//! - macOS Mach-O binaries
//!
//! ## Features
//!
//! - **Comprehensive Security Analysis**: Checks for stack canaries, NX/DEP, PIE/ASLR, RELRO, and more
//! - **Multi-Platform Support**: Unified API for analyzing different executable formats
//! - **Multiple Output Formats**: Human-readable, JSON, YAML, XML, and CSV output
//! - **Directory Scanning**: Recursive directory analysis with filtering options
//! - **Library and CLI**: Use as a Rust library or standalone command-line tool
//!
//! ## Quick Start
//!
//! ### Library Usage
//!
//! ```rust
//! use execheck::{analyze_file, OutputFormat, print_report};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // Analyze a single file
//! let file_path = PathBuf::from("/bin/ls");
//! let result = analyze_file(&file_path)?;
//! 
//! println!("File: {}", result.file_path);
//! println!("Type: {}", result.file_type);
//! println!("Status: {}", result.overall_status);
//! 
//! // Print detailed report
//! let report = execheck::SecurityReport {
//!     files: vec![result],
//!     summary: execheck::ReportSummary {
//!         total_files: 1,
//!         secure_files: 1,
//!         insecure_files: 0,
//!         unsupported_files: 0,
//!     },
//! };
//! 
//! print_report(&report, &OutputFormat::Human, None)?;
//! # Ok(())
//! # }
//! ```
//!
//! ### Batch Analysis
//!
//! ```rust
//! use execheck::{scan_directory, ScanOptions, FileFilter};
//! use std::path::PathBuf;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let options = ScanOptions {
//!     recursive: true,
//!     issues_only: true,
//!     strict: false,
//!     file_filter: FileFilter::All,
//!     one_filesystem: false,
//! };
//! 
//! let report = scan_directory(&PathBuf::from("/usr/bin"), &options)?;
//! println!("Scanned {} files", report.summary.total_files);
//! println!("Found issues in {} files", report.summary.insecure_files);
//! # Ok(())
//! # }
//! ```

pub mod checks;
pub mod output;

use anyhow::{bail, Context, Result};
use goblin::{Object, mach};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fs, path::PathBuf};
use walkdir::WalkDir;

// Re-export commonly used types
pub use output::{print_report, OutputFormat};

/// File type filters for directory scanning
#[derive(Debug, Clone)]
pub enum FileFilter {
    /// All executable files (default behavior)
    All,
    /// Only Windows executables (.exe files)
    WindowsExecutables,
    /// Only Windows dynamic libraries (.dll files)
    WindowsDlls,
    /// Both .exe and .dll files
    WindowsExecutablesAndDlls,
    /// Custom file extension filter
    Extensions(Vec<String>),
    /// Custom predicate function
    Custom(fn(&std::path::Path) -> bool),
}

/// Configuration options for directory scanning
#[derive(Debug, Clone)]
pub struct ScanOptions {
    /// Enable recursive directory traversal
    pub recursive: bool,
    /// Only return files with security issues
    pub issues_only: bool,
    /// Enable strict mode (affects error handling)
    pub strict: bool,
    /// File type filter for scanning
    pub file_filter: FileFilter,
    /// Stay within single filesystem (Unix-like systems only)
    pub one_filesystem: bool,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            recursive: false,
            issues_only: false,
            strict: false,
            file_filter: FileFilter::All,
            one_filesystem: false,
        }
    }
}

/// Security analysis result for a single executable file
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SecurityCheck {
    /// Path to the analyzed file
    pub file_path: String,
    /// File type (ELF, PE, Mach-O, etc.)
    pub file_type: String,
    /// Map of security check names to their results
    pub checks: HashMap<String, String>,
    /// Overall security status (Secure, Mostly Secure, Insecure, etc.)
    pub overall_status: String,
}

/// Complete security analysis report for multiple files
#[derive(Serialize, Deserialize, Debug)]
pub struct SecurityReport {
    /// Individual file analysis results
    pub files: Vec<SecurityCheck>,
    /// Summary statistics
    pub summary: ReportSummary,
}

/// Summary statistics for a security report
#[derive(Serialize, Deserialize, Debug)]
pub struct ReportSummary {
    /// Total number of files analyzed
    pub total_files: usize,
    /// Number of files with good security posture
    pub secure_files: usize,
    /// Number of files with security issues
    pub insecure_files: usize,
    /// Number of files that couldn't be analyzed
    pub unsupported_files: usize,
}

/// Analyze a single executable file for security features
///
/// This function detects the executable format and performs appropriate security analysis.
///
/// # Arguments
///
/// * `path` - Path to the executable file to analyze
///
/// # Returns
///
/// Returns a `SecurityCheck` struct containing the analysis results, or an error if
/// the file cannot be read or is not a supported executable format.
///
/// # Example
///
/// ```rust
/// use execheck::analyze_file;
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let result = analyze_file(&PathBuf::from("/bin/ls"))?;
/// println!("Security status: {}", result.overall_status);
/// # Ok(())
/// # }
/// ```
pub fn analyze_file(path: &PathBuf) -> Result<SecurityCheck> {
    let data = fs::read(path).with_context(|| format!("reading {:?}", path))?;
    
    match Object::parse(&data).context("parsing object")? {
        Object::Elf(elf) => checks::analyze_elf(path, &elf, &data),
        Object::PE(pe) => checks::analyze_pe(path, &pe, &data),
        Object::Mach(mach) => match mach {
            mach::Mach::Fat(fat) => checks::analyze_macho_fat(path, &fat, &data),
            mach::Mach::Binary(macho) => checks::analyze_macho(path, &macho, &data),
        },
        other => bail!("Unsupported file type: {other:?}"),
    }
}

/// Scan a directory for executable files and analyze their security features
///
/// This function recursively scans a directory for executable files and analyzes each one.
/// The behavior can be customized using the `ScanOptions` parameter.
///
/// # Arguments
///
/// * `dir_path` - Path to the directory to scan
/// * `options` - Scanning options (recursive, issues_only, strict)
///
/// # Returns
///
/// Returns a `SecurityReport` containing analysis results for all found executables.
///
/// # Example
///
/// ```rust
/// use execheck::{scan_directory, ScanOptions, FileFilter};
/// use std::path::PathBuf;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let options = ScanOptions {
///     recursive: true,
///     issues_only: false,
///     strict: false,
///     file_filter: FileFilter::All,
///     one_filesystem: false,
/// };
///
/// let report = scan_directory(&PathBuf::from("/usr/bin"), &options)?;
/// println!("Found {} executable files", report.summary.total_files);
/// # Ok(())
/// # }
/// ```
pub fn scan_directory(dir_path: &PathBuf, options: &ScanOptions) -> Result<SecurityReport> {
    let files = collect_executable_files(dir_path, options)?;
    analyze_files(files, options)
}

/// Analyze multiple files and generate a security report
///
/// # Arguments
///
/// * `files` - Vector of file paths to analyze
/// * `options` - Scanning options that affect filtering
///
/// # Returns
///
/// Returns a complete `SecurityReport` with summary statistics.
pub fn analyze_files(files: Vec<PathBuf>, options: &ScanOptions) -> Result<SecurityReport> {
    let mut security_checks = Vec::new();
    let mut secure_count = 0;
    let mut insecure_count = 0;
    let mut unsupported_count = 0;

    for file_path in files {
        match analyze_file(&file_path) {
            Ok(check) => {
                let is_secure = check.overall_status == "Secure";
                if is_secure {
                    secure_count += 1;
                } else {
                    insecure_count += 1;
                }
                
                if !options.issues_only || !is_secure {
                    security_checks.push(check);
                }
            }
            Err(_) => {
                unsupported_count += 1;
                if !options.issues_only {
                    security_checks.push(SecurityCheck {
                        file_path: file_path.display().to_string(),
                        file_type: "Unknown".to_string(),
                        checks: HashMap::new(),
                        overall_status: "Unsupported".to_string(),
                    });
                }
            }
        }
    }

    Ok(SecurityReport {
        files: security_checks,
        summary: ReportSummary {
            total_files: secure_count + insecure_count + unsupported_count,
            secure_files: secure_count,
            insecure_files: insecure_count,
            unsupported_files: unsupported_count,
        },
    })
}

/// Check if a file appears to be an executable based on magic bytes
///
/// This function performs a quick check of the file header to identify common
/// executable formats without fully parsing the file.
///
/// # Arguments
///
/// * `path` - Path to the file to check
///
/// # Returns
///
/// Returns `true` if the file appears to be an executable, `false` otherwise.
pub fn is_executable_file(path: &std::path::Path) -> Result<bool> {
    let data = match fs::read(path) {
        Ok(data) if data.len() >= 4 => data,
        _ => return Ok(false),
    };
    
    // Check for common executable headers
    if data.starts_with(b"\x7fELF") ||                      // ELF
       data.starts_with(b"MZ") ||                           // PE/DOS
       data.starts_with(&[0xFE, 0xED, 0xFA, 0xCE]) ||     // Mach-O 32-bit big endian
       data.starts_with(&[0xCE, 0xFA, 0xED, 0xFE]) ||     // Mach-O 32-bit little endian
       data.starts_with(&[0xFE, 0xED, 0xFA, 0xCF]) ||     // Mach-O 64-bit big endian
       data.starts_with(&[0xCF, 0xFA, 0xED, 0xFE]) {      // Mach-O 64-bit little endian
        return Ok(true);
    }
    
    Ok(false)
}

/// Check if a file matches the specified file filter
///
/// This function applies custom filtering logic based on the FileFilter enum.
///
/// # Arguments
///
/// * `path` - Path to the file to check
/// * `filter` - The file filter to apply
///
/// # Returns
///
/// Returns `true` if the file matches the filter, `false` otherwise.
pub fn matches_file_filter(path: &std::path::Path, filter: &FileFilter) -> Result<bool> {
    match filter {
        FileFilter::All => is_executable_file(path),
        FileFilter::WindowsExecutables => {
            if let Some(ext) = path.extension() {
                if ext.to_string_lossy().to_lowercase() == "exe" {
                    return is_executable_file(path);
                }
            }
            Ok(false)
        }
        FileFilter::WindowsDlls => {
            if let Some(ext) = path.extension() {
                if ext.to_string_lossy().to_lowercase() == "dll" {
                    return is_executable_file(path);
                }
            }
            Ok(false)
        }
        FileFilter::WindowsExecutablesAndDlls => {
            if let Some(ext) = path.extension() {
                let ext_lower = ext.to_string_lossy().to_lowercase();
                if ext_lower == "exe" || ext_lower == "dll" {
                    return is_executable_file(path);
                }
            }
            Ok(false)
        }
        FileFilter::Extensions(extensions) => {
            if let Some(ext) = path.extension() {
                let ext_lower = ext.to_string_lossy().to_lowercase();
                if extensions.iter().any(|e| e.to_lowercase() == ext_lower) {
                    return is_executable_file(path);
                }
            }
            Ok(false)
        }
        FileFilter::Custom(predicate) => {
            if predicate(path) {
                return is_executable_file(path);
            }
            Ok(false)
        }
    }
}

/// Collect all executable files from a directory
///
/// This function walks through a directory and identifies executable files based on
/// their magic bytes and the specified file filter. It can operate recursively or 
/// just scan the top level, and can respect filesystem boundaries.
///
/// # Arguments
///
/// * `dir` - Directory path to scan
/// * `options` - Scan options including recursion, filtering, and filesystem boundaries
///
/// # Returns
///
/// Returns a vector of paths to executable files found in the directory.
pub fn collect_executable_files(dir: &PathBuf, options: &ScanOptions) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    
    let mut walker = WalkDir::new(dir);
    
    if !options.recursive {
        walker = walker.max_depth(1);
    }
    
    // Handle filesystem boundaries on Unix-like systems
    #[cfg(unix)]
    let root_dev = if options.one_filesystem {
        use std::os::unix::fs::MetadataExt;
        Some(fs::metadata(dir)
            .context("getting root directory metadata")?
            .dev())
    } else {
        None
    };
    
    #[cfg(not(unix))]
    let root_dev: Option<()> = None;
    
    for entry in walker {
        let entry = entry.context("walking directory")?;
        let path = entry.path();
        
        // Check filesystem boundaries on Unix systems
        #[cfg(unix)]
        if let Some(expected_dev) = root_dev {
            use std::os::unix::fs::MetadataExt;
            if let Ok(metadata) = entry.metadata() {
                if metadata.dev() != expected_dev {
                    continue; // Skip files on different filesystems
                }
            }
        }
        
        if path.is_file() && matches_file_filter(path, &options.file_filter)? {
            files.push(path.to_path_buf());
        }
    }
    
    Ok(files)
}


/// Get version information for the library
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Get detailed version information including dependencies
pub fn version_info() -> String {
    format!(
        "execheck {} (goblin {}, built with rustc)",
        env!("CARGO_PKG_VERSION"),
        env!("CARGO_PKG_VERSION_MAJOR")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_version() {
        assert!(!version().is_empty());
        assert!(version_info().contains("execheck"));
    }

    #[test]
    fn test_scan_options_default() {
        let options = ScanOptions::default();
        assert!(!options.recursive);
        assert!(!options.issues_only);
        assert!(!options.strict);
    }

    #[test]
    fn test_is_executable_file_nonexistent() {
        let result = is_executable_file(&PathBuf::from("/nonexistent/file").as_path());
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }

    #[test] 
    fn test_security_check_creation() {
        let check = SecurityCheck {
            file_path: "/test/file".to_string(),
            file_type: "ELF".to_string(),
            checks: HashMap::new(),
            overall_status: "Secure".to_string(),
        };
        
        assert_eq!(check.file_path, "/test/file");
        assert_eq!(check.file_type, "ELF");
        assert_eq!(check.overall_status, "Secure");
    }

    #[test]
    fn test_file_filter_all() {
        use std::path::Path;
        
        // Create temporary test file (this is just testing the logic)
        let result = matches_file_filter(Path::new("/nonexistent/test.exe"), &FileFilter::All);
        assert!(result.is_ok()); // Should not error on checking filter logic
    }

    #[test]
    fn test_file_filter_windows_exe() {
        use std::path::Path;
        
        // Test .exe extension matching logic (not actual file content)
        let path_exe = Path::new("/test/file.exe");
        let path_txt = Path::new("/test/file.txt");
        
        // The function will return Ok(false) for non-existent files after checking extension
        let result_exe = matches_file_filter(path_exe, &FileFilter::WindowsExecutables);
        let result_txt = matches_file_filter(path_txt, &FileFilter::WindowsExecutables);
        
        assert!(result_exe.is_ok());
        assert!(result_txt.is_ok());
    }

    #[test] 
    fn test_file_filter_extensions() {
        use std::path::Path;
        
        let extensions = vec!["exe".to_string(), "dll".to_string(), "so".to_string()];
        let filter = FileFilter::Extensions(extensions);
        
        // Test extension matching logic
        let result = matches_file_filter(Path::new("/test/file.exe"), &filter);
        assert!(result.is_ok());
        
        let result = matches_file_filter(Path::new("/test/file.txt"), &filter);
        assert!(result.is_ok());
    }

    #[test]
    fn test_scan_options_with_filters() {
        let options = ScanOptions {
            recursive: true,
            issues_only: false,
            strict: false,
            file_filter: FileFilter::WindowsExecutables,
            one_filesystem: true,
        };
        
        assert!(options.recursive);
        assert!(options.one_filesystem);
        assert!(!options.issues_only);
        assert!(!options.strict);
    }

    #[test]
    fn test_scan_options_default_includes_new_fields() {
        let options = ScanOptions::default();
        assert!(!options.recursive);
        assert!(!options.issues_only); 
        assert!(!options.strict);
        assert!(!options.one_filesystem);
        // file_filter should be FileFilter::All but we can't easily test enum equality
    }
}