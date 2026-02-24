#!/usr/bin/env cargo
//! Advanced filtering and filesystem boundary example
//! 
//! Run with: cargo run --example advanced_filtering

use execheck::{
    collect_executable_files, analyze_files, print_report, 
    ScanOptions, FileFilter, OutputFormat
};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ExeCheck Advanced Filtering Example ===\n");

    // Example 1: Filter only Windows executables (.exe)
    println!("1. Scanning for Windows executables (.exe files only):");
    let exe_options = ScanOptions {
        recursive: false,
        issues_only: false,
        strict: false,
        file_filter: FileFilter::WindowsExecutables,
        one_filesystem: false,
    };
    
    if let Ok(exe_files) = collect_executable_files(&PathBuf::from("."), &exe_options) {
        println!("   Found {} .exe files", exe_files.len());
        for file in exe_files.iter().take(3) {
            println!("   - {}", file.display());
        }
    } else {
        println!("   No .exe files found or error occurred");
    }

    // Example 2: Filter only Windows DLLs (.dll)
    println!("\n2. Scanning for Windows DLLs (.dll files only):");
    let dll_options = ScanOptions {
        recursive: false,
        issues_only: false,
        strict: false,
        file_filter: FileFilter::WindowsDlls,
        one_filesystem: false,
    };
    
    if let Ok(dll_files) = collect_executable_files(&PathBuf::from("."), &dll_options) {
        println!("   Found {} .dll files", dll_files.len());
        for file in dll_files.iter().take(3) {
            println!("   - {}", file.display());
        }
    } else {
        println!("   No .dll files found or error occurred");
    }

    // Example 3: Custom extension filtering
    println!("\n3. Custom extension filtering (exe, dll, so, dylib):");
    let custom_extensions = vec![
        "exe".to_string(),
        "dll".to_string(), 
        "so".to_string(),
        "dylib".to_string(),
    ];
    
    let custom_options = ScanOptions {
        recursive: true,
        issues_only: false,
        strict: false,
        file_filter: FileFilter::Extensions(custom_extensions),
        one_filesystem: false,
    };
    
    if let Ok(custom_files) = collect_executable_files(&PathBuf::from("."), &custom_options) {
        println!("   Found {} files with custom extensions", custom_files.len());
        for file in custom_files.iter().take(5) {
            println!("   - {}", file.display());
        }
    } else {
        println!("   No files with custom extensions found or error occurred");
    }

    // Example 4: Custom predicate filtering
    println!("\n4. Custom predicate filtering (files containing 'lib' in name):");
    let lib_filter = |path: &std::path::Path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .map_or(false, |name| name.to_lowercase().contains("lib"))
    };
    
    let predicate_options = ScanOptions {
        recursive: true,
        issues_only: false,
        strict: false,
        file_filter: FileFilter::Custom(lib_filter),
        one_filesystem: false,
    };
    
    if let Ok(lib_files) = collect_executable_files(&PathBuf::from("/usr/lib"), &predicate_options) {
        println!("   Found {} library files", lib_files.len());
        for file in lib_files.iter().take(5) {
            println!("   - {}", file.display());
        }
    } else {
        println!("   Error scanning /usr/lib or no library files found");
    }

    // Example 5: Filesystem boundary demonstration (Unix only)
    #[cfg(unix)]
    {
        println!("\n5. Filesystem boundary scanning (Unix only):");
        let boundary_options = ScanOptions {
            recursive: true,
            issues_only: false,
            strict: false,
            file_filter: FileFilter::All,
            one_filesystem: true, // Stay within single filesystem
        };
        
        if let Ok(boundary_files) = collect_executable_files(&PathBuf::from("/"), &boundary_options) {
            println!("   Found {} files within root filesystem", boundary_files.len());
            println!("   (This prevents crossing into /proc, /sys, mounted drives, etc.)");
        } else {
            println!("   Error scanning root filesystem with boundary restrictions");
        }
    }
    
    #[cfg(not(unix))]
    {
        println!("\n5. Filesystem boundary scanning:");
        println!("   (Not supported on this platform - Unix-like systems only)");
    }

    // Example 6: Practical use case - analyze only PE files in a directory
    println!("\n6. Practical example - Analyze Windows executables and DLLs with JSON output:");
    
    let analysis_options = ScanOptions {
        recursive: true,
        issues_only: true, // Only show files with security issues
        strict: false,
        file_filter: FileFilter::WindowsExecutablesAndDlls,
        one_filesystem: false,
    };
    
    // Try to analyze current directory for demo purposes
    if let Ok(files) = collect_executable_files(&PathBuf::from("."), &analysis_options) {
        if !files.is_empty() {
            let report = analyze_files(files, &analysis_options)?;
            
            if !report.files.is_empty() {
                println!("   Analysis results (JSON format):");
                print_report(&report, &OutputFormat::Json, None)?;
            } else {
                println!("   No security issues found in Windows executables/DLLs!");
            }
        } else {
            println!("   No Windows executables or DLLs found in current directory");
        }
    }

    println!("\n=== Advanced Filtering Example Complete ===");
    Ok(())
}