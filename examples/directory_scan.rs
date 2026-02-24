#!/usr/bin/env cargo
//! Directory scanning example
//! 
//! Run with: cargo run --example directory_scan

use execheck::{scan_directory, print_report, OutputFormat, ScanOptions, FileFilter};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Configure scan options
    let options = ScanOptions {
        recursive: false,        // Only scan top level
        issues_only: true,       // Only show files with security issues
        strict: false,          // Don't exit on issues
        file_filter: FileFilter::All, // All executable types
        one_filesystem: false,   // Allow crossing filesystem boundaries
    };
    
    // Scan a directory (adjust path as needed)
    let scan_path = PathBuf::from("/usr/bin");
    println!("Scanning directory: {} (issues only)", scan_path.display());
    
    match scan_directory(&scan_path, &options) {
        Ok(report) => {
            println!("\n=== Scan Summary ===");
            println!("Total files analyzed: {}", report.summary.total_files);
            println!("Secure files: {}", report.summary.secure_files);
            println!("Files with issues: {}", report.summary.insecure_files);
            println!("Unsupported files: {}", report.summary.unsupported_files);
            
            if report.summary.insecure_files > 0 {
                println!("\n=== Files with Security Issues ===");
                print_report(&report, &OutputFormat::Human, None)?;
            } else {
                println!("\nAll analyzed files have good security posture! ✓");
            }
        }
        Err(e) => {
            eprintln!("Failed to scan directory: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}