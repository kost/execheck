#!/usr/bin/env cargo
//! Custom filtering and analysis example
//! 
//! Run with: cargo run --example custom_filter

use execheck::{analyze_files, collect_executable_files, ScanOptions, SecurityCheck};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Collect executable files from a directory
    let scan_path = PathBuf::from("/usr/bin");
    let options = ScanOptions {
        recursive: false,
        ..Default::default()
    };
    let files = collect_executable_files(&scan_path, &options)?;
    
    println!("Found {} executable files in {}", files.len(), scan_path.display());
    
    // Analyze files with the same options
    let report = analyze_files(files, &options)?;
    
    // Custom filtering: find files missing stack canaries
    let files_without_canary: Vec<&SecurityCheck> = report.files
        .iter()
        .filter(|check| {
            check.checks.get("canary").map_or(false, |v| v.contains("No Canary"))
        })
        .collect();
    
    println!("\n=== Files Missing Stack Canaries ===");
    if files_without_canary.is_empty() {
        println!("All files have stack canary protection! ✓");
    } else {
        for check in files_without_canary {
            println!("⚠️  {} ({})", check.file_path, check.file_type);
        }
    }
    
    // Custom filtering: find files with RPATH issues
    let files_with_rpath: Vec<&SecurityCheck> = report.files
        .iter()
        .filter(|check| {
            check.checks.get("rpath").map_or(false, |v| v == "RPATH") ||
            check.checks.get("runpath").map_or(false, |v| v == "RUNPATH")
        })
        .collect();
    
    println!("\n=== Files with RPATH/RUNPATH Issues ===");
    if files_with_rpath.is_empty() {
        println!("No RPATH/RUNPATH issues found! ✓");
    } else {
        for check in files_with_rpath {
            println!("⚠️  {} ({})", check.file_path, check.file_type);
            if let Some(rpath) = check.checks.get("rpath") {
                if rpath == "RPATH" {
                    println!("    - Has RPATH");
                }
            }
            if let Some(runpath) = check.checks.get("runpath") {
                if runpath == "RUNPATH" {
                    println!("    - Has RUNPATH");
                }
            }
        }
    }
    
    // Security score calculation
    let total_checks = report.files.len();
    let security_score = if total_checks > 0 {
        (report.summary.secure_files as f64 / total_checks as f64) * 100.0
    } else {
        0.0
    };
    
    println!("\n=== Security Score ===");
    println!("Overall security score: {:.1}%", security_score);
    println!("({}/{} files are secure)", report.summary.secure_files, total_checks);
    
    Ok(())
}