#!/usr/bin/env cargo
//! Simple executable analysis example
//! 
//! Run with: cargo run --example simple_analysis

use execheck::{analyze_file, print_report, OutputFormat, SecurityReport, ReportSummary};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Analyze a single executable file
    let file_path = PathBuf::from("/bin/ls");
    
    println!("Analyzing: {}", file_path.display());
    
    match analyze_file(&file_path) {
        Ok(result) => {
            println!("\n=== Analysis Results ===");
            println!("File: {}", result.file_path);
            println!("Type: {}", result.file_type);
            println!("Status: {}", result.overall_status);
            
            println!("\n=== Security Checks ===");
            for (check, value) in &result.checks {
                println!("  {}: {}", check, value);
            }
            
            // Create a report and print it in human-readable format
            println!("\n=== Formatted Report ===");
            let report = SecurityReport {
                files: vec![result],
                summary: ReportSummary {
                    total_files: 1,
                    secure_files: 1,
                    insecure_files: 0,
                    unsupported_files: 0,
                },
            };
            
            print_report(&report, &OutputFormat::Human, None)?;
        }
        Err(e) => {
            eprintln!("Failed to analyze file: {}", e);
            std::process::exit(1);
        }
    }
    
    Ok(())
}