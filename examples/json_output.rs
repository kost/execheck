#!/usr/bin/env cargo
//! JSON output example for programmatic consumption
//! 
//! Run with: cargo run --example json_output

use execheck::{analyze_file, print_report, OutputFormat, SecurityReport, ReportSummary};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Analyze multiple files
    let files = vec![
        PathBuf::from("/bin/ls"),
        PathBuf::from("/bin/cat"),
        PathBuf::from("/bin/echo"),
    ];
    
    let mut results = Vec::new();
    let mut secure_count = 0;
    let mut insecure_count = 0;
    let mut unsupported_count = 0;
    
    println!("Analyzing {} files...", files.len());
    
    for file_path in files {
        match analyze_file(&file_path) {
            Ok(result) => {
                match result.overall_status.as_str() {
                    "Secure" => secure_count += 1,
                    "Mostly Secure" | "Insecure" => insecure_count += 1,
                    _ => unsupported_count += 1,
                }
                results.push(result);
            }
            Err(e) => {
                eprintln!("Warning: Failed to analyze {}: {}", file_path.display(), e);
                unsupported_count += 1;
            }
        }
    }
    
    // Create report
    let report = SecurityReport {
        files: results,
        summary: ReportSummary {
            total_files: secure_count + insecure_count + unsupported_count,
            secure_files: secure_count,
            insecure_files: insecure_count,
            unsupported_files: unsupported_count,
        },
    };
    
    println!("\n=== JSON Output ===");
    print_report(&report, &OutputFormat::Json, None)?;
    
    Ok(())
}