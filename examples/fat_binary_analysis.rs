use execheck::{analyze_file, print_report, OutputFormat};
use std::path::PathBuf;

/// Example demonstrating analysis of Mach-O fat binaries (universal binaries).
/// 
/// Fat binaries contain multiple architectures in a single file, commonly used
/// on macOS to support both Intel and Apple Silicon architectures.
/// 
/// This example shows how ExeCheck handles fat binaries and reports
/// architecture information.
fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== ExeCheck Fat Binary Analysis Example ===");
    println!();
    
    // Example fat binary paths (these may not exist on all systems)
    let potential_fat_binaries = vec![
        "/Applications/Xcode.app/Contents/MacOS/Xcode",
        "/System/Applications/Calculator.app/Contents/MacOS/Calculator",
        "/usr/bin/python3",
        "/bin/bash",
    ];
    
    println!("Searching for fat binaries on the system...");
    println!();
    
    let mut found_examples = false;
    
    for binary_path in potential_fat_binaries {
        let path = PathBuf::from(binary_path);
        
        if path.exists() {
            println!("Analyzing: {}", binary_path);
            
            match analyze_file(&path) {
                Ok(result) => {
                    // Check if this is a fat binary
                    if result.file_type.contains("Fat") {
                        found_examples = true;
                        
                        println!("✅ Found fat binary!");
                        println!("   File Type: {}", result.file_type);
                        println!("   Status: {}", result.overall_status);
                        
                        if let Some(arch_count) = result.checks.get("architectures") {
                            println!("   Architectures: {}", arch_count);
                        }
                        
                        // Show per-architecture security details
                        if let Some(total_archs) = result.checks.get("total_architectures") {
                            println!("   Total Architectures: {}", total_archs);
                        }
                        if let Some(secure_archs) = result.checks.get("secure_architectures") {
                            println!("   Secure Architectures: {}", secure_archs);
                        }
                        if let Some(arch_list) = result.checks.get("architectures") {
                            println!("   Architecture List: {}", arch_list);
                        }
                        
                        // Show individual architecture security checks
                        println!("   Per-Architecture Security:");
                        for (key, value) in &result.checks {
                            if key.contains("_pie") || key.contains("_canary") || key.contains("_nx") {
                                println!("     {}: {}", key, value);
                            }
                        }
                        
                        println!();
                        
                        // Show detailed report in JSON format
                        println!("Detailed JSON Report:");
                        print_report(&execheck::SecurityReport {
                            files: vec![result],
                            summary: execheck::ReportSummary {
                                total_files: 1,
                                secure_files: 0,
                                insecure_files: 0,
                                unsupported_files: 1,
                            },
                        }, &OutputFormat::Json, None)?;
                        
                        println!("\n{}\n", "=".repeat(60));
                    } else {
                        println!("   Not a fat binary ({})", result.file_type);
                    }
                }
                Err(e) => {
                    println!("   Error analyzing: {}", e);
                }
            }
        } else {
            println!("Skipping: {} (not found)", binary_path);
        }
    }
    
    if !found_examples {
        // Create a demonstration with mock data
        println!("No fat binaries found on system. Showing example output:");
        println!();
        
        demonstrate_fat_binary_output()?;
    }
    
    println!("=== Fat Binary Analysis Notes ===");
    println!();
    println!("Current Status:");
    println!("• ✅ Fat binary detection and architecture counting");
    println!("• ✅ Per-architecture security analysis"); 
    println!("• ✅ Architecture-specific security checks (e.g., 'x86_64_pie', 'arm64_canary')");
    println!("• ✅ Combined security status (Secure/Mixed/Insecure)");
    println!();
    println!("Fat binaries now show detailed architecture-specific security analysis,");
    println!("allowing you to see security features for each architecture independently.");
    
    Ok(())
}

/// Demonstrate what fat binary output will look like when fully implemented
fn demonstrate_fat_binary_output() -> Result<(), Box<dyn std::error::Error>> {
    use std::collections::HashMap;
    
    println!("Example Fat Binary Analysis (Mock Data):");
    println!();
    
    // Create a mock fat binary result showing the full implementation
    let mut checks = HashMap::new();
    checks.insert("total_architectures".to_string(), "2".to_string());
    checks.insert("secure_architectures".to_string(), "1".to_string());
    checks.insert("architectures".to_string(), "x86_64, arm64".to_string());
    
    // Per-architecture security checks
    checks.insert("x86_64_pie".to_string(), "PIE Enabled".to_string());
    checks.insert("arm64_pie".to_string(), "PIE Enabled".to_string());
    checks.insert("x86_64_canary".to_string(), "Canary Found".to_string());
    checks.insert("arm64_canary".to_string(), "No Canary Found".to_string());
    checks.insert("x86_64_nx".to_string(), "NX enabled".to_string());
    checks.insert("arm64_nx".to_string(), "NX enabled".to_string());
    
    let mock_result = execheck::SecurityCheck {
        file_path: "/example/universal_app".to_string(),
        file_type: "Mach-O Fat (2 archs)".to_string(),
        checks,
        overall_status: "Mixed".to_string(),
    };
    
    let report = execheck::SecurityReport {
        files: vec![mock_result],
        summary: execheck::ReportSummary {
            total_files: 1,
            secure_files: 0,
            insecure_files: 1,
            unsupported_files: 0,
        },
    };
    
    // Show current output
    println!("Current Output (Human Format):");
    print_report(&report, &OutputFormat::Human, None)?;
    
    println!("\nFuture Enhanced Output (When Fully Implemented):");
    println!("File: /example/universal_app");
    println!("Type: Mach-O Fat (2 archs)");
    println!("Status: ⚠ Mixed");
    println!("Security Checks:");
    println!("  X86_64 Architecture:");
    println!("    PIE           : ✓ PIE Enabled");
    println!("    Stack Canary  : ✓ Canary Found");
    println!("    NX            : ✓ NX enabled");
    println!();
    println!("  ARM64 Architecture:");
    println!("    PIE           : ✓ PIE Enabled");
    println!("    Stack Canary  : ✗ No Canary Found");
    println!("    NX            : ✓ NX enabled");
    
    Ok(())
}