use anyhow::{Context, Result};
use serde_json;
use serde_yaml;
use std::{fs::File, io::{self, Write, BufWriter}, path::PathBuf};
use crate::{SecurityReport, SecurityCheck};

/// Available output formats for security reports
#[derive(clap::ValueEnum, Clone, Debug)]
pub enum OutputFormat {
    /// Human-readable format with colors and formatting
    Human,
    /// JSON format for programmatic consumption
    Json,
    /// YAML format for configuration files
    Yaml,
    /// XML format for structured data exchange
    Xml,
    /// CSV format for spreadsheet analysis
    Csv,
}

pub fn print_report(report: &SecurityReport, format: &OutputFormat, output_file: Option<&PathBuf>) -> Result<()> {
    let output: Box<dyn Write> = if let Some(file_path) = output_file {
        Box::new(BufWriter::new(File::create(file_path).context("creating output file")?))
    } else {
        Box::new(io::stdout())
    };
    
    match format {
        OutputFormat::Human => print_human_report(report, output)?,
        OutputFormat::Json => print_json_report(report, output)?,
        OutputFormat::Yaml => print_yaml_report(report, output)?,
        OutputFormat::Xml => print_xml_report(report, output)?,
        OutputFormat::Csv => print_csv_report(report, output)?,
    }
    
    Ok(())
}

fn print_human_report(report: &SecurityReport, mut output: Box<dyn Write>) -> Result<()> {
    // Print header
    writeln!(output, "Security Check Report")?;
    writeln!(output, "====================")?;
    writeln!(output)?;
    
    // Print summary
    writeln!(output, "Summary:")?;
    writeln!(output, "  Total files: {}", report.summary.total_files)?;
    writeln!(output, "  Secure files: {}", report.summary.secure_files)?;
    writeln!(output, "  Insecure files: {}", report.summary.insecure_files)?;
    writeln!(output, "  Unsupported files: {}", report.summary.unsupported_files)?;
    writeln!(output)?;
    
    // Print individual file results
    for file_check in &report.files {
        print_human_file_check(&file_check, &mut output)?;
        writeln!(output)?;
    }
    
    Ok(())
}

fn print_human_file_check(check: &SecurityCheck, output: &mut Box<dyn Write>) -> Result<()> {
    writeln!(output, "File: {}", check.file_path)?;
    writeln!(output, "Type: {}", check.file_type)?;
    writeln!(output, "Status: {}", format_security_status(&check.overall_status))?;
    
    if !check.checks.is_empty() {
        writeln!(output, "Security Checks:")?;
        
        match check.file_type.as_str() {
            "ELF" => print_elf_checks(check, output)?,
            "PE" => print_pe_checks(check, output)?,
            "Mach-O" => print_macho_checks(check, output)?,
            _ => {
                for (key, value) in &check.checks {
                    writeln!(output, "  {}: {}", key, value)?;
                }
            }
        }
    }
    
    Ok(())
}

fn print_elf_checks(check: &SecurityCheck, output: &mut Box<dyn Write>) -> Result<()> {
    let checks_order = [
        ("relro", "RELRO"),
        ("canary", "Stack Canary"),
        ("nx", "NX"),
        ("pie", "PIE"),
        ("rpath", "RPATH"),
        ("runpath", "RUNPATH"), 
        ("symbols", "Symbols"),
        ("fortify_source", "FORTIFY"),
        ("fortified", "Fortified"),
        ("fortifyable", "Fortifiable"),
        ("cet", "CET"),
    ];
    
    for (key, label) in &checks_order {
        if let Some(value) = check.checks.get(*key) {
            writeln!(output, "  {:<15}: {}", label, format_check_value(value))?;
        }
    }
    
    Ok(())
}

fn print_pe_checks(check: &SecurityCheck, output: &mut Box<dyn Write>) -> Result<()> {
    let checks_order = [
        ("dynamic_base", "Dynamic Base"),
        ("aslr", "ASLR"),
        ("high_entropy_va", "High Entropy VA"),
        ("force_integrity", "Force Integrity"),
        ("isolation", "Isolation"),
        ("nx", "NX"),
        ("seh", "SEH"),
        ("cfg", "CFG"),
        ("rfg", "RFG"),
        ("safe_seh", "SafeSEH"),
        ("gs", "GS"),
        ("authenticode", "Authenticode"),
        ("dotnet", ".NET"),
    ];
    
    for (key, label) in &checks_order {
        if let Some(value) = check.checks.get(*key) {
            writeln!(output, "  {:<15}: {}", label, format_check_value(value))?;
        }
    }
    
    Ok(())
}

fn print_macho_checks(check: &SecurityCheck, output: &mut Box<dyn Write>) -> Result<()> {
    // Check if this is a fat binary (contains architecture prefixes)
    let is_fat_binary = check.checks.keys().any(|k| k.contains('_') && 
        (k.starts_with("x86_64_") || k.starts_with("arm64_") || k.starts_with("i386_") || k.starts_with("arm_")));
    
    if is_fat_binary {
        print_fat_macho_checks(check, output)
    } else {
        print_single_arch_macho_checks(check, output)
    }
}

fn print_single_arch_macho_checks(check: &SecurityCheck, output: &mut Box<dyn Write>) -> Result<()> {
    let checks_order = [
        ("pie", "PIE"),
        ("canary", "Stack Canary"),
        ("nx", "NX"),
        ("arc", "ARC"),
        ("encrypted", "Encrypted"),
        ("restricted", "Restricted"),
        ("code_signature", "Code Signature"),
    ];
    
    for (key, label) in &checks_order {
        if let Some(value) = check.checks.get(*key) {
            writeln!(output, "  {:<15}: {}", label, format_check_value(value))?;
        }
    }
    
    Ok(())
}

fn print_fat_macho_checks(check: &SecurityCheck, output: &mut Box<dyn Write>) -> Result<()> {
    // Group checks by architecture
    let mut arch_checks: std::collections::HashMap<String, Vec<(String, String)>> = std::collections::HashMap::new();
    
    for (key, value) in &check.checks {
        if let Some(underscore_pos) = key.find('_') {
            let arch = &key[..underscore_pos];
            let check_name = &key[underscore_pos + 1..];
            
            arch_checks.entry(arch.to_string())
                .or_insert_with(Vec::new)
                .push((check_name.to_string(), value.clone()));
        }
    }
    
    // Print checks for each architecture
    for (arch, checks) in &arch_checks {
        writeln!(output, "  {} Architecture:", arch.to_uppercase())?;
        
        let checks_order = [
            ("pie", "PIE"),
            ("canary", "Stack Canary"),
            ("nx", "NX"),
            ("arc", "ARC"),
            ("encrypted", "Encrypted"),
            ("restricted", "Restricted"),
            ("code_signature", "Code Signature"),
        ];
        
        for (key, label) in &checks_order {
            if let Some((_, value)) = checks.iter().find(|(k, _)| k == key) {
                writeln!(output, "    {:<13}: {}", label, format_check_value(value))?;
            }
        }
        writeln!(output)?;
    }
    
    Ok(())
}

fn format_security_status(status: &str) -> String {
    match status {
        "Secure" => format!("✓ {}", status),
        "Mostly Secure" => format!("⚠ {}", status),
        "Mixed" => format!("⚠ {}", status),
        "Insecure" => format!("✗ {}", status),
        "Unsupported" => format!("? {}", status),
        _ => status.to_string(),
    }
}

fn format_check_value(value: &str) -> String {
    match value {
        // Positive security features
        "Present" | "Canary Found" | "NX enabled" | "PIE Enabled" | 
        "Full RELRO" | "No RPATH" | "No RUNPATH" | "No Symbols" |
        "ARC Enabled" | "Encrypted" => format!("✓ {}", value),
        
        // Partial/Warning features  
        "Partial RELRO" | "Mostly Secure" => format!("⚠ {}", value),
        
        // Missing/Negative features
        "NotPresent" | "No Canary Found" | "NX disabled" | "PIE Disabled" |
        "No RELRO" | "RPATH" | "RUNPATH" | "Symbols" | "Not Encrypted" => format!("✗ {}", value),
        
        // Not applicable
        "NotApplicable" | "NotImplemented" => format!("- {}", value),
        
        // Default
        _ => value.to_string(),
    }
}

fn print_json_report(report: &SecurityReport, mut output: Box<dyn Write>) -> Result<()> {
    let json = serde_json::to_string_pretty(report).context("serializing to JSON")?;
    writeln!(output, "{}", json)?;
    Ok(())
}

fn print_yaml_report(report: &SecurityReport, mut output: Box<dyn Write>) -> Result<()> {
    let yaml = serde_yaml::to_string(report).context("serializing to YAML")?;
    write!(output, "{}", yaml)?;
    Ok(())
}

fn print_xml_report(report: &SecurityReport, mut output: Box<dyn Write>) -> Result<()> {
    writeln!(output, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>")?;
    writeln!(output, "<SecurityReport>")?;
    
    // Summary
    writeln!(output, "  <Summary>")?;
    writeln!(output, "    <TotalFiles>{}</TotalFiles>", report.summary.total_files)?;
    writeln!(output, "    <SecureFiles>{}</SecureFiles>", report.summary.secure_files)?;
    writeln!(output, "    <InsecureFiles>{}</InsecureFiles>", report.summary.insecure_files)?;
    writeln!(output, "    <UnsupportedFiles>{}</UnsupportedFiles>", report.summary.unsupported_files)?;
    writeln!(output, "  </Summary>")?;
    
    // Files
    writeln!(output, "  <Files>")?;
    for file_check in &report.files {
        writeln!(output, "    <File>")?;
        writeln!(output, "      <Path>{}</Path>", xml_escape(&file_check.file_path))?;
        writeln!(output, "      <Type>{}</Type>", xml_escape(&file_check.file_type))?;
        writeln!(output, "      <Status>{}</Status>", xml_escape(&file_check.overall_status))?;
        writeln!(output, "      <Checks>")?;
        for (key, value) in &file_check.checks {
            writeln!(output, "        <{}>{}</{}>", key, xml_escape(value), key)?;
        }
        writeln!(output, "      </Checks>")?;
        writeln!(output, "    </File>")?;
    }
    writeln!(output, "  </Files>")?;
    
    writeln!(output, "</SecurityReport>")?;
    Ok(())
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
     .replace('\'', "&apos;")
}

fn print_csv_report(report: &SecurityReport, output: Box<dyn Write>) -> Result<()> {
    let mut csv_writer = csv::Writer::from_writer(output);
    
    // Write header
    csv_writer.write_record(&[
        "file_path",
        "file_type", 
        "overall_status",
        "checks"
    ])?;
    
    // Write data rows
    for file_check in &report.files {
        let checks_str = serde_json::to_string(&file_check.checks).unwrap_or_default();
        csv_writer.write_record(&[
            &file_check.file_path,
            &file_check.file_type,
            &file_check.overall_status,
            &checks_str,
        ])?;
    }
    
    csv_writer.flush()?;
    Ok(())
}