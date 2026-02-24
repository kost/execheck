use anyhow::{bail, Result};
use clap::Parser;
use execheck::{analyze_files, collect_executable_files, print_report, ScanOptions, OutputFormat, FileFilter};
use std::path::PathBuf;

/// Comprehensive security checker for Linux (ELF), Windows (PE), and macOS (Mach-O) executables
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    /// Path(s) to binary or directory to analyze
    #[arg(required = true)]
    paths: Vec<PathBuf>,
    /// Recursive directory scanning
    #[arg(short, long)]
    recursive: bool,
    /// Output format
    #[arg(short, long, value_enum, default_value = "human")]
    output: OutputFormat,
    /// Output file (stdout if not specified)
    #[arg(short = 'f', long)]
    output_file: Option<PathBuf>,
    /// Exit non-zero if any security feature is missing
    #[arg(long)]
    strict: bool,
    /// Show only files with security issues
    #[arg(long)]
    issues_only: bool,
    /// File type filter
    #[arg(long, value_enum, default_value = "all")]
    filter: FileFilterArg,
    /// Custom file extensions to filter (comma-separated, e.g., "exe,dll")
    #[arg(long, value_delimiter = ',')]
    extensions: Option<Vec<String>>,
    /// Stay within single filesystem (Unix-like systems only)
    #[arg(short = 'x', long)]
    one_filesystem: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
enum FileFilterArg {
    /// All executable files (default)
    All,
    /// Only Windows .exe files
    Exe,
    /// Only Windows .dll files
    Dll,
    /// Both .exe and .dll files
    ExeDll,
    /// Custom extensions (use with --extensions)
    Custom,
}

fn main() -> Result<()> {
    let args = Args::parse();
    
    // Convert CLI filter argument to library FileFilter
    let file_filter = match args.filter {
        FileFilterArg::All => FileFilter::All,
        FileFilterArg::Exe => FileFilter::WindowsExecutables,
        FileFilterArg::Dll => FileFilter::WindowsDlls,
        FileFilterArg::ExeDll => FileFilter::WindowsExecutablesAndDlls,
        FileFilterArg::Custom => {
            if let Some(extensions) = args.extensions {
                FileFilter::Extensions(extensions)
            } else {
                eprintln!("Warning: --filter=custom specified but no --extensions provided, using all files");
                FileFilter::All
            }
        }
    };

    let options = ScanOptions {
        recursive: args.recursive,
        issues_only: args.issues_only,
        strict: args.strict,
        file_filter,
        one_filesystem: args.one_filesystem,
    };

    let mut all_files = Vec::new();
    
    for path in &args.paths {
        if path.is_dir() {
            let dir_files = collect_executable_files(path, &options)?;
            all_files.extend(dir_files);
        } else {
            all_files.push(path.clone());
        }
    }

    let report = analyze_files(all_files, &options)?;

    print_report(&report, &args.output, args.output_file.as_ref())?;

    if args.strict && report.summary.insecure_files > 0 {
        bail!("{} files have security issues", report.summary.insecure_files);
    }
    
    Ok(())
}



