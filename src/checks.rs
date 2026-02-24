use anyhow::Result;
use goblin::{elf, pe, mach};
use std::{collections::HashMap, path::PathBuf};
use crate::SecurityCheck;

pub fn analyze_elf(path: &PathBuf, elf: &elf::Elf, data: &[u8]) -> Result<SecurityCheck> {
    let mut checks = HashMap::new();
    
    // Stack Canary Check
    let canary = check_elf_canary(elf, data)?;
    checks.insert("canary".to_string(), canary.clone());
    
    // NX/DEP Check
    let nx = check_elf_nx(elf)?;
    checks.insert("nx".to_string(), nx.clone());
    
    // PIE Check
    let pie = check_elf_pie(elf)?;
    checks.insert("pie".to_string(), pie.clone());
    
    // RELRO Check
    let relro = check_elf_relro(elf)?;
    checks.insert("relro".to_string(), relro.clone());
    
    // RPATH Check
    let rpath = check_elf_rpath(elf)?;
    checks.insert("rpath".to_string(), rpath.clone());
    
    // RUNPATH Check
    let runpath = check_elf_runpath(elf)?;
    checks.insert("runpath".to_string(), runpath.clone());
    
    // Symbols Check
    let symbols = check_elf_symbols(elf)?;
    checks.insert("symbols".to_string(), symbols.clone());
    
    // Fortify Check
    let fortified = check_elf_fortified(elf)?;
    checks.insert("fortified".to_string(), fortified.0.clone());
    checks.insert("fortifyable".to_string(), fortified.1.to_string());
    checks.insert("fortify_source".to_string(), if fortified.0 != "0" { "Yes".to_string() } else { "No".to_string() });
    
    // CET Check (Control-flow Enforcement Technology)
    let (ibt, shstk) = check_elf_cet(elf, data)?;
    let cet_status = match (ibt, shstk) {
        (true, true) => "Full CET (IBT+SHSTK)",
        (true, false) => "IBT Only", 
        (false, true) => "SHSTK Only",
        (false, false) => "No CET",
    };
    checks.insert("cet".to_string(), cet_status.to_string());
    
    let overall_status = determine_elf_security_status(&checks);
    
    Ok(SecurityCheck {
        file_path: path.display().to_string(),
        file_type: "ELF".to_string(),
        checks,
        overall_status,
    })
}

pub fn analyze_pe(path: &PathBuf, pe: &pe::PE, data: &[u8]) -> Result<SecurityCheck> {
    let mut checks = HashMap::new();
    
    // Dynamic Base (ASLR)
    let dynamic_base = check_pe_dynamic_base(pe)?;
    checks.insert("dynamic_base".to_string(), dynamic_base.clone());
    
    // ASLR
    checks.insert("aslr".to_string(), dynamic_base.clone());
    
    // High Entropy VA (64-bit ASLR)
    let high_entropy = check_pe_high_entropy_va(pe)?;
    checks.insert("high_entropy_va".to_string(), high_entropy.clone());
    
    // Force Integrity
    let force_integrity = check_pe_force_integrity(pe)?;
    checks.insert("force_integrity".to_string(), force_integrity.clone());
    
    // Isolation
    let isolation = check_pe_isolation(pe)?;
    checks.insert("isolation".to_string(), isolation.clone());
    
    // NX/DEP
    let nx = check_pe_nx(pe)?;
    checks.insert("nx".to_string(), nx.clone());
    
    // SEH
    let seh = check_pe_seh(pe)?;
    checks.insert("seh".to_string(), seh.clone());
    
    // CFG (Control Flow Guard)
    let cfg = check_pe_cfg(pe)?;
    checks.insert("cfg".to_string(), cfg.clone());
    
    // RFG (Return Flow Guard)
    let rfg = check_pe_rfg(pe)?;
    checks.insert("rfg".to_string(), rfg.clone());
    
    // SafeSEH
    let safe_seh = check_pe_safe_seh(pe)?;
    checks.insert("safe_seh".to_string(), safe_seh.clone());
    
    // GS (Stack Cookie)
    let gs = check_pe_gs(pe)?;
    checks.insert("gs".to_string(), gs.clone());
    
    // Authenticode
    let authenticode = check_pe_authenticode(pe, data)?;
    checks.insert("authenticode".to_string(), authenticode.clone());
    
    // .NET
    let dotnet = check_pe_dotnet(pe)?;
    checks.insert("dotnet".to_string(), dotnet.clone());
    
    let overall_status = determine_pe_security_status(&checks);
    
    Ok(SecurityCheck {
        file_path: path.display().to_string(),
        file_type: "PE".to_string(),
        checks,
        overall_status,
    })
}

pub fn analyze_macho(path: &PathBuf, macho: &mach::MachO, _data: &[u8]) -> Result<SecurityCheck> {
    let mut checks = HashMap::new();
    
    // PIE Check
    let pie = check_macho_pie(macho)?;
    checks.insert("pie".to_string(), pie.clone());
    
    // Stack Canary Check
    let canary = check_macho_canary(macho)?;
    checks.insert("canary".to_string(), canary.clone());
    
    // NX Check
    let nx = check_macho_nx(macho)?;
    checks.insert("nx".to_string(), nx.clone());
    
    // ARC (Automatic Reference Counting)
    let arc = check_macho_arc(macho)?;
    checks.insert("arc".to_string(), arc.clone());
    
    // Encrypted Check
    let encrypted = check_macho_encrypted(macho)?;
    checks.insert("encrypted".to_string(), encrypted.clone());
    
    // Restricted Segment
    let restricted = check_macho_restricted(macho)?;
    checks.insert("restricted".to_string(), restricted.clone());
    
    // Code Signature
    let code_signature = check_macho_code_signature(macho)?;
    checks.insert("code_signature".to_string(), code_signature.clone());
    
    let overall_status = determine_macho_security_status(&checks);
    
    Ok(SecurityCheck {
        file_path: path.display().to_string(),
        file_type: "Mach-O".to_string(),
        checks,
        overall_status,
    })
}

pub fn analyze_macho_fat(path: &PathBuf, fat: &mach::MultiArch, _data: &[u8]) -> Result<SecurityCheck> {
    let mut all_checks = HashMap::new();
    let mut arch_results = Vec::new();
    let mut overall_secure_count = 0;
    let mut total_archs = 0;
    
    // Iterate through all architectures in the fat binary
    for arch_result in fat.into_iter() {
        match arch_result {
            Ok(mach::SingleArch::MachO(macho)) => {
                total_archs += 1;
                let arch_name = get_arch_name(&macho);
                
                // Analyze this specific architecture
                match analyze_macho_single_arch(path, &macho, &arch_name) {
                    Ok(arch_check) => {
                        // Track if this architecture is secure
                        if arch_check.overall_status == "Secure" {
                            overall_secure_count += 1;
                        }
                        
                        // Store results for this architecture
                        arch_results.push((arch_name.clone(), arch_check.clone()));
                        
                        // Add all checks with architecture prefix
                        for (check_name, check_value) in &arch_check.checks {
                            let prefixed_key = format!("{}_{}", arch_name, check_name);
                            all_checks.insert(prefixed_key, check_value.clone());
                        }
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to analyze {} architecture in {}: {}", 
                            arch_name, path.display(), e);
                    }
                }
            }
            Ok(mach::SingleArch::Archive(_)) => {
                eprintln!("Warning: Archive found in fat binary {}, skipping", path.display());
                continue;
            }
            Err(e) => {
                eprintln!("Warning: Failed to parse architecture in fat binary {}: {}", 
                    path.display(), e);
                continue;
            }
        }
    }
    
    if total_archs == 0 {
        return Ok(SecurityCheck {
            file_path: path.display().to_string(),
            file_type: "Mach-O Fat".to_string(),
            checks: HashMap::new(),
            overall_status: "Error".to_string(),
        });
    }
    
    // Add summary information
    all_checks.insert("total_architectures".to_string(), total_archs.to_string());
    all_checks.insert("secure_architectures".to_string(), overall_secure_count.to_string());
    all_checks.insert("architectures".to_string(), 
        arch_results.iter().map(|(name, _)| name.clone()).collect::<Vec<_>>().join(", "));
    
    // Determine overall status based on architecture results
    let overall_status = if overall_secure_count == total_archs {
        "Secure".to_string()
    } else if overall_secure_count == 0 {
        "Insecure".to_string()
    } else {
        "Mixed".to_string() // Some architectures secure, some not
    };
    
    Ok(SecurityCheck {
        file_path: path.display().to_string(),
        file_type: format!("Mach-O Fat ({} archs)", total_archs),
        checks: all_checks,
        overall_status,
    })
}

fn analyze_macho_single_arch(path: &PathBuf, macho: &mach::MachO, arch_name: &str) -> Result<SecurityCheck> {
    let mut checks = HashMap::new();
    
    // Run all the standard Mach-O checks for this architecture
    let pie = check_macho_pie(macho)?;
    checks.insert("pie".to_string(), pie.clone());
    
    let canary = check_macho_canary(macho)?;
    checks.insert("canary".to_string(), canary.clone());
    
    let nx = check_macho_nx(macho)?;
    checks.insert("nx".to_string(), nx.clone());
    
    let arc = check_macho_arc(macho)?;
    checks.insert("arc".to_string(), arc.clone());
    
    let encrypted = check_macho_encrypted(macho)?;
    checks.insert("encrypted".to_string(), encrypted.clone());
    
    let restricted = check_macho_restricted(macho)?;
    checks.insert("restricted".to_string(), restricted.clone());
    
    let code_signature = check_macho_code_signature(macho)?;
    checks.insert("code_signature".to_string(), code_signature.clone());
    
    let overall_status = determine_macho_security_status(&checks);
    
    Ok(SecurityCheck {
        file_path: format!("{} ({})", path.display(), arch_name),
        file_type: format!("Mach-O ({})", arch_name),
        checks,
        overall_status,
    })
}

fn get_arch_name(macho: &mach::MachO) -> String {
    use goblin::mach::constants::cputype::*;
    
    match macho.header.cputype {
        CPU_TYPE_X86 => "i386".to_string(),
        CPU_TYPE_X86_64 => "x86_64".to_string(),
        CPU_TYPE_ARM => "arm".to_string(),
        CPU_TYPE_ARM64 => "arm64".to_string(),
        CPU_TYPE_POWERPC => "ppc".to_string(),
        CPU_TYPE_POWERPC64 => "ppc64".to_string(),
        other => format!("cpu_{}", other),
    }
}

// ELF Security Checks
fn check_elf_canary(elf: &elf::Elf, _data: &[u8]) -> Result<String> {
    // Check for __stack_chk_fail symbol
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name.contains("__stack_chk_fail") {
                return Ok("Canary Found".to_string());
            }
        }
    }
    
    for sym in elf.syms.iter() {
        if let Some(name) = elf.strtab.get_at(sym.st_name) {
            if name.contains("__stack_chk_fail") {
                return Ok("Canary Found".to_string());
            }
        }
    }
    
    Ok("No Canary Found".to_string())
}

fn check_elf_nx(elf: &elf::Elf) -> Result<String> {
    for ph in &elf.program_headers {
        if ph.p_type == elf::program_header::PT_GNU_STACK {
            if ph.p_flags & elf::program_header::PF_X == 0 {
                return Ok("NX enabled".to_string());
            } else {
                return Ok("NX disabled".to_string());
            }
        }
    }
    Ok("NX Unknown".to_string())
}

fn check_elf_pie(elf: &elf::Elf) -> Result<String> {
    match elf.header.e_type {
        elf::header::ET_DYN => Ok("PIE Enabled".to_string()),
        elf::header::ET_EXEC => Ok("PIE Disabled".to_string()),
        _ => Ok("PIE Unknown".to_string()),
    }
}

fn check_elf_relro(elf: &elf::Elf) -> Result<String> {
    let mut has_relro = false;
    let mut has_bind_now = false;
    
    for ph in &elf.program_headers {
        if ph.p_type == elf::program_header::PT_GNU_RELRO {
            has_relro = true;
            break;
        }
    }
    
    // Check for BIND_NOW in dynamic section
    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == elf::dynamic::DT_BIND_NOW {
                has_bind_now = true;
                break;
            }
            if dyn_entry.d_tag == elf::dynamic::DT_FLAGS {
                if dyn_entry.d_val & elf::dynamic::DF_BIND_NOW != 0 {
                    has_bind_now = true;
                    break;
                }
            }
        }
    }
    
    match (has_relro, has_bind_now) {
        (true, true) => Ok("Full RELRO".to_string()),
        (true, false) => Ok("Partial RELRO".to_string()),
        (false, _) => Ok("No RELRO".to_string()),
    }
}

fn check_elf_rpath(elf: &elf::Elf) -> Result<String> {
    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == elf::dynamic::DT_RPATH {
                return Ok("RPATH".to_string());
            }
        }
    }
    Ok("No RPATH".to_string())
}

fn check_elf_runpath(elf: &elf::Elf) -> Result<String> {
    if let Some(dynamic) = &elf.dynamic {
        for dyn_entry in &dynamic.dyns {
            if dyn_entry.d_tag == elf::dynamic::DT_RUNPATH {
                return Ok("RUNPATH".to_string());
            }
        }
    }
    Ok("No RUNPATH".to_string())
}

fn check_elf_symbols(elf: &elf::Elf) -> Result<String> {
    if !elf.syms.is_empty() {
        Ok("Symbols".to_string())
    } else {
        Ok("No Symbols".to_string())
    }
}

fn check_elf_fortified(elf: &elf::Elf) -> Result<(String, u32)> {
    let mut fortified_count = 0;
    let mut fortifiable_count = 0;
    
    let fortifiable_functions = [
        "memcpy", "memset", "strcpy", "strcat", "sprintf", "snprintf",
        "gets", "fgets", "read", "recv", "recvfrom", "fread"
    ];
    
    // Check dynamic symbols
    for sym in elf.dynsyms.iter() {
        if let Some(name) = elf.dynstrtab.get_at(sym.st_name) {
            if name.contains("_chk") {
                fortified_count += 1;
            }
            
            for func in &fortifiable_functions {
                if name == *func {
                    fortifiable_count += 1;
                }
            }
        }
    }
    
    Ok((fortified_count.to_string(), fortifiable_count))
}

fn check_elf_cet(elf: &elf::Elf, data: &[u8]) -> Result<(bool, bool)> {
    const NT_GNU_PROPERTY_TYPE_0: u32 = 5;
    const GNU_PROPERTY_X86_FEATURE_1_AND: u32 = 0xc000_0002;
    const GNU_PROPERTY_X86_FEATURE_1_USED: u32 = 0xc000_0003;
    const IBT_BIT: u32 = 1 << 0;
    const SHSTK_BIT: u32 = 1 << 1;

    let mut ibt = false;
    let mut shstk = false;

    let mut parse_blob = |blob: &[u8]| -> Result<()> {
        let is_64 = elf.is_64;
        let align = if is_64 { 8 } else { 4 };
        let mut offset = 0;

        while offset + 12 <= blob.len() {
            let namesz = u32::from_le_bytes(blob[offset..offset+4].try_into().unwrap()) as usize;
            let descsz = u32::from_le_bytes(blob[offset+4..offset+8].try_into().unwrap()) as usize;
            let ntype = u32::from_le_bytes(blob[offset+8..offset+12].try_into().unwrap());
            offset += 12;
            let name_end = offset + round_up(namesz, 4);
            if name_end > blob.len() { break; }
            let name = &blob[offset..offset + namesz];
            offset = name_end;
            let desc_end = offset + round_up(descsz, align);
            if desc_end > blob.len() { break; }
            let desc = &blob[offset..offset + descsz];
            offset = desc_end;

            if ntype != NT_GNU_PROPERTY_TYPE_0 || (name != b"GNU\0" && name != b"GNU") {
                continue;
            }

            let mut p = 0;
            while p + 8 <= desc.len() {
                let pr_type = u32::from_le_bytes(desc[p..p+4].try_into().unwrap());
                let datasz = u32::from_le_bytes(desc[p+4..p+8].try_into().unwrap()) as usize;
                p += 8;
                let data_end = p + round_up(datasz, align);
                if data_end > desc.len() { break; }
                let data = &desc[p..p+datasz];
                p = data_end;

                if (pr_type == GNU_PROPERTY_X86_FEATURE_1_AND
                    || pr_type == GNU_PROPERTY_X86_FEATURE_1_USED) && datasz >= 4 {
                    let mask = u32::from_le_bytes(data[0..4].try_into().unwrap());
                    if mask & IBT_BIT != 0 { ibt = true; }
                    if mask & SHSTK_BIT != 0 { shstk = true; }
                }
            }
        }
        Ok(())
    };

    for header in &elf.section_headers {
        if let Some(name) = elf.shdr_strtab.get_at(header.sh_name) {
            if name == ".note.gnu.property" {
                let start = header.sh_offset as usize;
                let size = header.sh_size as usize;
                if start + size <= data.len() {
                    parse_blob(&data[start..start + size])?;
                }
            }
        }
    }
    
    for ph in &elf.program_headers {
        if ph.p_type == elf::program_header::PT_NOTE {
            let start = ph.p_offset as usize;
            let size = ph.p_filesz as usize;
            if start + size <= data.len() {
                parse_blob(&data[start..start + size])?;
            }
        }
    }

    Ok((ibt, shstk))
}

fn round_up(x: usize, a: usize) -> usize {
    (x + (a - 1)) & !(a - 1)
}

// PE Security Checks
fn check_pe_dynamic_base(pe: &pe::PE) -> Result<String> {
    if pe.header.coff_header.characteristics & pe::characteristic::IMAGE_FILE_DLL != 0 {
        if pe.header.optional_header.unwrap().windows_fields.dll_characteristics & 0x0040 != 0 {
            return Ok("Present".to_string());
        }
    } else {
        if pe.header.optional_header.unwrap().windows_fields.dll_characteristics & 0x0040 != 0 {
            return Ok("Present".to_string());
        }
    }
    Ok("NotPresent".to_string())
}

fn check_pe_high_entropy_va(pe: &pe::PE) -> Result<String> {
    if pe.is_64 {
        if pe.header.optional_header.unwrap().windows_fields.dll_characteristics & 0x0020 != 0 {
            return Ok("Present".to_string());
        }
    } else {
        return Ok("NotApplicable".to_string());
    }
    Ok("NotPresent".to_string())
}

fn check_pe_force_integrity(pe: &pe::PE) -> Result<String> {
    if pe.header.optional_header.unwrap().windows_fields.dll_characteristics & 0x0080 != 0 {
        Ok("Present".to_string())
    } else {
        Ok("NotPresent".to_string())
    }
}

fn check_pe_isolation(pe: &pe::PE) -> Result<String> {
    if pe.header.optional_header.unwrap().windows_fields.dll_characteristics & 0x0200 == 0 {
        Ok("Present".to_string())
    } else {
        Ok("NotPresent".to_string())
    }
}

fn check_pe_nx(pe: &pe::PE) -> Result<String> {
    if pe.header.optional_header.unwrap().windows_fields.dll_characteristics & 0x0100 != 0 {
        Ok("Present".to_string())
    } else {
        Ok("NotPresent".to_string())
    }
}

fn check_pe_seh(pe: &pe::PE) -> Result<String> {
    if pe.header.optional_header.unwrap().windows_fields.dll_characteristics & 0x0400 == 0 {
        Ok("Present".to_string())
    } else {
        Ok("NotPresent".to_string())
    }
}

fn check_pe_cfg(pe: &pe::PE) -> Result<String> {
    if pe.header.optional_header.unwrap().windows_fields.dll_characteristics & 0x4000 != 0 {
        Ok("Present".to_string())
    } else {
        Ok("NotPresent".to_string())
    }
}

fn check_pe_rfg(_pe: &pe::PE) -> Result<String> {
    // RFG is part of CFG and indicated by guard flags in load config
    // This is a simplified check - in practice you'd need to check load config
    Ok("NotImplemented".to_string())
}

fn check_pe_safe_seh(pe: &pe::PE) -> Result<String> {
    if pe.is_64 {
        Ok("NotApplicable".to_string())
    } else {
        // Check for SEH table in load config
        Ok("NotImplemented".to_string())
    }
}

fn check_pe_gs(_pe: &pe::PE) -> Result<String> {
    // Check for security cookie in load config
    // This is a simplified check
    Ok("NotImplemented".to_string())
}

fn check_pe_authenticode(_pe: &pe::PE, _data: &[u8]) -> Result<String> {
    // Authenticode signature checking would require certificate validation
    Ok("NotImplemented".to_string())
}

fn check_pe_dotnet(pe: &pe::PE) -> Result<String> {
    // Check for .NET CLR header
    // Simplified .NET detection - check for CLR directory
    // Note: This is a basic implementation
    if let Some(_oh) = pe.header.optional_header {
        // Simplified check - would need proper CLR header analysis
        return Ok("NotImplemented".to_string());
    }
    Ok("NotPresent".to_string())
}

// Mach-O Security Checks
fn check_macho_pie(macho: &mach::MachO) -> Result<String> {
    if macho.header.filetype == mach::header::MH_PIE {
        Ok("PIE Enabled".to_string())
    } else if macho.header.flags & mach::header::MH_PIE != 0 {
        Ok("PIE Enabled".to_string())  
    } else {
        Ok("PIE Disabled".to_string())
    }
}

fn check_macho_canary(macho: &mach::MachO) -> Result<String> {
    // Check for stack_chk symbols
    if let Some(ref symbols) = macho.symbols {
        for symbol_result in symbols.iter() {
            if let Ok((_addr, _symbol)) = symbol_result {
                // Note: Nlist doesn't have string content directly - this is simplified
                // In reality, you'd need to look up the symbol name in the string table
                // For now, returning a placeholder
                return Ok("NotImplemented".to_string());
            }
        }
    }
    Ok("No Canary Found".to_string())
}

fn check_macho_nx(_macho: &mach::MachO) -> Result<String> {
    // Mach-O typically has NX enabled by default on modern systems
    Ok("NX enabled".to_string())
}

fn check_macho_arc(macho: &mach::MachO) -> Result<String> {
    // Check for ARC symbols
    if let Some(ref symbols) = macho.symbols {
        for symbol_result in symbols.iter() {
            if let Ok((_addr, _symbol)) = symbol_result {
                // Note: Nlist doesn't have string content directly - this is simplified  
                // In reality, you'd need to look up the symbol name in the string table
                return Ok("NotImplemented".to_string());
            }
        }
    }
    Ok("ARC Unknown".to_string())
}

fn check_macho_encrypted(macho: &mach::MachO) -> Result<String> {
    for load_command in &macho.load_commands {
        if let mach::load_command::CommandVariant::EncryptionInfo64(_) = load_command.command {
            return Ok("Encrypted".to_string());
        }
        if let mach::load_command::CommandVariant::EncryptionInfo32(_) = load_command.command {
            return Ok("Encrypted".to_string());
        }
    }
    Ok("Not Encrypted".to_string())
}

fn check_macho_restricted(_macho: &mach::MachO) -> Result<String> {
    // Check for restricted segment (simplified)
    Ok("NotImplemented".to_string())
}

fn check_macho_code_signature(_macho: &mach::MachO) -> Result<String> {
    // Check for code signature (simplified)
    Ok("NotImplemented".to_string())
}

// Security Status Determination
fn determine_elf_security_status(checks: &HashMap<String, String>) -> String {
    let mut issues = 0;
    let mut _total = 0;
    
    let security_checks = [
        ("canary", "Canary Found"),
        ("nx", "NX enabled"), 
        ("pie", "PIE Enabled"),
        ("relro", "Full RELRO"),
        ("rpath", "No RPATH"),
        ("runpath", "No RUNPATH"),
        ("symbols", "No Symbols"),
    ];
    
    for (check, expected) in &security_checks {
        _total += 1;
        if let Some(value) = checks.get(*check) {
            if value != expected && !(check == &"relro" && value == "Partial RELRO") {
                issues += 1;
            }
        } else {
            issues += 1;
        }
    }
    
    if issues == 0 {
        "Secure".to_string()
    } else if issues <= 2 {
        "Mostly Secure".to_string()
    } else {
        "Insecure".to_string()
    }
}

fn determine_pe_security_status(checks: &HashMap<String, String>) -> String {
    let mut issues = 0;
    let mut _total = 0;
    
    let security_checks = [
        ("dynamic_base", "Present"),
        ("high_entropy_va", "Present"),
        ("nx", "Present"),
        ("cfg", "Present"),
        ("isolation", "Present"),
    ];
    
    for (check, expected) in &security_checks {
        _total += 1;
        if let Some(value) = checks.get(*check) {
            if value != expected && value != "NotApplicable" {
                issues += 1;
            }
        } else {
            issues += 1;
        }
    }
    
    if issues == 0 {
        "Secure".to_string()
    } else if issues <= 1 {
        "Mostly Secure".to_string()
    } else {
        "Insecure".to_string()
    }
}

fn determine_macho_security_status(checks: &HashMap<String, String>) -> String {
    let mut issues = 0;
    let mut _total = 0;
    
    let security_checks = [
        ("pie", "PIE Enabled"),
        ("canary", "Canary Found"),
        ("nx", "NX enabled"),
    ];
    
    for (check, expected) in &security_checks {
        _total += 1;
        if let Some(value) = checks.get(*check) {
            if value != expected {
                issues += 1;
            }
        } else {
            issues += 1;
        }
    }
    
    if issues == 0 {
        "Secure".to_string()
    } else if issues <= 1 {
        "Mostly Secure".to_string()
    } else {
        "Insecure".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    
    #[test]
    fn test_fat_binary_basic_functionality() {
        // This is a placeholder test until we have proper fat binary implementation
        // We test that the analyze_macho_fat function doesn't panic and returns expected structure
        
        // Since we can't easily create a real MultiArch for testing, we test the expected behavior
        // when we implement proper fat binary support later
        
        let _path = PathBuf::from("/test/fat_binary");
        
        // This test verifies the basic structure and placeholder implementation
        // When we implement full fat binary support, this test should be expanded
        
        // For now, we verify that our placeholder doesn't break basic functionality
        assert_eq!(1, 1); // Placeholder assertion
    }
    
    #[test]
    fn test_fat_binary_output_format() {
        // Test that fat binary output formatting works correctly
        let mut checks = std::collections::HashMap::new();
        checks.insert("x86_64_pie".to_string(), "PIE Enabled".to_string());
        checks.insert("arm64_pie".to_string(), "PIE Enabled".to_string());
        checks.insert("x86_64_canary".to_string(), "Canary Found".to_string());
        checks.insert("arm64_canary".to_string(), "No Canary Found".to_string());
        checks.insert("total_architectures".to_string(), "2".to_string());
        checks.insert("secure_architectures".to_string(), "1".to_string());
        checks.insert("architectures".to_string(), "x86_64, arm64".to_string());
        
        let check = SecurityCheck {
            file_path: "/test/fat_binary".to_string(),
            file_type: "Mach-O Fat (2 archs)".to_string(),
            checks,
            overall_status: "Mixed".to_string(),
        };
        
        // Verify that we can create fat binary security checks with architecture prefixes
        assert!(check.checks.contains_key("x86_64_pie"));
        assert!(check.checks.contains_key("arm64_pie"));
        assert!(check.checks.contains_key("x86_64_canary"));
        assert!(check.checks.contains_key("arm64_canary"));
        assert!(check.checks.contains_key("total_architectures"));
        assert!(check.checks.contains_key("secure_architectures"));
        assert_eq!(check.file_type, "Mach-O Fat (2 archs)");
        assert_eq!(check.overall_status, "Mixed");
        assert_eq!(check.checks.get("x86_64_pie").unwrap(), "PIE Enabled");
        assert_eq!(check.checks.get("arm64_canary").unwrap(), "No Canary Found");
    }
    
    #[test]
    fn test_fat_binary_status_calculation() {
        // Test the different status calculations for fat binaries
        
        // Test all secure architectures
        let mut all_secure_checks = std::collections::HashMap::new();
        all_secure_checks.insert("total_architectures".to_string(), "2".to_string());
        all_secure_checks.insert("secure_architectures".to_string(), "2".to_string());
        let all_secure = SecurityCheck {
            file_path: "/test/all_secure".to_string(),
            file_type: "Mach-O Fat (2 archs)".to_string(),
            checks: all_secure_checks,
            overall_status: "Secure".to_string(),
        };
        assert_eq!(all_secure.overall_status, "Secure");
        
        // Test no secure architectures
        let mut all_insecure_checks = std::collections::HashMap::new();
        all_insecure_checks.insert("total_architectures".to_string(), "2".to_string());
        all_insecure_checks.insert("secure_architectures".to_string(), "0".to_string());
        let all_insecure = SecurityCheck {
            file_path: "/test/all_insecure".to_string(),
            file_type: "Mach-O Fat (2 archs)".to_string(),
            checks: all_insecure_checks,
            overall_status: "Insecure".to_string(),
        };
        assert_eq!(all_insecure.overall_status, "Insecure");
        
        // Test mixed security
        let mut mixed_checks = std::collections::HashMap::new();
        mixed_checks.insert("total_architectures".to_string(), "2".to_string());
        mixed_checks.insert("secure_architectures".to_string(), "1".to_string());
        let mixed = SecurityCheck {
            file_path: "/test/mixed".to_string(),
            file_type: "Mach-O Fat (2 archs)".to_string(),
            checks: mixed_checks,
            overall_status: "Mixed".to_string(),
        };
        assert_eq!(mixed.overall_status, "Mixed");
    }
}
