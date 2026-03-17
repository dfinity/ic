use std::fs;
use std::path::Path;
use regex::Regex;
use syn::{parse_file, visit::Visit, LitInt};
use walkdir::WalkDir;

struct NumericLiteralVisitor {
    literals: Vec<(String, std::ops::Range<usize>)>,
}

impl<'ast> Visit<'ast> for NumericLiteralVisitor {
    fn visit_lit_int(&mut self, i: &'ast LitInt) {
        let lit_str = i.to_string();
        let byte_range = i.span().byte_range();
        self.literals.push((lit_str, byte_range));
    }
}

fn process_file(path: &Path) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    let source = fs::read_to_string(path)?;
    let file = parse_file(&source)?;

    let mut visitor = NumericLiteralVisitor { literals: vec![] };
    visitor.visit_file(&file);

    // Regex to detect buggy literals and capture the suffix
    let suffix_re = Regex::new(r"^(.+?)([iu](?:8|16|32|64|128|size))$")?;

    let mut replacements: Vec<(std::ops::Range<usize>, String)> = vec![];

    for (lit, range) in visitor.literals.iter() {
        let Some(captures) = suffix_re.captures(lit) else {
            // No suffix -> no defect.
            continue;
        };

        let prefix = &captures[1];
        let suffix = &captures[2];

        if prefix.ends_with('_') {
            // Suffix is separated. Good job!
            continue;
        }

        // Found non-compliant code (e.g. 42u64).
        // Add patch to the list.
        replacements.push((range.clone(), format!("{}_{}", prefix, suffix)));
    }

    if replacements.is_empty() {
        return Ok(None); // No changes needed
    }

    let fixed_count = replacements.len();

    // Sort by range start descending so we can replace from end to start
    replacements.sort_by(|a, b| b.0.start.cmp(&a.0.start));

    let mut modified = source.clone();
    for (range, new_lit) in replacements {
        modified.replace_range(range, &new_lit);
    }

    fs::write(path, &modified)?;
    Ok(Some(fixed_count))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let target_dir = if args.len() > 1 {
        &args[1]
    } else {
        "."
    };

    let target_path = Path::new(target_dir);
    if !target_path.exists() {
        eprintln!("Error: directory not found: {}", target_dir);
        std::process::exit(1);
    }

    let mut total_fixed = 0;
    let mut files_modified = 0;

    for entry in WalkDir::new(target_path)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "rs"))
    {
        let path = entry.path();
        match process_file(path) {
            Ok(Some(count)) => {
                println!("Fixed {}: {} literals", path.display(), count);
                total_fixed += count;
                files_modified += 1;
            }
            Ok(None) => {
                // No changes needed
            }
            Err(e) => {
                eprintln!("Error processing {}: {}", path.display(), e);
            }
        }
    }

    println!("\n✓ Processed complete");
    println!("  Files modified: {}", files_modified);
    println!("  Literals fixed: {}", total_fixed);
}
