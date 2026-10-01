//! Prints which import slots `install` rewrote in this process, and every import left alone.

fn main() {
    let report = snare_interpose::install();
    for image in &report.images {
        println!("{}", image.path);
        println!("    modelled: {}", image.modelled.join(" "));
        println!("    observed: {}", image.observed.join(" "));
        println!("    not hooked: {}", image.other_imports.join(" "));
    }
    if !report.unresolved.is_empty() {
        println!("not provided by this OS: {}", report.unresolved.join(", "));
    }
}
