//! Build script to generate build-time information

use vergen::EmitBuilder;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Generate build-time environment variables
    EmitBuilder::builder().build_date().git_sha(false).emit()?;

    Ok(())
}
