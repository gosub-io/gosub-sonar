//! File system helpers for staging and renaming downloaded files.

use std::io;
use std::path::Path;
use tempfile::{Builder, NamedTempFile};

/// Create a temp file in the same directory as `dest` for atomic renaming.
///
/// The temp file is created next to the destination so that the final
/// [`std::fs::rename`] is always within the same filesystem, making it atomic.
///
/// Example: `/downloads/file.pdf` → `/downloads/.file.pdf.part-AB12cd.tmp`
pub fn temp_path_for(dest: &Path) -> io::Result<NamedTempFile> {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let filename = dest.file_name().unwrap_or_default();

    Builder::new()
        .prefix(&format!(".{}.part-", filename.to_string_lossy()))
        .suffix(".tmp")
        .tempfile_in(parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temp_path_creation() -> io::Result<()> {
        let dest = Path::new("/tmp/testfile.txt");
        let temp_file = temp_path_for(dest)?;

        assert!(temp_file.path().exists());
        assert!(temp_file.path().parent() == Some(Path::new("/tmp")));
        assert!(temp_file
            .path()
            .to_string_lossy()
            .contains("testfile.txt.part-"));

        Ok(())
    }
}
