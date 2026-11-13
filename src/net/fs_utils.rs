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
///
/// A name too long to fit with that around it is cut short, so that the temp name stays within
/// [`NAME_MAX`].
pub fn temp_path_for(dest: &Path) -> io::Result<NamedTempFile> {
    let parent = dest.parent().unwrap_or_else(|| Path::new("."));
    let filename = dest.file_name().unwrap_or_default().to_string_lossy();
    let mut keep = filename.len().min(NAME_MAX - TEMP_NAME_EXTRA);
    while !filename.is_char_boundary(keep) {
        keep -= 1;
    }

    Builder::new()
        .prefix(&format!(".{}.part-", &filename[..keep]))
        .suffix(".tmp")
        .tempfile_in(parent)
}

/// The longest file name most file systems take, in bytes.
const NAME_MAX: usize = 255;

/// What the temp name adds to the destination's: `.`, `.part-`, six random characters and
/// `.tmp`.
const TEMP_NAME_EXTRA: usize = 17;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_temp_path_creation() -> io::Result<()> {
        let dir = std::env::temp_dir();
        let dest = dir.join("testfile.txt");
        let temp_file = temp_path_for(&dest)?;

        assert!(temp_file.path().exists());
        assert!(temp_file.path().parent() == Some(dir.as_path()));
        assert!(temp_file
            .path()
            .to_string_lossy()
            .contains("testfile.txt.part-"));

        Ok(())
    }

    /// A name of 239 bytes or more made a temp name past 255 bytes, which the file system
    /// refuses.
    #[test]
    fn a_long_name_still_gets_a_temp_file() -> io::Result<()> {
        let dir = tempfile::tempdir()?;
        for name in ["a".repeat(255), format!("a{}", "é".repeat(127))] {
            let temp_file = temp_path_for(&dir.path().join(&name))?;
            let temp_name = temp_file.path().file_name().unwrap();
            assert!(temp_name.len() <= NAME_MAX, "{}", temp_name.len());
        }
        Ok(())
    }
}
