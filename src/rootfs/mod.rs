pub mod nix;

use std::path::{Path, PathBuf};

/// Rootfs provider: generates minimal filesystems for jail containers.
pub struct RootfsProvider {
    pub cache_dir: PathBuf,
}

impl RootfsProvider {
    pub fn new(cache_dir: PathBuf) -> Self {
        Self { cache_dir }
    }

    /// Create a minimal rootfs in the target directory.
    /// For now, creates a basic directory structure.
    /// Phase 1: basic dirs. Phase 2: NixOS flake integration.
    pub fn create_minimal_rootfs(&self, target: &Path) -> anyhow::Result<()> {
        let dirs = [
            "bin", "dev", "etc", "home", "lib", "proc", "root", "run", "sbin", "sys", "tmp",
            "usr/bin", "usr/lib", "usr/sbin", "var/log", "var/tmp",
        ];

        for dir in &dirs {
            std::fs::create_dir_all(target.join(dir))?;
        }

        // Basic /etc files
        std::fs::write(target.join("etc/hostname"), "jail\n")?;
        std::fs::write(
            target.join("etc/resolv.conf"),
            "nameserver 8.8.8.8\nnameserver 8.8.4.4\n",
        )?;
        std::fs::write(
            target.join("etc/passwd"),
            "root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/usr/bin/nologin\n",
        )?;
        std::fs::write(target.join("etc/group"), "root:x:0:\nnobody:x:65534:\n")?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_create_minimal_rootfs() {
        let tmp = TempDir::new().unwrap();
        let provider = RootfsProvider::new(tmp.path().to_path_buf());
        let target = tmp.path().join("rootfs");

        provider.create_minimal_rootfs(&target).unwrap();

        assert!(target.join("bin").exists());
        assert!(target.join("dev").exists());
        assert!(target.join("etc").exists());
        assert!(target.join("proc").exists());
        assert!(target.join("tmp").exists());
        assert!(target.join("usr/bin").exists());
        assert!(target.join("etc/hostname").exists());
        assert!(target.join("etc/resolv.conf").exists());
        assert!(target.join("etc/passwd").exists());

        let hostname = std::fs::read_to_string(target.join("etc/hostname")).unwrap();
        assert_eq!(hostname.trim(), "jail");
    }
}
