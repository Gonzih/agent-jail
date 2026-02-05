//! NixOS flake → rootfs generation.
//!
//! Shells out to `nix build .#rootfs` to generate a minimal NixOS rootfs.
//! The flake defines: bash, coreutils, curl, ca-certificates as base.
//! Agent profiles add: python3, node, git, build-essential.

use crate::error::ApiError;
use std::path::{Path, PathBuf};

pub struct NixBuilder {
    pub nix_binary: String,
}

impl NixBuilder {
    pub fn new() -> Self {
        Self {
            nix_binary: std::env::var("NIX_BINARY").unwrap_or_else(|_| "nix".into()),
        }
    }

    /// Check if Nix is available.
    pub fn is_available(&self) -> bool {
        std::process::Command::new(&self.nix_binary)
            .args(["--version"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Build a rootfs from a Nix flake.
    pub async fn build_rootfs(
        &self,
        flake_ref: &str,
        output_attr: &str,
        link_path: &Path,
    ) -> Result<PathBuf, ApiError> {
        let attr = format!("{}#{}", flake_ref, output_attr);

        let output = tokio::process::Command::new(&self.nix_binary)
            .args([
                "build",
                &attr,
                "--out-link",
                &link_path.to_string_lossy(),
                "--no-link",
            ])
            .output()
            .await
            .map_err(|e| ApiError::Internal(format!("Nix build failed: {}", e)))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(ApiError::Internal(format!("Nix build failed: {}", stderr)));
        }

        Ok(link_path.to_path_buf())
    }
}

impl Default for NixBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nix_builder_creation() {
        let builder = NixBuilder::new();
        assert_eq!(builder.nix_binary, "nix");
    }

    #[test]
    fn test_nix_availability_check() {
        let builder = NixBuilder::new();
        // May or may not be available — just verify no panic
        let _ = builder.is_available();
    }
}
