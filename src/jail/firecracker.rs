//! Phase 2: Firecracker microVM-based jail isolation.
//!
//! Stub implementation — will be implemented when Phase 1 (namespaces) is stable.
//! Uses Firecracker's native snapshot/branch + userfaultfd CoW cloning.

use crate::error::ApiError;
use crate::jail::JailBackend;
use crate::types::{ExecResult, JailConfig, JailId, SnapshotId};
use std::future::Future;
use std::pin::Pin;

#[derive(Default)]
pub struct FirecrackerBackend;

impl FirecrackerBackend {
    pub fn new() -> Self {
        Self
    }
}

impl JailBackend for FirecrackerBackend {
    fn create(
        &self,
        _config: &JailConfig,
    ) -> Pin<Box<dyn Future<Output = Result<JailId, ApiError>> + Send + '_>> {
        Box::pin(async {
            Err(ApiError::Unsupported(
                "Firecracker backend not yet implemented (Phase 2)".into(),
            ))
        })
    }

    fn start(
        &self,
        _id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<(), ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Firecracker: Phase 2".into())) })
    }

    fn stop(
        &self,
        _id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<(), ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Firecracker: Phase 2".into())) })
    }

    fn destroy(
        &self,
        _id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<(), ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Firecracker: Phase 2".into())) })
    }

    fn exec(
        &self,
        _id: &JailId,
        _cmd: &[String],
        _env: Option<&[String]>,
        _cwd: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<ExecResult, ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Firecracker: Phase 2".into())) })
    }

    fn snapshot(
        &self,
        _id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<SnapshotId, ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Firecracker: Phase 2".into())) })
    }

    fn restore(
        &self,
        _snapshot: &SnapshotId,
    ) -> Pin<Box<dyn Future<Output = Result<JailId, ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Firecracker: Phase 2".into())) })
    }

    fn is_available(&self) -> bool {
        false
    }

    fn backend_name(&self) -> &'static str {
        "firecracker"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_firecracker_not_available() {
        let backend = FirecrackerBackend::new();
        assert!(!backend.is_available());
        assert_eq!(backend.backend_name(), "firecracker");
    }
}
