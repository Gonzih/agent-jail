pub mod firecracker;
pub mod namespace;

use crate::error::ApiError;
use crate::types::{ExecResult, JailConfig, JailId, SnapshotId};
use std::future::Future;
use std::pin::Pin;

/// Trait defining the jail isolation backend.
/// Phase 1: Linux namespaces + CRIU (namespace.rs)
/// Phase 2: Firecracker microVMs (firecracker.rs)
pub trait JailBackend: Send + Sync {
    fn create(
        &self,
        config: &JailConfig,
    ) -> Pin<Box<dyn Future<Output = Result<JailId, ApiError>> + Send + '_>>;

    fn start(&self, id: &JailId)
        -> Pin<Box<dyn Future<Output = Result<(), ApiError>> + Send + '_>>;

    fn stop(&self, id: &JailId) -> Pin<Box<dyn Future<Output = Result<(), ApiError>> + Send + '_>>;

    fn destroy(
        &self,
        id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<(), ApiError>> + Send + '_>>;

    fn exec(
        &self,
        id: &JailId,
        cmd: &[String],
        env: Option<&[String]>,
        cwd: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<ExecResult, ApiError>> + Send + '_>>;

    fn snapshot(
        &self,
        id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<SnapshotId, ApiError>> + Send + '_>>;

    fn restore(
        &self,
        snapshot: &SnapshotId,
    ) -> Pin<Box<dyn Future<Output = Result<JailId, ApiError>> + Send + '_>>;

    fn is_available(&self) -> bool;

    fn backend_name(&self) -> &'static str;
}

/// Stub backend for non-Linux platforms and testing.
/// Returns Unsupported for all operations that require real isolation.
pub struct StubBackend;

impl JailBackend for StubBackend {
    fn create(
        &self,
        _config: &JailConfig,
    ) -> Pin<Box<dyn Future<Output = Result<JailId, ApiError>> + Send + '_>> {
        Box::pin(async {
            Err(ApiError::Unsupported(
                "Stub backend: no real isolation".into(),
            ))
        })
    }

    fn start(
        &self,
        _id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<(), ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Stub backend".into())) })
    }

    fn stop(
        &self,
        _id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<(), ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Stub backend".into())) })
    }

    fn destroy(
        &self,
        _id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<(), ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Stub backend".into())) })
    }

    fn exec(
        &self,
        _id: &JailId,
        _cmd: &[String],
        _env: Option<&[String]>,
        _cwd: Option<&str>,
    ) -> Pin<Box<dyn Future<Output = Result<ExecResult, ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Stub backend".into())) })
    }

    fn snapshot(
        &self,
        _id: &JailId,
    ) -> Pin<Box<dyn Future<Output = Result<SnapshotId, ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Stub backend".into())) })
    }

    fn restore(
        &self,
        _snapshot: &SnapshotId,
    ) -> Pin<Box<dyn Future<Output = Result<JailId, ApiError>> + Send + '_>> {
        Box::pin(async { Err(ApiError::Unsupported("Stub backend".into())) })
    }

    fn is_available(&self) -> bool {
        false
    }

    fn backend_name(&self) -> &'static str {
        "stub"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stub_backend_not_available() {
        let backend = StubBackend;
        assert!(!backend.is_available());
        assert_eq!(backend.backend_name(), "stub");
    }

    #[tokio::test]
    async fn test_stub_backend_returns_unsupported() {
        let backend = StubBackend;
        let config = JailConfig::default();
        let result = backend.create(&config).await;
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::Unsupported(_) => {}
            other => panic!("Expected Unsupported, got {:?}", other),
        }
    }
}
