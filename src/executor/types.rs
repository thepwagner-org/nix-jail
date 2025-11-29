//! Shared types for job execution
//!
//! Re-exports from traits.rs for backward compatibility.
//! New code should import from `crate::executor` directly.

// Re-exports are intentional for backward compatibility even if unused in this crate
#[allow(unused_imports)]
pub use super::traits::{
    ExecutionConfig, ExecutionHandle, Executor, ExecutorError, HardeningProfile,
};

// Backward compatibility alias - prefer `Executor` for new code
#[allow(unused_imports)]
pub use super::traits::Executor as JobExecutor;
