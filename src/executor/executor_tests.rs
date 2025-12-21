//! Generic test suite for Executor implementations
//!
//! This module provides tests that work against any `Executor` implementation.
//! Each executor can import and run these tests to verify basic functionality.
//!
//! Usage:
//! ```ignore
//! use crate::executor::executor_tests;
//!
//! #[tokio::test]
//! async fn test_executor_suite() {
//!     let executor = MyExecutor::new();
//!     executor_tests::test_success_execution(&executor).await;
//!     executor_tests::test_stderr_capture(&executor).await;
//!     // ... or run all tests
//! }
//! ```

use super::test_helpers::{collect_output, TestConfigBuilder};
use super::traits::Executor;
use std::time::Duration;

/// Test that a simple echo command succeeds and produces expected output
pub async fn test_success_execution<E: Executor>(executor: &E) {
    let config = TestConfigBuilder::new("test-success")
        .command(vec!["echo", "hello world"])
        .build();

    let handle = executor.execute(config).await.expect("execution failed");
    let output = collect_output(handle).await;

    assert_eq!(output.stdout, vec!["hello world"]);
    assert_eq!(output.exit_code, 0);
}

/// Test that stderr is captured separately from stdout
pub async fn test_stderr_capture<E: Executor>(executor: &E) {
    let config = TestConfigBuilder::new("test-stderr")
        .command(vec!["sh", "-c", "echo error >&2"])
        .build();

    let handle = executor.execute(config).await.expect("execution failed");
    let output = collect_output(handle).await;

    assert_eq!(output.stderr, vec!["error"]);
    assert_eq!(output.exit_code, 0);
}

/// Test that non-zero exit codes are captured correctly
pub async fn test_non_zero_exit<E: Executor>(executor: &E) {
    let config = TestConfigBuilder::new("test-exit")
        .command(vec!["sh", "-c", "exit 42"])
        .build();

    let handle = executor.execute(config).await.expect("execution failed");
    let output = collect_output(handle).await;

    assert_eq!(output.exit_code, 42);
}

/// Test that environment variables are passed to the command
pub async fn test_environment_variables<E: Executor>(executor: &E) {
    let config = TestConfigBuilder::new("test-env")
        .command(vec!["sh", "-c", "echo $TEST_VAR"])
        .env("TEST_VAR", "test_value")
        .build();

    let handle = executor.execute(config).await.expect("execution failed");
    let output = collect_output(handle).await;

    assert_eq!(output.stdout, vec!["test_value"]);
    assert_eq!(output.exit_code, 0);
}

/// Test that multiline output is captured correctly
pub async fn test_multiline_output<E: Executor>(executor: &E) {
    let config = TestConfigBuilder::new("test-multiline")
        .command(vec!["sh", "-c", "echo line1; echo line2; echo line3"])
        .build();

    let handle = executor.execute(config).await.expect("execution failed");
    let output = collect_output(handle).await;

    assert_eq!(output.stdout, vec!["line1", "line2", "line3"]);
    assert_eq!(output.exit_code, 0);
}

/// Test that empty command returns an error
pub async fn test_empty_command_error<E: Executor>(executor: &E) {
    let config = TestConfigBuilder::new("test-empty").command(vec![]).build();

    let result = executor.execute(config).await;
    assert!(result.is_err(), "empty command should fail");
}

/// Test that timeouts are enforced
pub async fn test_timeout_handling<E: Executor>(executor: &E) {
    let config = TestConfigBuilder::new("test-timeout")
        .command(vec!["sleep", "60"])
        .timeout(Duration::from_millis(100))
        .build();

    let handle = executor.execute(config).await.expect("execution failed");
    let output = collect_output(handle).await;

    // Process should have been killed, non-zero exit
    assert_ne!(output.exit_code, 0);
}

/// Test that working directory is respected
pub async fn test_working_directory<E: Executor>(executor: &E) {
    let config = TestConfigBuilder::new("test-pwd")
        .command(vec!["pwd"])
        .working_dir("/tmp")
        .build();

    let handle = executor.execute(config).await.expect("execution failed");
    let output = collect_output(handle).await;

    // Working dir varies by executor and platform:
    // - Chroot executors: /workspace
    // - Simple executors: /tmp or /private/tmp (macOS symlink)
    let pwd = output.stdout.first().expect("no output from pwd");
    assert!(
        pwd == "/tmp" || pwd == "/private/tmp" || pwd == "/workspace",
        "unexpected pwd: {}",
        pwd
    );
    assert_eq!(output.exit_code, 0);
}
