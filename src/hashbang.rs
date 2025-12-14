//! Hashbang/shebang detection for scripts
//!
//! Parses the first line of a script to detect the interpreter.

/// Detect hashbang from script content and return the interpreter name
///
/// Handles both direct paths (#!/bin/bash) and env-style (#!/usr/bin/env python3)
pub fn detect_interpreter(script: &str) -> Option<String> {
    let first_line = script.lines().next()?;
    if !first_line.starts_with("#!") {
        return None;
    }

    let shebang = first_line.trim_start_matches("#!").trim();

    // Handle "#!/usr/bin/env bash" or "#!/usr/bin/env python3"
    if shebang.contains("/env ") || shebang.contains("/env\t") {
        let binary = shebang.split_whitespace().last()?;
        return Some(binary.to_string());
    }

    // Handle "#!/bin/bash" or "#!/usr/bin/python3"
    let binary = shebang.split('/').next_back()?.split_whitespace().next()?;
    Some(binary.to_string())
}

/// Check if an interpreter is bash-like (bash or sh)
pub fn is_bash_like(interpreter: &str) -> bool {
    interpreter == "bash" || interpreter == "sh"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_direct_bash() {
        assert_eq!(
            detect_interpreter("#!/bin/bash\necho hi"),
            Some("bash".to_string())
        );
    }

    #[test]
    fn test_detect_env_bash() {
        assert_eq!(
            detect_interpreter("#!/usr/bin/env bash\necho hi"),
            Some("bash".to_string())
        );
    }

    #[test]
    fn test_detect_env_python() {
        assert_eq!(
            detect_interpreter("#!/usr/bin/env python3\nprint('hi')"),
            Some("python3".to_string())
        );
    }

    #[test]
    fn test_detect_direct_python() {
        assert_eq!(
            detect_interpreter("#!/usr/bin/python3\nprint('hi')"),
            Some("python3".to_string())
        );
    }

    #[test]
    fn test_no_hashbang() {
        assert_eq!(detect_interpreter("echo hi"), None);
    }

    #[test]
    fn test_empty_script() {
        assert_eq!(detect_interpreter(""), None);
    }

    #[test]
    fn test_is_bash_like() {
        assert!(is_bash_like("bash"));
        assert!(is_bash_like("sh"));
        assert!(!is_bash_like("python3"));
        assert!(!is_bash_like("node"));
    }

    #[test]
    fn test_bash_with_args() {
        assert_eq!(
            detect_interpreter("#!/bin/bash -e\necho hi"),
            Some("bash".to_string())
        );
    }
}
