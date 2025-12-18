use moka::sync::Cache;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Cache key for Nix package resolution
///
/// Combines the list of packages and the nixpkgs version to create
/// a unique cache key. The packages are sorted for consistent hashing.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    /// Sorted list of package names
    packages: Vec<String>,
    /// Nixpkgs version (None = default)
    nixpkgs_version: Option<String>,
}

impl CacheKey {
    /// Create a new cache key from packages and version
    ///
    /// The packages are automatically sorted to ensure consistent cache hits
    /// regardless of the order they were specified.
    pub fn new(packages: &[&str], nixpkgs_version: Option<&str>) -> Self {
        let mut sorted_packages: Vec<String> = packages.iter().map(|s| s.to_string()).collect();
        sorted_packages.sort();

        Self {
            packages: sorted_packages,
            nixpkgs_version: nixpkgs_version.map(|s| s.to_string()),
        }
    }
}

/// Thread-safe in-memory cache for Nix package resolution
///
/// Caches the results of find_nix_packages_with_version() to avoid
/// expensive nix-instantiate and nix-store operations.
///
/// Features:
/// - LRU eviction with configurable max size (default: 1000 entries)
/// - Time-based expiration (default: 24 hours)
/// - Thread-safe using moka::sync::Cache
/// - Automatic package sorting for consistent cache hits
#[derive(Clone, Debug)]
pub struct NixPackageCache {
    cache: Arc<Cache<CacheKey, Vec<PathBuf>>>,
}

impl NixPackageCache {
    /// Create a new cache with default settings
    ///
    /// - Max entries: 1000
    /// - TTL: 24 hours
    pub fn new() -> Self {
        Self::with_config(1000, Duration::from_secs(24 * 60 * 60))
    }

    /// Create a new cache with custom settings
    ///
    /// # Arguments
    /// * `max_capacity` - Maximum number of entries before LRU eviction
    /// * `ttl` - Time-to-live for cache entries
    pub fn with_config(max_capacity: u64, ttl: Duration) -> Self {
        let cache = Cache::builder()
            .max_capacity(max_capacity)
            .time_to_live(ttl)
            .build();

        Self {
            cache: Arc::new(cache),
        }
    }

    /// Get cached package paths
    ///
    /// Returns None if the entry is not in the cache or has expired.
    pub fn get(&self, packages: &[&str], nixpkgs_version: Option<&str>) -> Option<Vec<PathBuf>> {
        let key = CacheKey::new(packages, nixpkgs_version);
        self.cache.get(&key)
    }

    /// Store package paths in the cache
    pub fn insert(&self, packages: &[&str], nixpkgs_version: Option<&str>, paths: Vec<PathBuf>) {
        let key = CacheKey::new(packages, nixpkgs_version);
        self.cache.insert(key, paths);
    }

    /// Get cache entry count for monitoring
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Clear all entries from the cache
    #[cfg(test)]
    pub fn clear(&self) {
        self.cache.invalidate_all();
    }
}

impl Default for NixPackageCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_cache_key_sorting() {
        // Package order should not matter
        let key1 = CacheKey::new(&["bash", "coreutils", "curl"], None);
        let key2 = CacheKey::new(&["curl", "bash", "coreutils"], None);
        assert_eq!(key1, key2);
    }

    #[test]
    fn test_cache_key_version() {
        // Different versions should create different keys
        let key1 = CacheKey::new(&["bash"], Some("nixos-24.05"));
        let key2 = CacheKey::new(&["bash"], Some("nixos-25.11"));
        let key3 = CacheKey::new(&["bash"], None);

        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key2, key3);
    }

    #[test]
    fn test_cache_basic_operations() {
        let cache = NixPackageCache::new();

        // Cache miss
        assert!(cache.get(&["bash"], None).is_none());

        // Insert and retrieve
        let paths = vec![PathBuf::from("/nix/store/bash-123")];
        cache.insert(&["bash"], None, paths.clone());
        assert_eq!(cache.get(&["bash"], None), Some(paths));

        // Package order should not matter
        let paths2 = vec![PathBuf::from("/nix/store/curl-456")];
        cache.insert(&["bash", "curl"], None, paths2.clone());
        assert_eq!(cache.get(&["curl", "bash"], None), Some(paths2));
    }

    #[test]
    fn test_cache_versioned_entries() {
        let cache = NixPackageCache::new();

        let paths_24 = vec![PathBuf::from("/nix/store/bash-24")];
        let paths_25 = vec![PathBuf::from("/nix/store/bash-25")];

        cache.insert(&["bash"], Some("nixos-24.05"), paths_24.clone());
        cache.insert(&["bash"], Some("nixos-25.11"), paths_25.clone());

        assert_eq!(cache.get(&["bash"], Some("nixos-24.05")), Some(paths_24));
        assert_eq!(cache.get(&["bash"], Some("nixos-25.11")), Some(paths_25));
        assert!(cache.get(&["bash"], None).is_none());
    }

    #[test]
    fn test_cache_multiple_entries() {
        let cache = NixPackageCache::new();

        // Cache multiple entries
        let paths1 = vec![PathBuf::from("/nix/store/bash")];
        let paths2 = vec![PathBuf::from("/nix/store/curl")];
        let paths3 = vec![PathBuf::from("/nix/store/jq")];

        cache.insert(&["bash"], None, paths1.clone());
        cache.insert(&["curl"], None, paths2.clone());
        cache.insert(&["jq"], Some("nixos-24.05"), paths3.clone());

        // All should be retrievable
        assert_eq!(cache.get(&["bash"], None), Some(paths1));
        assert_eq!(cache.get(&["curl"], None), Some(paths2));
        assert_eq!(cache.get(&["jq"], Some("nixos-24.05")), Some(paths3));

        // Wrong version should not match
        assert!(cache.get(&["jq"], None).is_none());
    }

    #[test]
    fn test_cache_expiration() {
        // Create cache with 1ms TTL
        let cache = NixPackageCache::with_config(1000, Duration::from_millis(1));

        cache.insert(&["bash"], None, vec![PathBuf::from("/nix/store/bash")]);

        // Should be in cache immediately
        assert!(cache.get(&["bash"], None).is_some());

        // Wait for expiration
        std::thread::sleep(Duration::from_millis(10));

        // Should be expired now
        assert!(cache.get(&["bash"], None).is_none());
    }

    #[test]
    fn test_cache_capacity() {
        // Create cache with capacity of 2
        let cache = NixPackageCache::with_config(2, Duration::from_secs(60));

        cache.insert(&["pkg1"], None, vec![PathBuf::from("/nix/store/pkg1")]);
        cache.insert(&["pkg2"], None, vec![PathBuf::from("/nix/store/pkg2")]);

        // Both should be cached
        assert!(cache.get(&["pkg1"], None).is_some());
        assert!(cache.get(&["pkg2"], None).is_some());

        // Add third entry - should trigger LRU eviction
        cache.insert(&["pkg3"], None, vec![PathBuf::from("/nix/store/pkg3")]);

        // Give moka time to evict (it's async internally)
        std::thread::sleep(Duration::from_millis(10));

        // At least one entry should be present, but not more than capacity
        assert!(cache.entry_count() <= 2);
    }
}
