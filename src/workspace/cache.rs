use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

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

/// On-disk cache entry format
#[derive(Debug, Clone, Serialize, Deserialize)]
struct DiskCacheEntry {
    /// Sorted package names (for verification)
    packages: Vec<String>,
    /// Nixpkgs version (None = default)
    nixpkgs_version: Option<String>,
    /// Resolved store paths
    store_paths: Vec<PathBuf>,
    /// Unix timestamp when entry was created
    created_at: u64,
}

/// Disk-based package cache for CLI mode persistence
///
/// Stores cache entries as JSON files in a cache directory.
/// File naming uses SHA256 hash of (sorted packages + version) for deterministic lookup.
/// TTL is enforced via the `created_at` timestamp in each entry.
#[derive(Debug, Clone)]
pub struct DiskPackageCache {
    cache_dir: PathBuf,
    ttl: Duration,
}

impl DiskPackageCache {
    /// Default TTL: 24 hours (same as in-memory cache)
    const DEFAULT_TTL: Duration = Duration::from_secs(24 * 60 * 60);

    /// Create a new disk cache with default TTL (24 hours)
    pub fn new(cache_dir: PathBuf) -> Self {
        Self {
            cache_dir,
            ttl: Self::DEFAULT_TTL,
        }
    }

    /// Create a new disk cache with custom TTL
    #[cfg(test)]
    pub fn with_ttl(cache_dir: PathBuf, ttl: Duration) -> Self {
        Self { cache_dir, ttl }
    }

    /// Compute the cache file path for given packages and version
    fn cache_file_path(&self, packages: &[&str], nixpkgs_version: Option<&str>) -> PathBuf {
        let key = CacheKey::new(packages, nixpkgs_version);
        let hash = Self::hash_key(&key);
        self.cache_dir.join(format!("{}.json", hash))
    }

    /// Hash a cache key to create a filename
    fn hash_key(key: &CacheKey) -> String {
        let mut hasher = Sha256::new();
        for pkg in &key.packages {
            hasher.update(pkg.as_bytes());
            hasher.update(b"\n");
        }
        if let Some(version) = &key.nixpkgs_version {
            hasher.update(b"version:");
            hasher.update(version.as_bytes());
        }
        let result = hasher.finalize();
        hex::encode(&result[..16]) // Use first 16 bytes (32 hex chars) for shorter filenames
    }

    /// Get cached package paths from disk
    ///
    /// Returns None if:
    /// - Entry doesn't exist
    /// - Entry is expired (past TTL)
    /// - Entry is corrupted/unreadable
    pub fn get(&self, packages: &[&str], nixpkgs_version: Option<&str>) -> Option<Vec<PathBuf>> {
        let path = self.cache_file_path(packages, nixpkgs_version);

        // Read and parse entry
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::NotFound {
                    tracing::debug!(path = %path.display(), error = %e, "disk cache read error");
                }
                return None;
            }
        };

        let entry: DiskCacheEntry = match serde_json::from_str(&content) {
            Ok(e) => e,
            Err(e) => {
                tracing::debug!(path = %path.display(), error = %e, "disk cache parse error");
                // Remove corrupted entry
                let _ = fs::remove_file(&path);
                return None;
            }
        };

        // Check TTL
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > entry.created_at + self.ttl.as_secs() {
            tracing::debug!(path = %path.display(), "disk cache entry expired");
            let _ = fs::remove_file(&path);
            return None;
        }

        tracing::debug!(
            path = %path.display(),
            packages = ?entry.packages,
            "disk cache hit"
        );
        Some(entry.store_paths)
    }

    /// Store package paths in the disk cache
    ///
    /// Errors are logged but not propagated (best-effort caching).
    pub fn insert(&self, packages: &[&str], nixpkgs_version: Option<&str>, paths: Vec<PathBuf>) {
        let path = self.cache_file_path(packages, nixpkgs_version);

        // Ensure cache directory exists
        if let Err(e) = fs::create_dir_all(&self.cache_dir) {
            tracing::debug!(error = %e, "failed to create cache directory");
            return;
        }

        let key = CacheKey::new(packages, nixpkgs_version);
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let entry = DiskCacheEntry {
            packages: key.packages,
            nixpkgs_version: key.nixpkgs_version,
            store_paths: paths,
            created_at: now,
        };

        let content = match serde_json::to_string_pretty(&entry) {
            Ok(c) => c,
            Err(e) => {
                tracing::debug!(error = %e, "failed to serialize cache entry");
                return;
            }
        };

        // Write atomically via temp file + rename
        let temp_path = path.with_extension("tmp");
        if let Err(e) = fs::write(&temp_path, &content) {
            tracing::debug!(error = %e, "failed to write cache temp file");
            return;
        }

        if let Err(e) = fs::rename(&temp_path, &path) {
            tracing::debug!(error = %e, "failed to rename cache file");
            let _ = fs::remove_file(&temp_path);
            return;
        }

        tracing::debug!(
            path = %path.display(),
            packages = ?entry.packages,
            "disk cache insert"
        );
    }

    /// Get the cache directory path
    pub fn cache_dir(&self) -> &Path {
        &self.cache_dir
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

    // DiskPackageCache tests

    #[test]
    fn test_disk_cache_basic_operations() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = DiskPackageCache::new(temp_dir.path().to_path_buf());

        // Cache miss
        assert!(cache.get(&["bash"], None).is_none());

        // Insert and retrieve
        let paths = vec![PathBuf::from("/nix/store/bash-123")];
        cache.insert(&["bash"], None, paths.clone());
        assert_eq!(cache.get(&["bash"], None), Some(paths));
    }

    #[test]
    fn test_disk_cache_package_order_independent() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = DiskPackageCache::new(temp_dir.path().to_path_buf());

        let paths = vec![
            PathBuf::from("/nix/store/bash-123"),
            PathBuf::from("/nix/store/curl-456"),
        ];
        cache.insert(&["bash", "curl"], None, paths.clone());

        // Should find with reversed order
        assert_eq!(cache.get(&["curl", "bash"], None), Some(paths));
    }

    #[test]
    fn test_disk_cache_versioned_entries() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache = DiskPackageCache::new(temp_dir.path().to_path_buf());

        let paths_24 = vec![PathBuf::from("/nix/store/bash-24")];
        let paths_25 = vec![PathBuf::from("/nix/store/bash-25")];

        cache.insert(&["bash"], Some("nixos-24.05"), paths_24.clone());
        cache.insert(&["bash"], Some("nixos-25.11"), paths_25.clone());

        assert_eq!(cache.get(&["bash"], Some("nixos-24.05")), Some(paths_24));
        assert_eq!(cache.get(&["bash"], Some("nixos-25.11")), Some(paths_25));
        assert!(cache.get(&["bash"], None).is_none());
    }

    #[test]
    #[ignore] // Timing-sensitive test, skip in regular test runs
    fn test_disk_cache_expiration() {
        let temp_dir = tempfile::tempdir().unwrap();
        // Use 2 second TTL for reliable testing
        let cache = DiskPackageCache::with_ttl(temp_dir.path().to_path_buf(), Duration::from_secs(2));

        cache.insert(&["bash"], None, vec![PathBuf::from("/nix/store/bash")]);

        // Should be in cache immediately
        assert!(cache.get(&["bash"], None).is_some());

        // Wait for expiration (3 seconds to be safe)
        std::thread::sleep(Duration::from_secs(3));

        // Should be expired now
        assert!(cache.get(&["bash"], None).is_none());
    }

    #[test]
    fn test_disk_cache_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();
        let cache_dir = temp_dir.path().to_path_buf();

        // Insert with first cache instance
        {
            let cache = DiskPackageCache::new(cache_dir.clone());
            cache.insert(&["bash"], None, vec![PathBuf::from("/nix/store/bash-123")]);
        }

        // Retrieve with new cache instance (simulating process restart)
        {
            let cache = DiskPackageCache::new(cache_dir);
            let paths = cache.get(&["bash"], None);
            assert_eq!(paths, Some(vec![PathBuf::from("/nix/store/bash-123")]));
        }
    }
}
