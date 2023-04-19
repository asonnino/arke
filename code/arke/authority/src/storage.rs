use rocksdb::perf;

/// Convenient name for rocksdb's error.
pub type StoreError = rocksdb::Error;
type StoreResult<T> = Result<T, StoreError>;

/// Wrapper around rocksdb.
pub struct Storage(rocksdb::DB);

impl Storage {
    /// Create a new persistent storage.
    pub fn new<P: AsRef<std::path::Path>>(path: P) -> StoreResult<Self> {
        let db = rocksdb::DB::open_default(path)?;
        Ok(Self(db))
    }

    /// Read a value from storage.
    pub fn read(&self, key: &[u8]) -> StoreResult<Option<Vec<u8>>> {
        self.0.get(key)
    }

    /// Write a value to storage.
    pub fn write(&self, key: &[u8], value: &[u8]) -> StoreResult<()> {
        self.0.put(key, value)
    }

    pub fn log_metrics(&self) {
        // Flush cache first.
        // TODO(eoz): Figure out why flush is ineffective
        // Sample log:
        // Memory usage stats:
        // Mem table total: 2048, Mem table unflushed: 2048, Mem table readers total: 4509, Cache total: 0
        self.flush_cache();

        // Print database stats.
        if let Ok(Some(db_stats)) = self.0.property_value("rocksdb.dbstats") {
            println!("{}", db_stats);
        } else {
            panic!("Error retrieving DB stats.");
        }

        // Print memory stats.
        if let Ok(mem_stats) = perf::get_memory_usage_stats(Some(&[&self.0]), None) {
            println!("Memory usage stats: Mem table total: {}, Mem table unflushed: {}, Mem table readers total: {}, Cache total: {}",
            mem_stats.mem_table_total, mem_stats.mem_table_unflushed, mem_stats.mem_table_readers_total, mem_stats.cache_total);
        } else {
            panic!("Error retrieving memory usage stats.");
        }
    }

    pub fn flush_cache(&self) {
        if self.0.flush().is_err() {
            panic!("Panic flushing the cache.");
        }
    }
}
