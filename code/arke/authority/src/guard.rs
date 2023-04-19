use std::{
    collections::HashMap,
    hash::Hash,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use tokio::{
    sync::{Mutex, OwnedMutexGuard, RwLock},
    task::JoinHandle,
    time::sleep,
};

type Locks<K> = Arc<RwLock<HashMap<K, Arc<Mutex<()>>>>>;

pub struct Guard<K> {
    locks: Locks<K>,
    locks_size: Arc<AtomicUsize>,
    _cleaner: JoinHandle<()>,
}

impl<K> Default for Guard<K>
where
    K: Sync + Send + 'static + Eq + Hash + Clone,
{
    fn default() -> Self {
        Self::new(Self::DEFAULT_CAPACITY, Self::CLEANUP_PRECISION)
    }
}

impl<K> Guard<K> {
    const DEFAULT_CAPACITY: usize = 100_000;
    const CLEANUP_PRECISION: Duration = Duration::from_secs(1);
}

impl<K> Guard<K>
where
    K: Sync + Send + 'static + Eq + Hash + Clone,
{
    pub fn new(capacity: usize, cleanup_precision: Duration) -> Self {
        let locks = Arc::new(RwLock::new(HashMap::with_capacity(capacity * 2)));
        let locks_size = Arc::new(AtomicUsize::new(0));

        let locks_cloned = locks.clone();
        let locks_size_cloned = locks_size.clone();
        Self {
            locks,
            locks_size,
            _cleaner: tokio::spawn(async move {
                loop {
                    sleep(cleanup_precision).await;
                    if locks_size_cloned.load(Ordering::SeqCst) >= capacity {
                        let removed = Self::cleanup(locks_cloned.clone());
                        locks_size_cloned.fetch_sub(removed, Ordering::SeqCst);
                    }
                }
            }),
        }
    }

    fn cleanup(locks: Locks<K>) -> usize {
        let mut removed = 0;
        if let Ok(mut map) = locks.try_write() {
            map.retain(|_, v| {
                if Arc::strong_count(v) == 1 {
                    let guard = v.try_lock();
                    if guard.is_ok() {
                        removed += 1;
                        false
                    } else {
                        true
                    }
                } else {
                    true
                }
            })
        }
        removed
    }

    pub async fn acquire_lock(&self, key: &K) -> OwnedMutexGuard<()> {
        let element = {
            let map = self.locks.read().await;
            map.get(key).cloned()
        };
        match element {
            Some(guard) => guard.lock_owned().await,
            None => {
                let guard = {
                    let mut map = self.locks.write().await;
                    map.entry(key.clone())
                        .or_insert_with(|| {
                            self.locks_size.fetch_add(1, Ordering::SeqCst);
                            Arc::new(Mutex::new(()))
                        })
                        .clone()
                };
                guard.lock_owned().await
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::{sync::atomic::Ordering, time::Duration};

    use futures::future::join;
    use tokio::time::sleep;

    use crate::guard::Guard;

    #[tokio::test(start_paused = true)]
    async fn conflict() {
        let locks = Guard::default();
        let key = "hello, world!".to_string();
        let guard_1 = locks.acquire_lock(&key);
        let guard_2 = locks.acquire_lock(&key);

        tokio::select! {
            _ = join(guard_1, guard_2) => panic!(""),
            () = sleep(Duration::from_secs(10)) => ()
        }
    }

    #[tokio::test(start_paused = true)]
    async fn no_conflicts() {
        let locks = Guard::default();
        let key = "hello, world!".to_string();

        let guard_1 = locks.acquire_lock(&key).await;
        drop(guard_1);
        let guard_2 = locks.acquire_lock(&key).await;
        drop(guard_2);
    }

    #[tokio::test(start_paused = true)]
    async fn cleanup() {
        let default_capacity = 2;
        let cleanup_precision = Duration::from_secs(1);
        let locks = Guard::new(default_capacity, cleanup_precision);

        // Fill the table above the cleanup threshold.
        for i in 0..default_capacity * 2 {
            let key = format!("{i} - hello, world!");
            let _guard = locks.acquire_lock(&key).await;
        }

        assert_eq!(
            locks.locks_size.load(Ordering::SeqCst),
            default_capacity * 2
        );

        // Wait long enough for the cleanup task to kick in
        sleep(cleanup_precision * 2).await;

        assert_eq!(locks.locks_size.load(Ordering::SeqCst), 0);
    }
}
