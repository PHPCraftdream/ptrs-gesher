use std::sync::{Arc, Mutex};

pub struct ServerMetrics;

pub type Metrics = Arc<Mutex<ServerMetrics>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metrics_creates_default() {
        let m: Metrics = Arc::new(Mutex::new(ServerMetrics));
        let _lock = m.lock().unwrap();
    }

    #[test]
    fn metrics_is_clone() {
        let m: Metrics = Arc::new(Mutex::new(ServerMetrics));
        let m2 = m.clone();
        drop(m);
        let _lock = m2.lock().unwrap();
    }
}
