use std::time::Duration;

pub struct FrequencyController {
    base_interval: Duration,
    current_interval: Duration,
    temp_threshold: f64,
    max_backoff_factor: f64,
}

impl FrequencyController {
    pub fn new(base_interval: Duration, temp_threshold: f64) -> Self {
        Self {
            base_interval,
            current_interval: base_interval,
            temp_threshold,
            max_backoff_factor: 10.0,
        }
    }

    pub fn update(&mut self, current_temp: f64) -> Duration {
        if current_temp <= self.temp_threshold {
            self.current_interval = self.base_interval;
        } else {
            let overshoot = (current_temp - self.temp_threshold) / 10.0;
            let factor = (1.0 + overshoot * 2.0).min(self.max_backoff_factor);
            self.current_interval = Duration::from_secs_f64(
                self.base_interval.as_secs_f64() * factor
            );
        }
        self.current_interval
    }

    pub fn current_interval(&self) -> Duration {
        self.current_interval
    }

    pub fn is_throttled(&self) -> bool {
        self.current_interval > self.base_interval
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_no_throttle_below_threshold() {
        let mut fc = FrequencyController::new(Duration::from_millis(100), 80.0);
        let interval = fc.update(70.0);
        assert_eq!(interval, Duration::from_millis(100));
        assert!(!fc.is_throttled());
    }

    #[test]
    fn test_throttle_above_threshold() {
        let mut fc = FrequencyController::new(Duration::from_millis(100), 80.0);
        let interval = fc.update(90.0);
        assert!(interval > Duration::from_millis(100));
        assert!(fc.is_throttled());
    }

    #[test]
    fn test_max_backoff() {
        let mut fc = FrequencyController::new(Duration::from_millis(100), 80.0);
        let interval = fc.update(200.0);
        assert_eq!(interval, Duration::from_millis(1000));
    }

    #[test]
    fn test_recovery() {
        let mut fc = FrequencyController::new(Duration::from_millis(100), 80.0);
        fc.update(95.0);
        assert!(fc.is_throttled());
        fc.update(70.0);
        assert!(!fc.is_throttled());
        assert_eq!(fc.current_interval(), Duration::from_millis(100));
    }
}
