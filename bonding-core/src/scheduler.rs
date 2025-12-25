//! Scheduler for path selection and bonding logic.
//!
//! This module implements the core bonding logic that decides how to distribute
//! packets across multiple network paths (interfaces). It supports multiple modes:
//!
//! - **STRIPE**: Round-robin distribution across all paths
//! - **PREFERRED**: Prefer specific paths (e.g., Ethernet over Wi-Fi)
//! - **REDUNDANT**: Send duplicate packets across multiple paths
//!
//! The scheduler is designed to be pure and deterministic for testability.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Bonding mode configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BondingMode {
    /// Round-robin striping across all paths
    Stripe,
    /// Prefer specific paths based on metrics
    Preferred,
    /// Send redundant copies across multiple paths
    Redundant,
}

/// Path identifier
pub type PathId = usize;

/// Path metrics for scoring
#[derive(Debug, Clone)]
pub struct PathMetrics {
    /// Round-trip time (EWMA)
    pub rtt: Duration,
    /// Packet loss rate (0.0 - 1.0)
    pub loss_rate: f64,
    /// Queue depth (packets waiting to send)
    pub queue_depth: usize,
    /// Recent goodput (bytes/sec)
    pub goodput: u64,
    /// Last update timestamp
    pub last_update: Instant,
}

impl Default for PathMetrics {
    fn default() -> Self {
        Self {
            rtt: Duration::from_millis(50),
            loss_rate: 0.0,
            queue_depth: 0,
            goodput: 0,
            last_update: Instant::now(),
        }
    }
}

impl PathMetrics {
    /// Calculate a score for this path (higher is better)
    pub fn score(&self) -> f64 {
        let rtt_score = 1000.0 / (self.rtt.as_millis() as f64).max(1.0);
        let loss_score = 1.0 - self.loss_rate;
        let queue_score = 1.0 / (self.queue_depth as f64 + 1.0);
        let goodput_score = (self.goodput as f64) / 1_000_000.0; // Normalize to Mbps

        // Weighted combination
        (rtt_score * 0.3) + (loss_score * 0.4) + (queue_score * 0.2) + (goodput_score * 0.1)
    }

    /// Update RTT with exponential moving average
    pub fn update_rtt(&mut self, new_rtt: Duration, alpha: f64) {
        let old_rtt = self.rtt.as_millis() as f64;
        let new_rtt_ms = new_rtt.as_millis() as f64;
        let updated = (alpha * new_rtt_ms) + ((1.0 - alpha) * old_rtt);
        self.rtt = Duration::from_millis(updated as u64);
        self.last_update = Instant::now();
    }

    /// Update loss rate with exponential moving average
    pub fn update_loss(&mut self, lost: bool, alpha: f64) {
        let loss_value = if lost { 1.0 } else { 0.0 };
        self.loss_rate = (alpha * loss_value) + ((1.0 - alpha) * self.loss_rate);
        self.last_update = Instant::now();
    }
}

/// Scheduler decision result
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SchedulerDecision {
    /// Primary path to send on
    pub primary_path: PathId,
    /// Additional paths for redundancy (if any)
    pub redundant_paths: Vec<PathId>,
}

/// Packet scheduler
pub struct Scheduler {
    /// Bonding mode
    mode: BondingMode,
    /// Metrics for each path
    metrics: HashMap<PathId, PathMetrics>,
    /// Current round-robin index (for STRIPE mode)
    stripe_index: usize,
    /// Available path IDs
    paths: Vec<PathId>,
}

impl Scheduler {
    /// Create a new scheduler with the specified mode
    pub fn new(mode: BondingMode) -> Self {
        Self {
            mode,
            metrics: HashMap::new(),
            stripe_index: 0,
            paths: Vec::new(),
        }
    }

    /// Add a path to the scheduler
    pub fn add_path(&mut self, path_id: PathId) {
        if !self.paths.contains(&path_id) {
            self.paths.push(path_id);
            self.metrics.insert(path_id, PathMetrics::default());
        }
    }

    /// Remove a path from the scheduler
    pub fn remove_path(&mut self, path_id: PathId) {
        self.paths.retain(|&id| id != path_id);
        self.metrics.remove(&path_id);
    }

    /// Update metrics for a path
    pub fn update_metrics(&mut self, path_id: PathId, metrics: PathMetrics) {
        self.metrics.insert(path_id, metrics);
    }

    /// Get metrics for a path
    pub fn get_metrics(&self, path_id: PathId) -> Option<&PathMetrics> {
        self.metrics.get(&path_id)
    }

    /// Get mutable metrics for a path
    pub fn get_metrics_mut(&mut self, path_id: PathId) -> Option<&mut PathMetrics> {
        self.metrics.get_mut(&path_id)
    }

    /// Schedule a packet and return the decision
    ///
    /// This is a pure function that takes the current state and returns
    /// which path(s) to use for sending the packet.
    pub fn schedule(&mut self) -> Option<SchedulerDecision> {
        if self.paths.is_empty() {
            return None;
        }

        match self.mode {
            BondingMode::Stripe => self.schedule_stripe(),
            BondingMode::Preferred => self.schedule_preferred(),
            BondingMode::Redundant => self.schedule_redundant(),
        }
    }

    /// Schedule using round-robin striping
    fn schedule_stripe(&mut self) -> Option<SchedulerDecision> {
        if self.paths.is_empty() {
            return None;
        }

        let path = self.paths[self.stripe_index % self.paths.len()];
        self.stripe_index = self.stripe_index.wrapping_add(1);

        Some(SchedulerDecision {
            primary_path: path,
            redundant_paths: Vec::new(),
        })
    }

    /// Schedule using preferred path (best score)
    fn schedule_preferred(&self) -> Option<SchedulerDecision> {
        if self.paths.is_empty() {
            return None;
        }

        // Find path with best score
        let best_path = self
            .paths
            .iter()
            .max_by(|&&a, &&b| {
                let score_a = self.metrics.get(&a).map(|m| m.score()).unwrap_or(0.0);
                let score_b = self.metrics.get(&b).map(|m| m.score()).unwrap_or(0.0);
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied()?;

        Some(SchedulerDecision {
            primary_path: best_path,
            redundant_paths: Vec::new(),
        })
    }

    /// Schedule using redundancy (send on all paths)
    fn schedule_redundant(&self) -> Option<SchedulerDecision> {
        if self.paths.is_empty() {
            return None;
        }

        // Use best path as primary, others as redundant
        let best_path = self
            .paths
            .iter()
            .max_by(|&&a, &&b| {
                let score_a = self.metrics.get(&a).map(|m| m.score()).unwrap_or(0.0);
                let score_b = self.metrics.get(&b).map(|m| m.score()).unwrap_or(0.0);
                score_a
                    .partial_cmp(&score_b)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
            .copied()?;

        let redundant_paths: Vec<PathId> = self
            .paths
            .iter()
            .copied()
            .filter(|&id| id != best_path)
            .collect();

        Some(SchedulerDecision {
            primary_path: best_path,
            redundant_paths,
        })
    }

    /// Get the current bonding mode
    pub fn mode(&self) -> BondingMode {
        self.mode
    }

    /// Set the bonding mode
    pub fn set_mode(&mut self, mode: BondingMode) {
        self.mode = mode;
    }

    /// Get the number of active paths
    pub fn path_count(&self) -> usize {
        self.paths.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_stripe_mode() {
        let mut scheduler = Scheduler::new(BondingMode::Stripe);
        scheduler.add_path(0);
        scheduler.add_path(1);
        scheduler.add_path(2);

        // Should round-robin through paths
        assert_eq!(scheduler.schedule().unwrap().primary_path, 0);
        assert_eq!(scheduler.schedule().unwrap().primary_path, 1);
        assert_eq!(scheduler.schedule().unwrap().primary_path, 2);
        assert_eq!(scheduler.schedule().unwrap().primary_path, 0);
    }

    #[test]
    fn test_scheduler_preferred_mode() {
        let mut scheduler = Scheduler::new(BondingMode::Preferred);
        scheduler.add_path(0);
        scheduler.add_path(1);

        // Set better metrics for path 1
        let metrics1 = PathMetrics {
            rtt: Duration::from_millis(10),
            loss_rate: 0.01,
            ..Default::default()
        };
        scheduler.update_metrics(1, metrics1);

        let metrics0 = PathMetrics {
            rtt: Duration::from_millis(100),
            loss_rate: 0.1,
            ..Default::default()
        };
        scheduler.update_metrics(0, metrics0);

        // Should prefer path 1 (better metrics)
        let decision = scheduler.schedule().unwrap();
        assert_eq!(decision.primary_path, 1);
        assert!(decision.redundant_paths.is_empty());
    }

    #[test]
    fn test_scheduler_redundant_mode() {
        let mut scheduler = Scheduler::new(BondingMode::Redundant);
        scheduler.add_path(0);
        scheduler.add_path(1);
        scheduler.add_path(2);

        let decision = scheduler.schedule().unwrap();

        // Should have one primary and two redundant paths
        assert_eq!(decision.redundant_paths.len(), 2);

        // All paths should be used
        let all_paths: Vec<PathId> = std::iter::once(decision.primary_path)
            .chain(decision.redundant_paths.iter().copied())
            .collect();
        assert_eq!(all_paths.len(), 3);
    }

    #[test]
    fn test_path_metrics_score() {
        let metrics = PathMetrics {
            rtt: Duration::from_millis(20),
            loss_rate: 0.01,
            queue_depth: 5,
            goodput: 10_000_000, // 10 Mbps
            ..Default::default()
        };

        let score = metrics.score();
        assert!(score > 0.0);
    }

    #[test]
    fn test_path_metrics_update_rtt() {
        let mut metrics = PathMetrics::default();
        let initial_rtt = metrics.rtt;

        metrics.update_rtt(Duration::from_millis(100), 0.5);

        // RTT should be between initial and new value
        assert!(metrics.rtt > initial_rtt);
        assert!(metrics.rtt < Duration::from_millis(100));
    }

    #[test]
    fn test_path_metrics_update_loss() {
        let mut metrics = PathMetrics::default();
        assert_eq!(metrics.loss_rate, 0.0);

        metrics.update_loss(true, 0.1);
        assert!(metrics.loss_rate > 0.0);
        assert!(metrics.loss_rate < 0.2);
    }

    #[test]
    fn test_scheduler_no_paths() {
        let mut scheduler = Scheduler::new(BondingMode::Stripe);
        assert!(scheduler.schedule().is_none());
    }

    #[test]
    fn test_scheduler_add_remove_path() {
        let mut scheduler = Scheduler::new(BondingMode::Stripe);
        assert_eq!(scheduler.path_count(), 0);

        scheduler.add_path(0);
        assert_eq!(scheduler.path_count(), 1);

        scheduler.add_path(1);
        assert_eq!(scheduler.path_count(), 2);

        scheduler.remove_path(0);
        assert_eq!(scheduler.path_count(), 1);

        let decision = scheduler.schedule().unwrap();
        assert_eq!(decision.primary_path, 1);
    }
}
