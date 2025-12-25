//! Reorder buffer with sequence number tracking and replay protection.
//!
//! This module handles out-of-order packet delivery, implements a jitter buffer,
//! and provides replay attack protection through sequence number validation.

use std::collections::{BTreeMap, VecDeque};
use std::time::{Duration, Instant};

/// Maximum size of the reorder buffer
const MAX_BUFFER_SIZE: usize = 1024;

/// Maximum age of packets in the buffer before they're considered stale
const MAX_PACKET_AGE: Duration = Duration::from_secs(5);

/// Size of the replay window for sequence number tracking
const REPLAY_WINDOW_SIZE: u64 = 1024;

/// Reorder buffer errors
#[derive(Debug, thiserror::Error)]
pub enum ReorderError {
    #[error("Duplicate packet detected: sequence {0}")]
    Duplicate(u64),

    #[error("Packet too old: sequence {0}, expected > {1}")]
    TooOld(u64, u64),

    #[error("Buffer full: cannot accept more packets")]
    BufferFull,

    #[error("Replay detected: sequence {0}")]
    Replay(u64),
}

/// Buffered packet with metadata
#[derive(Debug, Clone)]
struct BufferedPacket {
    /// Packet payload
    data: Vec<u8>,
    /// Time when packet was received
    received_at: Instant,
}

/// Reorder buffer for handling out-of-order packets
pub struct ReorderBuffer {
    /// Expected next sequence number
    next_expected: u64,
    /// Buffered packets awaiting reordering
    buffer: BTreeMap<u64, BufferedPacket>,
    /// Replay detection window (bit field)
    replay_window: VecDeque<bool>,
    /// Base sequence number for replay window
    replay_base: u64,
    /// Maximum buffer size
    max_size: usize,
    /// Maximum packet age
    max_age: Duration,
}

impl ReorderBuffer {
    /// Create a new reorder buffer
    pub fn new() -> Self {
        Self {
            next_expected: 0,
            buffer: BTreeMap::new(),
            replay_window: VecDeque::with_capacity(REPLAY_WINDOW_SIZE as usize),
            replay_base: 0,
            max_size: MAX_BUFFER_SIZE,
            max_age: MAX_PACKET_AGE,
        }
    }

    /// Create a reorder buffer with custom parameters
    pub fn with_params(max_size: usize, max_age: Duration) -> Self {
        Self {
            next_expected: 0,
            buffer: BTreeMap::new(),
            replay_window: VecDeque::with_capacity(REPLAY_WINDOW_SIZE as usize),
            replay_base: 0,
            max_size,
            max_age,
        }
    }

    /// Insert a packet into the reorder buffer
    ///
    /// Returns `Ok(())` if the packet was accepted, or an error if it should be dropped.
    pub fn insert(&mut self, sequence: u64, data: Vec<u8>) -> Result<(), ReorderError> {
        // Check if packet is too old
        if sequence < self.next_expected {
            return Err(ReorderError::TooOld(sequence, self.next_expected));
        }

        // Check for replay attacks (after checking too old, since old packets are replays too)
        if self.is_replay(sequence) {
            return Err(ReorderError::Replay(sequence));
        }

        // Check for duplicates in buffer
        if self.buffer.contains_key(&sequence) {
            return Err(ReorderError::Duplicate(sequence));
        }

        // Check buffer size before buffering
        if self.buffer.len() >= self.max_size {
            return Err(ReorderError::BufferFull);
        }

        // Mark sequence as seen in replay window
        self.mark_seen(sequence);

        // Buffer the packet (even if it's next_expected, retrieve() will handle it)
        self.buffer.insert(
            sequence,
            BufferedPacket {
                data,
                received_at: Instant::now(),
            },
        );

        Ok(())
    }

    /// Retrieve the next in-order packet(s)
    ///
    /// Returns a vector of packets that are now in order, starting with the
    /// next expected sequence number.
    pub fn retrieve(&mut self) -> Vec<(u64, Vec<u8>)> {
        let mut result = Vec::new();

        // Clean up stale packets first
        self.cleanup_stale();

        // Retrieve all consecutive packets starting from next_expected
        while let Some((&seq, _)) = self.buffer.iter().next() {
            if seq != self.next_expected {
                break;
            }

            if let Some(packet) = self.buffer.remove(&seq) {
                result.push((seq, packet.data));
                self.next_expected += 1;
            }
        }

        result
    }

    /// Check if a sequence number represents a replay
    fn is_replay(&self, sequence: u64) -> bool {
        // Packets before the replay base are always replays
        if sequence < self.replay_base {
            return true;
        }

        // Calculate position in replay window
        let offset = sequence.saturating_sub(self.replay_base);

        if offset >= REPLAY_WINDOW_SIZE {
            // Packet is ahead of our window, not a replay
            return false;
        }

        // Check if we've seen this sequence
        self.replay_window
            .get(offset as usize)
            .copied()
            .unwrap_or(false)
    }

    /// Mark a sequence number as seen
    fn mark_seen(&mut self, sequence: u64) {
        if sequence < self.replay_base {
            return; // Too old, ignore
        }

        let offset = sequence.saturating_sub(self.replay_base);

        if offset >= REPLAY_WINDOW_SIZE {
            // Need to slide the window forward
            let slide = offset - REPLAY_WINDOW_SIZE + 1;
            self.slide_window(slide);
        }

        let offset = sequence.saturating_sub(self.replay_base);

        // Ensure window is large enough
        while self.replay_window.len() <= offset as usize {
            self.replay_window.push_back(false);
        }

        if let Some(seen) = self.replay_window.get_mut(offset as usize) {
            *seen = true;
        }
    }

    /// Slide the replay window forward
    fn slide_window(&mut self, positions: u64) {
        for _ in 0..positions.min(self.replay_window.len() as u64) {
            self.replay_window.pop_front();
        }
        self.replay_base += positions;
    }

    /// Clean up stale packets from the buffer
    fn cleanup_stale(&mut self) {
        let now = Instant::now();
        let max_age = self.max_age;

        self.buffer
            .retain(|_, packet| now.duration_since(packet.received_at) < max_age);
    }

    /// Get the next expected sequence number
    pub fn next_expected(&self) -> u64 {
        self.next_expected
    }

    /// Get the current buffer size
    pub fn buffer_size(&self) -> usize {
        self.buffer.len()
    }

    /// Check if the buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Reset the reorder buffer
    pub fn reset(&mut self) {
        self.buffer.clear();
        self.replay_window.clear();
        self.next_expected = 0;
        self.replay_base = 0;
    }

    /// Set the next expected sequence number (for session initialization)
    pub fn set_next_expected(&mut self, sequence: u64) {
        self.next_expected = sequence;
        self.replay_base = sequence.saturating_sub(REPLAY_WINDOW_SIZE / 2);
    }
}

impl Default for ReorderBuffer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_order_packets() {
        let mut buffer = ReorderBuffer::new();

        // Insert packets in order
        assert!(buffer.insert(0, vec![1, 2, 3]).is_ok());
        assert!(buffer.insert(1, vec![4, 5, 6]).is_ok());
        assert!(buffer.insert(2, vec![7, 8, 9]).is_ok());

        // Should be able to retrieve all packets immediately
        let packets = buffer.retrieve();
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].0, 0);
        assert_eq!(packets[1].0, 1);
        assert_eq!(packets[2].0, 2);
        assert_eq!(buffer.next_expected(), 3);
    }

    #[test]
    fn test_out_of_order_packets() {
        let mut buffer = ReorderBuffer::new();

        // Insert packets out of order
        assert!(buffer.insert(0, vec![1]).is_ok());
        assert!(buffer.insert(2, vec![3]).is_ok()); // Gap at seq 1
        assert!(buffer.insert(3, vec![4]).is_ok());

        // Can retrieve packet 0, but 2 and 3 must wait for 1
        let packets = buffer.retrieve();
        assert_eq!(packets.len(), 1);
        assert_eq!(packets[0].0, 0);
        assert_eq!(buffer.buffer_size(), 2); // 2 and 3 still buffered

        // Insert missing packet
        assert!(buffer.insert(1, vec![2]).is_ok());

        // Now should be able to retrieve packets 1, 2, and 3
        let packets = buffer.retrieve();
        assert_eq!(packets.len(), 3);
        assert_eq!(packets[0].0, 1);
        assert_eq!(packets[1].0, 2);
        assert_eq!(packets[2].0, 3);
    }

    #[test]
    fn test_duplicate_detection() {
        let mut buffer = ReorderBuffer::new();

        assert!(buffer.insert(0, vec![1]).is_ok());
        assert!(buffer.insert(1, vec![2]).is_ok());

        // Try to insert duplicate (packet 1 is still in buffer)
        let result = buffer.insert(1, vec![3]);

        // Packet 1 might have been marked as seen in replay window
        // When we try to insert again, it should fail
        match result {
            Err(ReorderError::Duplicate(_)) => {
                // Expected case
            }
            Err(ReorderError::Replay(_)) => {
                // Also acceptable - replay detection caught it
            }
            other => {
                panic!("Expected Duplicate or Replay error, got {:?}", other);
            }
        }
    }

    #[test]
    fn test_too_old_packet() {
        let mut buffer = ReorderBuffer::new();

        assert!(buffer.insert(0, vec![1]).is_ok());
        assert!(buffer.insert(1, vec![2]).is_ok());
        assert!(buffer.insert(2, vec![3]).is_ok());

        // Retrieve packets to advance next_expected
        let packets = buffer.retrieve();
        assert_eq!(packets.len(), 3);
        assert_eq!(buffer.next_expected(), 3);

        // Try to insert old packet (sequence < next_expected)
        let result = buffer.insert(0, vec![4]);
        assert!(matches!(result, Err(ReorderError::TooOld(_, _))));
    }

    #[test]
    fn test_replay_detection() {
        let mut buffer = ReorderBuffer::new();

        // Insert some packets
        assert!(buffer.insert(0, vec![1]).is_ok());
        assert!(buffer.insert(1, vec![2]).is_ok());

        // Try to replay sequence 0
        let result = buffer.insert(0, vec![3]);
        assert!(matches!(
            result,
            Err(ReorderError::Replay(_)) | Err(ReorderError::TooOld(_, _))
        ));
    }

    #[test]
    fn test_buffer_wraparound() {
        let mut buffer = ReorderBuffer::new();

        // Insert packets near u64::MAX to test wraparound handling
        let start = u64::MAX - 10;
        buffer.set_next_expected(start);

        assert!(buffer.insert(start, vec![1]).is_ok());
        assert!(buffer.insert(start + 1, vec![2]).is_ok());

        // Retrieve to advance next_expected
        let packets = buffer.retrieve();
        assert_eq!(packets.len(), 2);
        assert_eq!(buffer.next_expected(), start + 2);
    }

    #[test]
    fn test_buffer_full() {
        let mut buffer = ReorderBuffer::with_params(3, MAX_PACKET_AGE);

        // Fill the buffer with out-of-order packets
        assert!(buffer.insert(1, vec![1]).is_ok());
        assert!(buffer.insert(2, vec![2]).is_ok());
        assert!(buffer.insert(3, vec![3]).is_ok());

        // Buffer should be full
        let result = buffer.insert(4, vec![4]);
        assert!(matches!(result, Err(ReorderError::BufferFull)));
    }

    #[test]
    fn test_reset() {
        let mut buffer = ReorderBuffer::new();

        assert!(buffer.insert(0, vec![1]).is_ok());
        assert!(buffer.insert(2, vec![3]).is_ok());
        assert_eq!(buffer.buffer_size(), 2); // Both packets buffered

        buffer.reset();
        assert_eq!(buffer.buffer_size(), 0);
        assert_eq!(buffer.next_expected(), 0);
    }
}
