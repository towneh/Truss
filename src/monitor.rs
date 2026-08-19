//! The consuming half: turning arriving payloads back into DMX channel values.
//!
//! Everything else in this crate asks whether the lane survives. This asks what
//! a client does with what comes out of it, which is a different question with
//! a different failure mode: a stream can deliver every record intact and still
//! drive the wrong fixture if the consumer applies a block to the wrong slots.
//!
//! It is deliberately small and dependency-free. A player implementing the same
//! lane needs exactly this: hold the latest value for every channel, apply
//! blocks as they arrive, and notice when a universe stops being updated.

use std::collections::BTreeMap;

use crate::artnet::UNIVERSE_SLOTS;
use crate::payload::Block;

#[derive(Debug, Clone)]
pub struct Universe {
    pub values: [u8; UNIVERSE_SLOTS],
    /// Highest slot ever written, so a partially patched universe does not
    /// report 512 channels of mostly nothing.
    pub len: usize,
    /// Records that carried this universe.
    pub updates: u64,
    /// Age reported by the most recent block for it, in microseconds.
    pub last_age_us: u32,
}

impl Default for Universe {
    fn default() -> Self {
        Self {
            values: [0; UNIVERSE_SLOTS],
            len: 0,
            updates: 0,
            last_age_us: 0,
        }
    }
}

/// What one applied record changed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Applied {
    pub blocks: usize,
    /// Channels whose value differs from what was held before.
    pub changed: usize,
    /// Slots the block addressed past the end of a universe. Non-zero means the
    /// sender and the receiver disagree about the size of a universe, which is
    /// worth reporting rather than clamping silently.
    pub out_of_range: usize,
}

/// The current value of every channel a client has been told about.
#[derive(Debug, Default, Clone)]
pub struct DmxState {
    universes: BTreeMap<u16, Universe>,
    pub records: u64,
    pub changed_total: u64,
}

impl DmxState {
    pub fn apply(&mut self, blocks: &[Block]) -> Applied {
        let mut out = Applied {
            blocks: blocks.len(),
            ..Applied::default()
        };
        self.records += 1;

        for b in blocks {
            let u = self.universes.entry(b.universe).or_default();
            u.updates += 1;
            u.last_age_us = b.age_us;

            let start = b.start as usize;
            for (i, &v) in b.values.iter().enumerate() {
                let slot = start + i;
                if slot >= UNIVERSE_SLOTS {
                    out.out_of_range += 1;
                    continue;
                }
                if u.values[slot] != v {
                    u.values[slot] = v;
                    out.changed += 1;
                }
                if slot + 1 > u.len {
                    u.len = slot + 1;
                }
            }
        }
        self.changed_total += out.changed as u64;
        out
    }

    /// A channel's current value. `None` for a universe never received, which is
    /// distinct from a channel sitting at zero: one is unpatched, the other is
    /// a fixture told to be dark.
    pub fn value(&self, universe: u16, slot: u16) -> Option<u8> {
        let u = self.universes.get(&universe)?;
        let slot = slot as usize;
        if slot >= u.len {
            None
        } else {
            Some(u.values[slot])
        }
    }

    pub fn universe(&self, universe: u16) -> Option<&Universe> {
        self.universes.get(&universe)
    }

    pub fn universes(&self) -> impl Iterator<Item = (&u16, &Universe)> {
        self.universes.iter()
    }

    pub fn universe_count(&self) -> usize {
        self.universes.len()
    }

    /// Channels held across every universe, counted by how far each is patched.
    pub fn channel_count(&self) -> usize {
        self.universes.values().map(|u| u.len).sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn block(universe: u16, start: u16, values: Vec<u8>) -> Block {
        Block {
            universe,
            start,
            age_us: 1_000,
            values,
        }
    }

    #[test]
    fn a_block_lands_on_the_slots_it_names() {
        let mut s = DmxState::default();
        s.apply(&[block(3, 100, vec![10, 20, 30])]);

        assert_eq!(s.value(3, 100), Some(10));
        assert_eq!(s.value(3, 102), Some(30));
        assert_eq!(
            s.value(3, 99),
            Some(0),
            "slots below the run are still held"
        );
        assert_eq!(s.value(3, 103), None, "past the patch is not a value");
        assert_eq!(s.value(4, 100), None, "an unheard universe is not zero");
    }

    #[test]
    fn only_real_changes_count_as_changes() {
        let mut s = DmxState::default();
        let first = s.apply(&[block(0, 0, vec![1, 2, 3])]);
        assert_eq!(first.changed, 3);

        let same = s.apply(&[block(0, 0, vec![1, 2, 3])]);
        assert_eq!(same.changed, 0, "a repeated snapshot is not activity");

        let moved = s.apply(&[block(0, 0, vec![1, 9, 3])]);
        assert_eq!(moved.changed, 1);
        assert_eq!(s.records, 3);
    }

    #[test]
    fn a_later_block_wins_because_values_are_absolute() {
        let mut s = DmxState::default();
        s.apply(&[block(0, 0, vec![255])]);
        s.apply(&[block(0, 0, vec![0])]);
        assert_eq!(s.value(0, 0), Some(0));
    }

    #[test]
    fn a_run_past_the_end_of_a_universe_is_reported_not_wrapped() {
        let mut s = DmxState::default();
        let applied = s.apply(&[block(0, 510, vec![1, 2, 3, 4])]);
        assert_eq!(applied.out_of_range, 2);
        assert_eq!(s.value(0, 511), Some(2));
        // The two that did not fit must not have landed anywhere else.
        assert_eq!(s.value(1, 0), None);
        assert_eq!(s.universe(0).unwrap().len, 512);
    }

    #[test]
    fn partial_patches_are_counted_by_how_far_they_reach() {
        let mut s = DmxState::default();
        s.apply(&[block(0, 0, vec![0; 16]), block(9, 0, vec![0; 512])]);
        assert_eq!(s.universe_count(), 2);
        assert_eq!(s.channel_count(), 16 + 512);
    }
}
