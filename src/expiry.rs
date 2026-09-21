//! Independent ban/captcha deadlines in the shared decision cache.

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct DecisionExpiry {
    pub ban: i64,
    pub captcha: i64,
}

impl DecisionExpiry {
    pub const fn empty() -> Self {
        Self { ban: 0, captcha: 0 }
    }

    /// Zero means unlimited, so it dominates a finite deadline when merging.
    pub fn merge(&mut self, present: u8, bit: u8, expires: i64) {
        let deadline = match bit {
            1 => &mut self.ban,
            2 => &mut self.captcha,
            _ => return,
        };
        *deadline = if present & bit == 0 {
            expires
        } else if *deadline == 0 || expires == 0 {
            0
        } else {
            (*deadline).max(expires)
        };
    }

    pub fn active_mask(&self, present: u8, now: i64) -> u8 {
        let mut active = present;
        if self.ban != 0 && now >= self.ban {
            active &= !1;
        }
        if self.captcha != 0 && now >= self.captcha {
            active &= !2;
        }
        active
    }

    pub fn clear_bit(&mut self, bit: u8) {
        match bit {
            1 => self.ban = 0,
            2 => self.captcha = 0,
            _ => {}
        }
    }

    pub fn prune_inactive(&mut self, present: u8, now: i64) -> u8 {
        let active = self.active_mask(present, now);
        if active & 1 == 0 {
            self.ban = 0;
        }
        if active & 2 == 0 {
            self.captcha = 0;
        }
        active
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ban_expires_before_captcha_even_without_a_stream_deletion() {
        let mut expiry = DecisionExpiry::empty();
        expiry.merge(0, 1, 60);
        expiry.merge(1, 2, 3600);
        assert_eq!(expiry.active_mask(3, 59), 3);
        assert_eq!(expiry.active_mask(3, 60), 2);
        assert_eq!(expiry.active_mask(3, 3600), 0);
    }

    #[test]
    fn unlimited_deadlines_and_readding_a_removed_type() {
        let mut expiry = DecisionExpiry::empty();
        expiry.merge(0, 1, 60);
        expiry.merge(1, 1, 120);
        assert_eq!(expiry.ban, 120);
        expiry.merge(1, 1, 0);
        expiry.merge(1, 1, 240);
        assert_eq!(expiry.active_mask(1, i64::MAX), 1);
        expiry.merge(0, 1, 300);
        assert_eq!(expiry.active_mask(1, 300), 0);
    }

    #[test]
    fn prune_inactive_clears_expired_deadlines() {
        let mut expiry = DecisionExpiry::empty();
        expiry.merge(0, 1, 60);
        expiry.merge(1, 2, 3600);
        assert_eq!(expiry.prune_inactive(3, 60), 2);
        assert_eq!(expiry.ban, 0);
        assert_eq!(expiry.captcha, 3600);
    }
}
