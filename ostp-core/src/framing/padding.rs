use rand::Rng;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrafficProfile {
    JsonRpc,
    HttpsBurst,
    VideoStream,
}

impl TrafficProfile {
    pub fn target_size(&self, current: usize) -> usize {
        match self {
            TrafficProfile::JsonRpc => align_up(current.max(220), 64).min(1280),
            TrafficProfile::HttpsBurst => align_up(current.max(1200), 128).min(1280),
            TrafficProfile::VideoStream => align_up(current.max(900), 188).min(1280),
        }
    }
}

fn align_up(v: usize, align: usize) -> usize {
    v.div_ceil(align) * align
}

#[derive(Debug, Clone, Copy)]
pub enum PaddingStrategy {
    Fixed(usize),
    Adaptive,
    Profile(TrafficProfile),
}

#[derive(Debug, Clone)]
pub struct AdaptivePadder {
    pub mtu_hint: usize,
    pub max_pad: usize,
    pub strategy: PaddingStrategy,
}

impl AdaptivePadder {
    pub fn new(mtu_hint: usize, max_pad: usize, strategy: PaddingStrategy) -> Self {
        Self {
            mtu_hint,
            max_pad,
            strategy,
        }
    }

    pub fn padding_for_len(&self, payload_len: usize) -> usize {
        match self.strategy {
            PaddingStrategy::Fixed(target) => target.saturating_sub(payload_len),
            PaddingStrategy::Adaptive => {
                let base_bucket = 64;
                let bucketized = payload_len.div_ceil(base_bucket) * base_bucket;
                let mut target = bucketized.clamp(base_bucket, self.mtu_hint);
                if target < payload_len {
                    target = payload_len;
                }

                let base_pad = target - payload_len;
                let jitter_cap = self.max_pad.saturating_sub(base_pad);
                let jitter = if jitter_cap == 0 {
                    0
                } else {
                    rand::thread_rng().gen_range(0..=jitter_cap.min(256))
                };

                (base_pad + jitter).min(self.max_pad)
            }
            PaddingStrategy::Profile(prof) => {
                let target = prof.target_size(payload_len);
                target.saturating_sub(payload_len).min(self.max_pad)
            }
        }
    }

    pub fn build_padding(&self, payload_len: usize) -> Vec<u8> {
        let len = self.padding_for_len(payload_len);
        let mut buf = vec![0_u8; len];
        if len > 0 {
            rand::thread_rng().fill(&mut buf[..]);
        }
        buf
    }
}
