use std::num::Wrapping;

pub struct Random {
    context: [Wrapping<u32>; 4],
}


#[derive(Default)]
pub struct RandomBuilder(Vec<u32>);

impl RandomBuilder {

    pub fn add_seed(mut self, value: u32) -> Self {
        self.seed(value);
        self
    }

    pub fn seed(&mut self, value: u32) -> &mut Self {
        if self.0.len() <= 4 {
            self.0.push(value);
        }
        self
    }
    pub fn build(self) -> Random {
        use std::{
            convert::TryInto,
            time::{SystemTime, UNIX_EPOCH},
        };
        let context = match self.0.len() {
            0 => {
                let seed = if let Ok(dur) = SystemTime::now().duration_since(UNIX_EPOCH) {
                    dur.as_nanos().try_into().unwrap_or(0)
                } else {
                    0
                };
                Self::build_with_one(seed)
            }
            1 => Self::build_with_one(self.0[0]),
            2 => Self::build_with_four(self.0[0], self.0[1], 0, 0),
            3 => Self::build_with_four(self.0[0], self.0[1], self.0[2], 0),
            _ => Self::build_with_four(self.0[0], self.0[1], self.0[2], self.0[3]),
        };
        Random { context }
    }
    fn build_with_one(val: u32) -> [Wrapping<u32>; 4] {
        const START: Wrapping<u32> = Wrapping(0x6C078965);
        let mut ret = [Wrapping(0); 4];
        let base = Wrapping(val);
        ret[0] = START * (base ^ (base >> 30)) + Wrapping(1);
        ret[1] = START * (ret[0] ^ (ret[0] >> 30)) + Wrapping(2);
        ret[2] = START * (ret[1] ^ (ret[1] >> 30)) + Wrapping(3);
        ret[3] = START * (ret[2] ^ (ret[2] >> 30)) + Wrapping(4);

        ret
    }
    fn build_with_four(val1: u32, val2: u32, val3: u32, val4: u32) -> [Wrapping<u32>; 4] {
        if val1 | val2 | val3 | val4 == 0 {
            [
                Wrapping(1),
                Wrapping(0x6C_07_89_67),
                Wrapping(0x71_4A_CB_41),
                Wrapping(0x48_07_70_44),
            ]
        } else {
            [
                Wrapping(val1),
                Wrapping(val2),
                Wrapping(val3),
                Wrapping(val4),
            ]
        }
    }
}

impl Random {
    pub fn builder() -> RandomBuilder {
        Default::default()
    }
    
    pub fn random_u32(&mut self) -> u32 {
        let n = self.context[0] ^ (self.context[0] << 11);

        self.context[0] = self.context[1];
        self.context[1] = self.context[2];
        self.context[2] = self.context[3];
        self.context[3] = n ^ (n >> 8) ^ self.context[3] ^ (self.context[3] >> 19);

        self.context[3].0
    }

    pub fn random_u64(&mut self) -> u64 {
        let n1 = self.context[0] ^ (self.context[0] << 11);
        let n2 = self.context[1];
        let n3 = n1 ^ (n1 >> 8) ^ self.context[3];

        self.context[0] = self.context[2];
        self.context[1] = self.context[3];
        self.context[2] = n3 ^ (self.context[3] >> 19);
        self.context[3] = n2 ^ (n2 << 11) ^ ((n2 ^ (n2 << 11)) >> 8) ^ self.context[2] ^ (n3 >> 19);
        let left = (self.context[2].0 as u64) << 32u64;
        left | (self.context[3].0 as u64)
    }

    pub fn get_context(&self) -> (u32, u32, u32, u32) {
        (
            self.context[0].0,
            self.context[1].0,
            self.context[2].0,
            self.context[3].0,
        )
    }
}

#[derive(Default)]
pub struct HashCRC16 {
    table: Option<[Wrapping<u16>; 256]>,
}

impl HashCRC16 {
    fn init(&mut self) {
        let mut table = [Wrapping(0); 256];
        for (i, c) in table.iter_mut().enumerate() {
            let mut val = Wrapping(i as u16);
            for _ in 0..8 {
                if val & Wrapping(1u16) > Wrapping(0u16) {
                    val >>= 1;
                    val ^= Wrapping(0xA001);
                } else {
                    val >>= 1;
                }
            }
            *c = val;
        }
        self.table = Some(table);
    }
    pub fn calc_hash(&mut self, data: &[u8]) -> u16 {
        if self.table.is_none() {
            self.init();
        }
        let mut ret = Wrapping(0);
        if let Some(table) = self.table.as_mut() {
            for val in data {
                let w = Wrapping(*val as u16);
                let idx = w ^ (ret & Wrapping(0xFFu16));
                ret = table[idx.0 as usize] ^ (ret >> 8);
            }
        }
        ret.0
    }
    pub fn calc_string_hash(&mut self, data: &str) -> u16 {
        self.calc_hash(data.as_bytes())
    }
}

#[derive(Default)]
pub struct HashCRC32 {
    table: Option<[Wrapping<u32>; 256]>
}

impl HashCRC32 {
    pub fn init(&mut self) {
        let mut table = [Wrapping(0u32);256];
        for (i, c) in table.iter_mut().enumerate() {
            let mut val = Wrapping(i as u32);
            for _ in 0..8 {
                if val.0 & 1 > 0 {
                    val >>= 1;
                    val ^= Wrapping(0xEDB88320);
                } else {
                    val >>= 1
                }
            }
            *c = val;
        }

        self.table = Some(table);
    }
    pub fn calc_hash(&mut self, data: &[u8]) -> u32 {
        if self.table.is_none() {
            self.init();
        }
        let mut ret = Wrapping(u32::MAX);
        if let Some(table) = self.table.as_mut() {
            for val in data {
                let w = Wrapping(*val as u32);
                let idx = w ^ (ret & Wrapping(0xFFu32));
                ret = table[idx.0 as usize] ^ (ret >> 8);
            }
        }
        !(ret.0)
    }
    pub fn calc_string_hash(&mut self, data: &str) -> u32 {
        self.calc_hash(data.as_bytes())
    }
}

