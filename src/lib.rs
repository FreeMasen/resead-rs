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

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn random() {
        let mut r = Random::builder().add_seed(200).build();
        let target32 = [
            940615229u32,
            2135984020u32,
            799482374u32,
            3072700755u32,
            179947716u32,
            4046357024u32,
            3884923153u32,
            2109383578u32,
            3112286977u32,
            1010504083u32,
            2732777652u32,
            183247105u32,
            3187788526u32,
            1515381556u32,
            4009774986u32,
            2224004930u32,
            879321991u32,
            4193217917u32,
            343806421u32,
            3975408023u32,
            2482625237u32,
            301975890u32,
            4125852161u32,
            2250732154u32,
            3679797017u32,
            873449592u32,
            2640166770u32,
            542423553u32,
            1384899813u32,
            411937476u32,
            1750802568u32,
            3982105392u32,
            3774572210u32,
            2505386979u32,
            616236705u32,
            419764893u32,
            586162681u32,
            516299895u32,
            3803488000u32,
            3545538617u32,
            1879616579u32,
            1577264017u32,
            403307470u32,
            1848296862u32,
            1534400172u32,
            472754680u32,
            1269691960u32,
            1939066086u32,
            2157999182u32,
            4055068619u32,
            3582680051u32,
            949111128u32,
            3138603008u32,
            3518277022u32,
            1584343192u32,
            4095570564u32,
            3580852047u32,
            2709757993u32,
            2257549161u32,
            2568600686u32,
            929199373u32,
            2338068768u32,
            1989477149u32,
            574307181u32,
            114681914u32,
            1831560409u32,
            3010989962u32,
            1214491355u32,
            3781038037u32,
            3613766283u32,
            2752705458u32,
            4050821273u32,
            3762502085u32,
            440942252u32,
            703910196u32,
            1306970875u32,
            3029491603u32,
            4017400563u32,
            1619442520u32,
            457970849u32,
            1023721116u32,
            2003675389u32,
            577012019u32,
            1509322946u32,
            1092539710u32,
            1529788320u32,
            1564854511u32,
            3084899301u32,
            14636805u32,
            778203913u32,
            1561576602u32,
            337277990u32,
            4001853151u32,
            3544232509u32,
            280267739u32,
            3620239023u32,
            49023775u32,
            3572203557u32,
            1622483760u32,
            4099693703u32,
        ];
        for (i, t) in target32.iter().enumerate() {
            let c = r.random_u32();
            assert_eq!(*t, c, "failed on iteration for u32 {}, value {} expected {}", i, c, *t);
        }
        let target64 = [
            10847489112624616892u64,
            15532169589028003808u64,
            522460580994996160u64,
            16620067751845103675u64,
            4456409969820593901u64,
            8963490091968335832u64,
            9253985981693561054u64,
            2504731770550627465u64,
            13248834308077695558u64,
            12307222015852827267u64,
            15547150253993190132u64,
            6101328212770838514u64,
            3445759905466744748u64,
            11247562374786347988u64,
            16366931235963132777u64,
            7498898646939598995u64,
            5949231431788493788u64,
            6998944291204813039u64,
            1581706618998049075u64,
            4971029806265630877u64,
            16565850303456968266u64,
            8263612707705129561u64,
            7840251080397890092u64,
            8624264358126043091u64,
            10857920063153809534u64,
            13284139937645227u64,
            3802845780505898920u64,
            12933765041107881497u64,
            7221725002021176160u64,
            16109540834429657828u64,
            15242478733591555124u64,
            3985790565777332266u64,
            8364618671786447079u64,
            17325519578071271919u64,
            15855114090605589580u64,
            11470738557436465417u64,
            1910447191452640977u64,
            6808341487920819357u64,
            15689439030096460707u64,
            5510905548822614448u64,
            3847565980073326771u64,
            4439800234737467480u64,
            5054652954323072003u64,
            1923600431260956840u64,
            16192183125892460282u64,
            15483204203833072635u64,
            14640938891008779512u64,
            11318856706784487854u64,
            14155256466950065872u64,
            8174414645794959318u64,
            3599649051524949981u64,
            7164084849813784530u64,
            5810817520492259321u64,
            5715080020922712784u64,
            13803516900899567643u64,
            8570589997123602301u64,
            5104129592194863859u64,
            14881272346259536536u64,
            3354464620640059108u64,
            6161532404798531905u64,
            17385371328713758030u64,
            16478946927158009373u64,
            1270549347064452729u64,
            2766718275080166715u64,
            15360757430748695037u64,
            10377094315489647282u64,
            872639520271951194u64,
            12141872232015130142u64,
            2047186334847388610u64,
            12210279142197144321u64,
            10065899005513058751u64,
            6689796369747090274u64,
            12666216430932330826u64,
            12591954129292306222u64,
            6678253365619721355u64,
            14691708707980469055u64,
            16811429300932806174u64,
            3529625347048573750u64,
            17389091706653089668u64,
            8094477512470575982u64,
            2861071402895042949u64,
            11311568000471495312u64,
            14662194338639189690u64,
            8429720118578957876u64,
            1736428763034365373u64,
            1804509210541959147u64,
            2939020118371122520u64,
            10467763324018025460u64,
            4298526844657582901u64,
            13187536842642633908u64,
            5245478180735065818u64,
            13562971066631613428u64,
            6399786046628032014u64,
            963428267248134003u64,
            5707646310281283170u64,
            14988096148561203653u64,
            9845778767523179903u64,
            7263753957127673560u64,
            13799151619255487315u64,
            8641745092524991827u64,
        ];
        for (i, t) in target64.iter().enumerate() {
            let c = r.random_u64();
            assert_eq!(*t, c, "failed on iteration for u32 {}, value {} expected {}", i, c, *t);
        }
    }

    #[test]
    fn hash16() {
        let mut hasher = HashCRC16::default();
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(47827, hasher.calc_hash(&bytes));
    }
    #[test]
    fn hash32() {
        let mut hasher = HashCRC32::default();
        let bytes: Vec<u8> = (0u8..=255).collect();
        assert_eq!(688229491, hasher.calc_hash(&bytes));
    }
}
