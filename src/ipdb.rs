use binread::io::Cursor;
use binread::{derive_binread, BinRead, NullString};
use memmap2::Mmap;
use std::fs::File;
use std::mem::size_of;
use std::net::IpAddr;
use std::path::Path;

pub struct Ipdb {
    f: Mmap,
    meta: Meta,
}

#[derive(BinRead)]
#[br(magic = b"IPDB")]
#[allow(dead_code)]
struct Meta {
    version: u16, //f[4..5]
    offset: u8,   //f[6]
    ip_len: u8,   //f[7]
    #[br(try_map = |x: u64| x.try_into())]
    record_count: usize, //f[8..16]
    #[br(try_map = |x: u64| x.try_into())]
    index_base: usize, //f[16..24]
    reserve: u64, //f[24..32]
}

#[derive(BinRead)]
#[br(import(ip_len: u8))]
struct Index {
    #[br(if(ip_len == 4))]
    ip_v4: Option<u32>,
    #[br(if(ip_len == 8))]
    ip_v6: Option<u64>,
    #[br(try_map = |x: u32| x.try_into())]
    geo_index: usize,
}

#[derive_binread]
struct Geo {
    #[br(temp)]
    #[br(restore_position)]
    mode1: u8,

    #[br(if([1,2].contains(&mode1)))]
    #[br(map = |x: Option<[u8;4]>| x.map(|x| {let mut y = [0u8;4];y[0..3].copy_from_slice(&x[1..4]);u32::from_le_bytes(y) as usize} ))]
    redirect1: Option<usize>,

    #[br(if(![1,2].contains(&mode1)))]
    name1: Option<NullString>,

    #[br(temp)]
    #[br(restore_position)]
    mode2: u8,

    #[br(if([1,2].contains(&mode2)))]
    #[br(map = |x: Option<[u8;4]>| x.map(|x| {let mut y = [0u8;4];y[0..3].copy_from_slice(&x[1..4]);u32::from_le_bytes(y) as usize} ))]
    redirect2: Option<usize>,

    #[br(if(![1,2].contains(&mode2)))]
    name2: Option<NullString>,
}

impl Ipdb {
    pub fn new(path: impl AsRef<Path>) -> Ipdb {
        let file = File::open(path).expect("failed to open the file");
        let f = unsafe { Mmap::map(&file).expect("failed to map the file") };
        let mut reader = Cursor::new(&f[0..size_of::<Meta>()]);
        let meta = Meta::read(&mut reader).unwrap();

        Ipdb { f, meta }
    }

    fn read_index(&self, i: usize) -> (u64, usize) {
        let base = self.meta.index_base;
        let record_size = (self.meta.ip_len + 2 + 1) as usize;
        let pos = base + i * record_size;
        let mut v = [0u8; 13];
        v[..11].copy_from_slice(&self.f[pos..pos + record_size]);

        let mut reader = Cursor::new(&mut v);
        let index = Index::read_args(&mut reader, (self.meta.ip_len,)).unwrap();
        let ip = index
            .ip_v4
            .map_or_else(|| index.ip_v6.unwrap(), |ip| ip as u64);

        (ip, index.geo_index)
    }

    pub fn read_record(&self, i: usize) -> (u64, String, String) {
        let f = &self.f;
        let (ip, geo_index) = self.read_index(i);

        let mut reader = Cursor::new(&f[geo_index..]);
        let mut geo_info = Geo::read(&mut reader).unwrap();

        if let Some(redirect) = geo_info.redirect1 {
            let mut reader = Cursor::new(&f[redirect..]);
            geo_info.name1 = Some(NullString::read(&mut reader).unwrap());
        }

        if let Some(redirect) = geo_info.redirect2 {
            let mut reader = Cursor::new(&f[redirect..]);
            geo_info.name2 = Some(NullString::read(&mut reader).unwrap());
        }

        (
            ip,
            geo_info.name1.map_or("".to_string(), |s| s.to_string()),
            geo_info.name2.map_or("".to_string(), |s| s.to_string()),
        )
    }

    pub fn query(&self, ip: &IpAddr) -> Option<(String, String)> {
        match (ip, self.meta.ip_len) {
            (IpAddr::V4(_), 8) => panic!("excepted ipv6 address, but given ipv4 address"),
            (IpAddr::V6(_), 4) => panic!("excepted ipv4 address, but given ipv6 address"),
            _ => {}
        }

        let needle = match ip {
            IpAddr::V4(v4) => {
                let v4: u32 = (*v4).into();
                v4 as u64
            }
            IpAddr::V6(v6) => {
                let mut v6: u128 = (*v6).into();
                v6 >>= 64;
                v6 as u64
            }
        };

        let mut lo = 0usize;
        let mut hi = self.meta.record_count - 1;

        if needle < self.read_record(lo).0 {
            return None;
        } else {
            let (ip, _) = self.read_index(hi);
            if needle >= ip {
                let (_, s1, s2) = self.read_record(hi);
                return Some((s1, s2));
            }
        }

        let mut mi = 0usize;
        while lo + 1 < hi {
            mi = (lo + hi) / 2;
            let (ip, _) = self.read_index(mi);
            if ip <= needle {
                lo = mi;
            } else {
                hi = mi;
            }
        }

        let (_, geo1, geo2) = self.read_record(mi);

        Some((geo1, geo2))
    }
}
