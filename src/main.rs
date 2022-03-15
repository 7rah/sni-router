use anyhow::{anyhow, Result};
use moka::future::Cache;
use qqwry::QQWryData;
use regex::Regex;
use serde_derive::Deserialize;
use simplelog::{error, info, warn, *};
use sni_router::Ipdb;
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::os::unix::prelude::AsRawFd;
use std::str;
use std::sync::Arc;
use tls_parser::TlsMessage::Handshake;
use tls_parser::TlsMessageHandshake::ClientHello;
use tls_parser::{parse_tls_extensions, parse_tls_plaintext, TlsExtension};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::{io, spawn, try_join};

#[derive(Debug, Deserialize)]
struct Config {
    sni: Vec<Sni>,
    global: Global,
}

#[derive(Debug, Deserialize)]
struct Sni {
    name: String,
    inbound: Vec<String>,
    outbound: String,
}

#[derive(Debug, Deserialize)]
struct Global {
    qqwry: String,
    ipdb_v6: String,
}

#[derive(Debug)]
struct Outbound {
    name: String,
    socketaddr: SocketAddr,
}

struct Db {
    rule_sets: Vec<(Regex, usize)>,
    cache: Cache<String, usize>,
    outbounds: Vec<Outbound>,
}

impl Db {
    fn init_from_config(config: Config) -> Self {
        let mut outbounds = Vec::new();
        let mut rule_sets = Vec::new();
        for (i, sni) in config.sni.into_iter().enumerate() {
            let socketaddr = sni.outbound.to_socket_addrs().unwrap().next().unwrap();
            outbounds.push(Outbound {
                name: sni.name,
                socketaddr,
            });

            for rule in sni.inbound {
                rule_sets.push((Regex::new(&rule).unwrap(), i));
            }
        }

        let cache = Cache::new(512);
        Db {
            rule_sets,
            outbounds,
            cache,
        }
    }

    async fn cached_find(&self, domain: &str) -> Option<&Outbound> {
        if let Some(i) = self.cache.get(&domain.to_string()) {
            debug!("hit cache {}:{:?}", domain, self.outbounds[i]);
            return Some(&self.outbounds[i]);
        } else {
            debug!("miss cache {}", domain);
            if let Some(i) = self.find(domain) {
                self.cache.insert(domain.to_string(), i).await;
                return Some(&self.outbounds[i]);
            }
        }
        None
    }

    fn find(&self, domain: &str) -> Option<usize> {
        for (re, i) in &self.rule_sets {
            if re.is_match(domain) {
                return Some(*i);
            }
        }
        None
    }
}

fn init_config() -> Config {
    let arg = "config.toml";
    let mut file = File::open(arg).unwrap();
    let mut toml_str = String::new();
    file.read_to_string(&mut toml_str).unwrap();
    let config: Config = toml::from_str(&toml_str).unwrap();
    config
}

lazy_static::lazy_static! {
    static ref DB:Arc<Db> = Arc::new(Db::init_from_config(init_config()));
    static ref QQWRY:Arc<QQWryData> = {
        let config = init_config();
        let wry = QQWryData::new(config.global.qqwry).unwrap();
        Arc::new(wry)
    };
    static ref IPDB_V6:Ipdb = {
        let config = init_config();
        Ipdb::new(config.global.ipdb_v6)
    };
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ! {
    TermLogger::init(
        LevelFilter::Info,
        ConfigBuilder::new()
            .set_time_to_local(true)
            .set_time_format_str("%FT%T%.3f")
            .build(),
        TerminalMode::Stdout,
        ColorChoice::Auto,
    )
    .unwrap();

    let listener = TcpListener::bind("[::]:443").await.unwrap();

    loop {
        match listener.accept().await {
            Ok((inbound, addr)) => {
                spawn(async move {
                    match serve(inbound).await {
                        Ok(_) => (),
                        Err(e) => warn!("{} {}", addr, e),
                    }
                });
            }
            Err(e) => error!("{}", e),
        }
    }
}

fn mapped_addr_to_ipv4_addr(addr: SocketAddr) -> SocketAddr {
    let mut rawaddr = addr;
    if let IpAddr::V6(addr) = rawaddr.ip() {
        if let Some(addr) = addr.to_ipv4() {
            rawaddr.set_ip(addr.into());
        }
    }
    rawaddr
}

async fn serve(mut inbound: TcpStream) -> Result<()> {
    let buf = &mut [0u8; 2048];
    inbound.peek(buf).await?;
    let domain = parse_sni(buf).unwrap_or_default();
    let result = DB.cached_find(&domain).await;
    if let Some(outbound_config) = result {
        let mut outbound = TcpStream::connect(outbound_config.socketaddr).await?;
        let peer_addr = mapped_addr_to_ipv4_addr(inbound.peer_addr()?);
        let local_addr = mapped_addr_to_ipv4_addr(inbound.local_addr()?);

        spawn(async move { relay(&mut inbound, &mut outbound).await });

        let name = &outbound_config.name;

        let geo = match peer_addr.ip() {
            IpAddr::V4(v4) => QQWRY
                .query(v4)
                .map_or("".to_string(), |g| format!("{} {}", g.area, g.country))
                .replace(" CZ88.NET ", ""),
            IpAddr::V6(v6) => IPDB_V6
                .query(&IpAddr::V6(v6))
                .map_or("".to_string(), |(geo1, geo2)| -> String {
                    geo1 + " " + &geo2
                })
                .replace('\t', " "),
        };

        match (geo.as_str(), domain.as_str()) {
            ("", "") => info!("MATCH {name}  {peer_addr} <-> {local_addr}"),
            ("", domain) => info!("MATCH {name}  {peer_addr} <-> {domain} <-> {local_addr}"),
            (geo, "") => info!("MATCH {name}  {peer_addr} [{geo}] <-> {local_addr}"),
            (geo, domain) => {
                info!("MATCH {name}  {peer_addr} [{geo}] <-> {domain} <-> {local_addr}")
            }
        }
    }
    Ok(())
}

fn parse_sni(buf: &[u8]) -> Result<String> {
    let (_, res) = parse_tls_plaintext(buf).map_err(|_| anyhow!("unexpected protocol"))?;
    match &res.msg[0] {
        Handshake(ClientHello(contents)) => {
            let ext = contents
                .ext
                .ok_or_else(|| anyhow!("unable to find tls extensions"))?;

            let (_, exts) =
                parse_tls_extensions(ext).map_err(|_| anyhow!("unable to parse tls extensions"))?;

            let v = exts
                .iter()
                .find_map(|i| match i {
                    TlsExtension::SNI(v) => Some(v),
                    _ => None,
                })
                .ok_or_else(|| anyhow!("unable to find tls extension SNI"))?;

            let domain = str::from_utf8(v[0].1).unwrap().to_string();
            Ok(domain)
        }
        _ => Err(anyhow!("unexpected handshake type")),
    }
}

async fn relay(inbound: &mut TcpStream, outbound: &mut TcpStream) -> io::Result<()> {
    inbound.set_nodelay(true)?;
    outbound.set_nodelay(true)?;
    let (mut ri, mut wi) = inbound.split();
    let (mut ro, mut wo) = outbound.split();

    let client_to_server = async {
        zero_copy(&mut ri, &mut wo).await?;
        wo.shutdown().await
    };

    let server_to_client = async {
        zero_copy(&mut ro, &mut wi).await?;
        wi.shutdown().await
    };

    try_join!(client_to_server, server_to_client)?;

    Ok(())
}

pub async fn zero_copy<X, Y, R, W>(mut r: R, mut w: W) -> io::Result<()>
where
    X: AsRawFd,
    Y: AsRawFd,
    R: AsyncRead + AsRef<X> + Unpin,
    W: AsyncWrite + AsRef<Y> + Unpin,
{
    // create pipe
    let pipe = Pipe::create()?;
    let (rpipe, wpipe) = (pipe.0, pipe.1);
    // get raw fd
    let rfd = r.as_ref().as_raw_fd();
    let wfd = w.as_ref().as_raw_fd();
    let mut n: usize = 0;
    let mut done = false;

    'LOOP: loop {
        // read until the socket buffer is empty
        // or the pipe is filled
        // clear readiness (EPOLLIN)
        r.read(&mut [0u8; 0]).await?;
        while n < PIPE_BUF_SIZE {
            match splice_n(rfd, wpipe, PIPE_BUF_SIZE - n) {
                x if x > 0 => n += x as usize,
                x if x == 0 => {
                    done = true;
                    break;
                }
                x if x < 0 && is_wouldblock() => break,
                _ => break 'LOOP,
            }
        }
        // write until the pipe is empty
        while n > 0 {
            // clear readiness (EPOLLOUT)
            w.write(&[0u8; 0]).await?;
            match splice_n(rpipe, wfd, n) {
                x if x > 0 => n -= x as usize,
                x if x < 0 && is_wouldblock() => {}
                _ => break 'LOOP,
            }
        }
        // complete
        if done {
            break;
        }
    }

    w.shutdown().await?;
    Ok(())
}

pub struct Pipe(i32, i32);

impl Pipe {
    pub fn create() -> io::Result<Self> {
        use libc::{c_int, O_NONBLOCK};
        let mut pipes = std::mem::MaybeUninit::<[c_int; 2]>::uninit();
        unsafe {
            if libc::pipe2(pipes.as_mut_ptr() as *mut c_int, O_NONBLOCK) < 0 {
                return Err(io::Error::new(io::ErrorKind::Other, "failed to call pipe"));
            }
            Ok(Pipe(pipes.assume_init()[0], pipes.assume_init()[1]))
        }
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.0);
            libc::close(self.1);
        }
    }
}

const PIPE_BUF_SIZE: usize = 0x10000;

pub fn is_wouldblock() -> bool {
    use libc::{EAGAIN, EWOULDBLOCK};
    let errno = unsafe { *libc::__errno_location() };
    errno == EWOULDBLOCK || errno == EAGAIN
}

fn splice_n(r: i32, w: i32, n: usize) -> isize {
    use libc::{loff_t, SPLICE_F_MOVE, SPLICE_F_NONBLOCK};
    unsafe {
        libc::splice(
            r,
            std::ptr::null_mut::<loff_t>(),
            w,
            std::ptr::null_mut::<loff_t>(),
            n,
            SPLICE_F_MOVE | SPLICE_F_NONBLOCK,
        )
    }
}
