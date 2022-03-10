use anyhow::{anyhow, Result};
use dnsclientx::DNSClient;
use ipdb::Reader;
use moka::future::Cache;
use qqwry::QQWryData;
use regex::Regex;
use serde_derive::Deserialize;
use simplelog::{error, info, warn, *};
use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::str;
use std::sync::Arc;
use tls_parser::TlsMessage::Handshake;
use tls_parser::TlsMessageHandshake::ClientHello;
use tls_parser::{parse_tls_extensions, parse_tls_plaintext, TlsExtension};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::{select, spawn};

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
    static ref DNS:Arc<DNSClient> = {
        let p = |s: &str| s.parse().unwrap();
        let dns = DNSClient::new(vec![
            p("1.1.1.1:53"),
            p("8.8.8.8:53"),
            p("114.114.114.114:53"),
        ]);
        Arc::new(dns)
    };
    static ref QQWRY:Arc<QQWryData> = {
        let config = init_config();
        let wry = QQWryData::new(config.global.qqwry).unwrap();
        Arc::new(wry)
    };
    static ref IPDB_V6:Reader = {
        let config = init_config();
        Reader::open_file(config.global.ipdb_v6).unwrap()
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

        spawn(async move { copy_tcp(&mut inbound, &mut outbound).await });

        let name = &outbound_config.name;
        let site = DNS
            .query_ptr(peer_addr.ip())
            .await
            .map_or(String::from(""), |s| " ".to_string() + &s);

        let geo = match peer_addr.ip() {
            IpAddr::V4(v4) => QQWRY
                .query(v4)
                .map_or("".to_string(), |g| format!("{} {}", g.area, g.country)),
            IpAddr::V6(v6) => IPDB_V6
                .find(&v6.to_string(), "CN")
                .map_or("".to_string(), |v| format!("{} {} {}", v[0], v[1], v[2])),
        };

        match (geo.as_str(), domain.as_str()) {
            ("", "") => info!("MATCH {name}  {peer_addr} -> {local_addr}"),
            ("", domain) => info!("MATCH {name}  {peer_addr} -> {domain} -> {local_addr}"),
            (geo, "") => info!("MATCH {name}  {peer_addr}[{geo}] -> {local_addr}"),
            (geo, domain) => info!("MATCH {name}  {peer_addr}[{geo}] -> {domain} -> {local_addr}"),
        }

        debug!("{peer_addr} {site}");
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

async fn copy_tcp<A, B>(c: &mut A, s: &mut B)
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut buf1 = [0u8; 16384];
    let mut buf2 = [0u8; 16384];
    loop {
        select! {
            a = s.read(&mut buf1) => {
                let size = match a{
                    Ok(p) => p,
                    Err(_) => break,
                };

                if size == 0 {
                    break;
                }

                match c.write_all(&buf1[..size]).await{
                    Ok(_) => {},
                    Err(_) => break,
                };
            },
            b = c.read(&mut buf2) => {
                let size = match b{
                    Ok(p) => p,
                    Err(_) => break,
                };

                if size == 0 {
                    break;
                }

                match s.write_all(&buf2[..size]).await{
                    Ok(_) => {},
                    Err(_) => break,
                };
            }
        }
    }
}
