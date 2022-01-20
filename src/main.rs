use anyhow::anyhow;
use anyhow::Result;
use dnsclientx::DNSClient;
use moka::future::Cache;
use regex::Regex;
use serde_derive::Deserialize;
use simplelog::*;
use simplelog::{error, info, warn};
use std::net::IpAddr;
use std::net::SocketAddr;
use std::str;
use std::sync::Arc;
use std::{env, fs::File, io::Read};
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage::Handshake,
    TlsMessageHandshake::ClientHello,
};
use tokio::io::copy_bidirectional;
use tokio::net::lookup_host;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::spawn;

#[derive(Debug, Deserialize)]
struct Config {
    sni: Vec<Sni>,
}

#[derive(Debug, Deserialize)]
struct Sni {
    name: String,
    inbound: Vec<String>,
    outbound: String,
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
    async fn init_from_config(config: Config) -> Self {
        let mut outbounds = Vec::new();
        let mut rule_sets = Vec::new();
        for (i, sni) in config.sni.into_iter().enumerate() {
            let socketaddr = lookup_host(sni.outbound).await.unwrap().next().unwrap();
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

#[tokio::main(flavor = "current_thread")]
async fn main() -> ! {
    TermLogger::init(
        LevelFilter::Info,
        ConfigBuilder::new().set_time_to_local(true).build(),
        TerminalMode::Stdout,
        ColorChoice::Auto,
    )
    .unwrap();

    let arg = env::args().nth(1).unwrap_or_else(|| {
        warn!("need config file path,use default(./config.toml)");
        "config.toml".to_string()
    });
    let mut file = File::open(arg).unwrap();
    let mut toml_str = String::new();
    file.read_to_string(&mut toml_str).unwrap();
    let config: Config = toml::from_str(&toml_str).unwrap();

    let db = Db::init_from_config(config).await;
    let db = Arc::new(db);
    
    //string to ipaddr
    let p = |s:&str| {s.parse().unwrap()};
    let dns = DNSClient::new(vec![p("1.1.1.1:53"),p("8.8.8.8:53"),p("114.114.114.114:53")]);
    let dns = Arc::new(dns);

    let listener = TcpListener::bind("[::]:443").await.unwrap();

    loop {
        let db = db.clone();
        let dns = dns.clone();
        match listener.accept().await {
            Ok((inbound, addr)) => {
                spawn(async move {
                    match serve(db, dns, inbound).await {
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

async fn serve(db: Arc<Db>, dns: Arc<DNSClient>, mut inbound: TcpStream) -> Result<()> {
    let buf = &mut [0u8; 2048];
    inbound.peek(buf).await?;
    let domain = parse_sni(buf).unwrap_or_default();
    let result = db.cached_find(&domain).await;
    if let Some(outbound_config) = result {
        let mut outbound = TcpStream::connect(outbound_config.socketaddr).await?;
        let peer_addr = mapped_addr_to_ipv4_addr(inbound.peer_addr()?);
        let local_addr = mapped_addr_to_ipv4_addr(inbound.local_addr()?);

        spawn(async move { copy_bidirectional(&mut inbound, &mut outbound).await });

        let name = &outbound_config.name;
        let site = dns
            .query_ptr(peer_addr.ip())
            .await
            .map_or(String::from(""), |s| " ".to_string() + &s);
        info!("MATCH {name} {peer_addr}{site} -> {domain} -> {local_addr}");
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
