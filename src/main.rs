use anyhow::anyhow;
use anyhow::Result;
use regex::Regex;
use serde_derive::Deserialize;
use simplelog::*;
use simplelog::{error, info, warn};
use std::str;
use std::sync::Arc;
use std::vec;
use std::{env, fs::File, io::Read};
use tls_parser::{
    parse_tls_extensions, parse_tls_plaintext, TlsExtension, TlsMessage::Handshake,
    TlsMessageHandshake::ClientHello,
};
use tokio::io::copy_bidirectional;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::spawn;

#[derive(Debug, Deserialize)]
struct Config {
    sni: Vec<Sni>,
}

#[derive(Debug, Deserialize)]
struct Sni {
    default: Option<bool>,
    name: String,
    inbound: Option<Vec<String>>,
    outbound: String,
}

struct Db {
    list: Vec<(Vec<Regex>, String)>,
    default: Option<String>,
}

impl Db {
    fn init_from_config(config: Config) -> Self {
        let mut list = vec![];
        let mut default = None;
        for sni in config.sni {
            if sni.default == None {
                let mut v = vec![];
                for domain in sni.inbound.unwrap() {
                    v.push(Regex::new(&domain).unwrap());
                }
                list.push((v, sni.outbound));
            } else {
                default = Some(sni.outbound);
            }
        }
        Db { list, default }
    }

    fn find(&self, domain: &str) -> Option<&String> {
        for (list, outbound) in &self.list {
            for re in list {
                if re.is_match(domain) {
                    return Some(outbound);
                }
            }
        }
        if let Some(outbound) = &self.default {
            Some(outbound)
        } else {
            None
        }
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

    let db = Db::init_from_config(config);
    let db = Arc::new(db);
    let listener = TcpListener::bind("[::]:443").await.unwrap();

    loop {
        let db = db.clone();
        match listener.accept().await {
            Ok((inbound, addr)) => {
                spawn(async move {
                    match serve(db, inbound).await {
                        Ok(_) => (),
                        Err(e) => warn!("{} {}", addr, e),
                    }
                });
            }
            Err(e) => error!("{}", e),
        }
    }
}

async fn serve(db: Arc<Db>, mut inbound: TcpStream) -> Result<()> {
    let buf = &mut [0u8; 2048];
    inbound.peek(buf).await?;
    let domain = parse_sni(buf).unwrap_or_default();
    let result = db.find(&domain);
    if let Some(target) = result {
        info!("{} -> {} -> {}", inbound.peer_addr()?, domain, target);
        let mut outbound = TcpStream::connect(target).await?;
        debug!(
            "{:?}",
            copy_bidirectional(&mut inbound, &mut outbound).await
        );
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
