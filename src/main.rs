use clap::Parser;
use regex::Regex;
use rustls::ClientConfig;
use rustls::client::ServerName;
use std::process::exit;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::{spawn, time};
use tokio_rustls::{TlsConnector, client::TlsStream};
use webpki_roots::TLS_SERVER_ROOTS;
use color_print::{ceprintln, cprintln};

mod payloads;
mod response;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    /// Target URL with Endpoint
    #[arg(short, long)]
    url: String,
    /// Specify a virtual host
    #[arg(short, long)]
    vhost: Option<String>,
    /// Number of attack iterations per payload
    #[arg(short, long, default_value_t = 10)]
    repeat: usize,
    /// HTTP method to use (e.g GET, POST)
    #[arg(short, long, default_value_t = String::from("POST"))]
    method: String,
    /// Exit scan on first finding
    #[arg(short = 'x', long, default_value_t = false)]
    exit_early: bool,
    /// Number of times to greet
    #[arg(short, long, default_value_t = 5)]
    time_out: u64,
}
#[derive(Debug, Clone)]
struct ServerConfiguratoin {
    ssl_flag: bool,
    port: u16,
    host: String,
    path: String,
}

impl ServerConfiguratoin {
    fn from(url: &String) -> Self {
        let re = Regex::new(r"^(https?)://([^:/]+)(?::(\d+))?(/.*)?$").unwrap();
        if let Some(captures) = re.captures(url) {
            let ssl_flag = &captures[1] == "https";
            let host = captures[2].to_string();
            let port = captures
                .get(3)
                .map(|m| m.as_str().parse::<u16>().unwrap())
                .unwrap_or_else(|| if ssl_flag { 443 } else { 80 });
            let path = captures
                .get(4)
                .map_or(String::from("/"), |m| m.as_str().to_string());
            Self {
                ssl_flag,
                port,
                host,
                path,
            }
        } else {
            panic!("Invalid URL format: {}", url);
        }
    }
    async fn tcp_connect(&self) -> Result<TcpStream, String> {
        let addr = format!("{}:{}", self.host, self.port);
        match TcpStream::connect(addr).await {
            Ok(connection) => {
                return Ok(connection);
            }
            Err(e) => {
                return Err(format!("Can not connect to {}: {}", self.host, e));
            }
        }
    }
    async fn ssl_connect(&self) -> Result<TlsStream<TcpStream>, String> {
        match self.tcp_connect().await {
            Ok(tcp_connection) => {
                let mut root_cert_store = rustls::RootCertStore::empty();
                root_cert_store.add_server_trust_anchors(TLS_SERVER_ROOTS.0.iter().map(|ta| {
                    rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
                        ta.subject,
                        ta.spki,
                        ta.name_constraints,
                    )
                }));

                let config = ClientConfig::builder()
                    .with_safe_defaults()
                    .with_root_certificates(root_cert_store)
                    .with_no_client_auth();
                let connector = TlsConnector::from(Arc::new(config));
                let domain = ServerName::try_from(&*self.host.as_str()).unwrap();
                match connector.connect(domain, tcp_connection).await {
                    Ok(ssl_stream) => Ok(ssl_stream),
                    Err(e) => Err(format!("TLS handshake failed: {}", e)),
                }
            }
            Err(e) => return Err(e),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let server_config = Arc::new(ServerConfiguratoin::from(&args.url));
    let method = args.method.to_uppercase();
    println!("URL          : {}", &args.url);
    println!("Method       : {}", &method);
    println!("Endpoint     : {}", &server_config.path);
    println!("Timeout      : {}", &args.time_out);
    println!("Repeat       : {}", &args.repeat);
    println!("--------------------------------------------------");
    let time_out = Arc::new(args.time_out);
    let exit_first_finding = Arc::new(args.exit_early);
    let mut handles = Vec::new();
    if server_config.ssl_flag {
        for _ in 0..args.repeat {
            let mutations = payloads::Mutation::new_default_mutation(
                &method,
                &args.vhost.clone().unwrap_or(server_config.host.clone()),
                &server_config.path,
            );
            for mutation in mutations {
                let server_configuration = Arc::clone(&server_config);
                let response_time_out = Arc::clone(&time_out);
                let exit_early = Arc::clone(&exit_first_finding);
                let request = mutation.raw_format();
                let handel = spawn(async move {
                    match server_configuration.ssl_connect().await {
                        Ok(mut ssl_stream) => {
                            let _ = ssl_stream.write_all(request.as_bytes()).await;
                            let mut response_bytes: Vec<u8> = Vec::new();
                            match time::timeout(
                                std::time::Duration::from_secs(*response_time_out),
                                ssl_stream.read_to_end(&mut response_bytes),
                            )
                            .await
                            {
                                Ok(Ok(_)) => {
                                    let parse_response = response::Response::from(response_bytes);
                                    let (is_smuggling,info) = parse_response.analyze_smuggling();
                                    if is_smuggling {
                                        cprintln!("<green>Find Smuggling({}).</green>", mutation.name);
                                        for i in info {
                                            cprintln!("     [{}]",i);
                                        }
                                        if *exit_early {
                                            exit(0);
                                        }
                                    }   
                                }
                                Ok(Err(e)) => {
                                    ceprintln!("<red>read error: {}</red>", e);
                                }
                                Err(_) => {
                                    cprintln!("<yellow>Timeout hit. Possible smuggling behavior. => {} </yellow>",mutation.name);
                                }
                            }
                        }
                        Err(e) => {
                            ceprintln!("{}", e);
                        }
                    }
                });
                handles.push(handel);
            }
        }
        for handle in handles {
            let _ = handle.await;
        }
    } else {

        for _ in 0..args.repeat {
            let mutations = payloads::Mutation::new_default_mutation(
                &method,
                &args.vhost.clone().unwrap_or(server_config.host.clone()),
                &server_config.path,
            );
            for mutation in mutations {
                let server_configuration = Arc::clone(&server_config);
                let response_time_out = Arc::clone(&time_out);
                let exit_early = Arc::clone(&exit_first_finding);
                let request = mutation.raw_format();
                let handel = spawn(async move {
                    match server_configuration.tcp_connect().await {
                        Ok(mut ssl_stream) => {
                            let _ = ssl_stream.write_all(request.as_bytes()).await;
                            let mut response_bytes: Vec<u8> = Vec::new();
                            match time::timeout(
                                std::time::Duration::from_secs(*response_time_out),
                                ssl_stream.read_to_end(&mut response_bytes),
                            )
                            .await
                            {
                                Ok(Ok(_)) => {
                                    let parse_response = response::Response::from(response_bytes);
                                    let (is_smuggling,info) = parse_response.analyze_smuggling();
                                    if is_smuggling {
                                        cprintln!("<green>Find Smuggling({}).</green>", mutation.name);
                                        for i in info {
                                            cprintln!("     [{}]",i);
                                        }
                                        if *exit_early {
                                            exit(0);
                                        }
                                    }
                                   
                                }
                                Ok(Err(e)) => {
                                    ceprintln!("<red>read error: {}</red>", e);
                                }
                                Err(_) => {
                                    cprintln!("<yellow>Timeout hit. Possible smuggling behavior. => {} </yellow>",mutation.name);
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("{}", e);
                        }
                    }
                });
                handles.push(handel);
            }
        }
        for handle in handles {
            let _ = handle.await;
        }
    }
    Ok(())
}
