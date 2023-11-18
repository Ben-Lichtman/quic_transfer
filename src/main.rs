use anyhow::{anyhow, Result};
use clap::Parser;
use futures_util::StreamExt;
use normalize_path::NormalizePath;
use quinn::{ClientConfig, Connection, Endpoint, EndpointConfig, ServerConfig, TokioRuntime};
use rcgen::generate_simple_self_signed;
use rustls::{
	client::{ClientConfig as ClientTlsConfig, ServerCertVerified, ServerCertVerifier},
	server::ServerConfig as ServerTlsConfig,
	Certificate, OwnedTrustAnchor, PrivateKey, RootCertStore,
};
use serde::{Deserialize, Serialize};
use std::{
	net::{SocketAddr, UdpSocket},
	path::{Path, PathBuf},
	sync::Arc,
};
use tokio::{io::AsyncWriteExt, spawn};
use walkdir::WalkDir;

const CONCURRENCY: usize = 100;
const MAX_FILE_SIZE: usize = u32::MAX as _;

#[derive(Serialize, Deserialize)]
enum Message<'a> {
	Directory { path: PathBuf },
	FileContents { path: PathBuf, contents: &'a [u8] },
}

/// Ignores server certificates
/// This will make your connection vulnerable to MITM attacks
struct FakeCertVerifier;

impl ServerCertVerifier for FakeCertVerifier {
	fn verify_server_cert(
		&self,
		_: &Certificate,
		_: &[Certificate],
		_: &rustls::ServerName,
		_: &mut dyn Iterator<Item = &[u8]>,
		_: &[u8],
		_: std::time::SystemTime,
	) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
		Ok(ServerCertVerified::assertion())
	}
}

#[derive(Parser)]
enum Args {
	/// Generate certificate and key
	Generate {
		/// Location to put the server cert
		#[arg(short, long, default_value = "cert.der")]
		cert: PathBuf,

		/// Where to put the secret key
		#[arg(short, long, default_value = "sk.der")]
		secret_key: PathBuf,
	},

	/// Receive files as a server
	RecvServer {
		/// Bind address
		#[arg(short, long)]
		bind: SocketAddr,

		/// Path to receive files to
		#[arg(short, long)]
		path: PathBuf,

		/// Location to find the server cert
		#[arg(short, long, default_value = "cert.der")]
		cert: PathBuf,

		/// Where to find the secret key
		#[arg(short, long, default_value = "sk.der")]
		secret_key: PathBuf,
	},

	/// Send files as a server
	SendServer {
		/// Bind address
		#[arg(short, long)]
		bind: SocketAddr,

		/// Path to send files from
		#[arg(short, long)]
		path: PathBuf,

		/// Location to find the server cert
		#[arg(short, long, default_value = "cert.der")]
		cert: PathBuf,

		/// Where to find the secret key
		#[arg(short, long, default_value = "sk.der")]
		secret_key: PathBuf,
	},

	/// Receive files as a client
	RecvClient {
		/// Bind address
		#[arg(short, long, default_value = "0.0.0.0:0")]
		bind: SocketAddr,

		/// Remote address
		#[arg(short, long)]
		remote: SocketAddr,

		/// Path to receive files to
		#[arg(short, long)]
		path: PathBuf,

		/// Location to find the server cert
		#[arg(short, long)]
		cert: Option<PathBuf>,

		/// DANGEROUS!
		/// Do not verify server cert
		#[arg(long)]
		ignore_server_cert: bool,
	},

	/// Send files as a client
	SendClient {
		/// Bind address
		#[arg(short, long, default_value = "0.0.0.0:0")]
		bind: SocketAddr,

		/// Remote address
		#[arg(short, long)]
		remote: SocketAddr,

		/// Path to send files from
		#[arg(short, long)]
		path: PathBuf,

		/// Location to find the server cert
		#[arg(short, long)]
		cert: Option<PathBuf>,

		/// DANGEROUS!
		/// Do not verify server cert
		#[arg(long)]
		ignore_server_cert: bool,
	},
}

#[tokio::main]
async fn main() -> Result<()> {
	let args = Args::parse();
	match args {
		Args::Generate { cert, secret_key } => generate(&cert, &secret_key),
		Args::RecvServer {
			bind,
			path,
			cert,
			secret_key,
		} => {
			let server = setup_server(bind, &cert, &secret_key)?;
			let conn = accept_conn(&server).await?;
			recv(conn, &path).await?;
			server.wait_idle().await;
		}
		Args::SendServer {
			bind,
			path,
			cert,
			secret_key,
		} => {
			let server = setup_server(bind, &cert, &secret_key)?;
			let conn = accept_conn(&server).await?;
			send(conn, &path).await?;
			server.wait_idle().await;
		}
		Args::RecvClient {
			bind,
			remote,
			path,
			cert,
			ignore_server_cert,
		} => {
			let client = setup_client(bind, cert.as_deref(), ignore_server_cert)?;
			let conn = initiate_conn(&client, remote).await?;
			recv(conn, &path).await?;
			client.wait_idle().await;
		}
		Args::SendClient {
			bind,
			remote,
			path,
			cert,
			ignore_server_cert,
		} => {
			let client = setup_client(bind, cert.as_deref(), ignore_server_cert)?;
			let conn = initiate_conn(&client, remote).await?;
			send(conn, &path).await?;
			client.wait_idle().await;
		}
	}

	Ok(())
}

pub fn generate(cert_path: &Path, secret_key: &Path) {
	let cert = generate_simple_self_signed(vec![String::from("selfsign")]).unwrap();

	std::fs::write(cert_path, cert.serialize_der().unwrap()).unwrap();
	std::fs::write(secret_key, cert.serialize_private_key_der()).unwrap();
}

pub fn setup_server(bind: SocketAddr, cert: &Path, secret_key: &Path) -> Result<Endpoint> {
	let socket = UdpSocket::bind(bind)?;

	let cert_der = std::fs::read(cert)?;
	let sk_der = std::fs::read(secret_key)?;

	let crypto_config = ServerTlsConfig::builder()
		.with_safe_defaults()
		.with_no_client_auth()
		.with_single_cert(vec![Certificate(cert_der)], PrivateKey(sk_der))?;
	let server_config = ServerConfig::with_crypto(Arc::new(crypto_config));
	let config = EndpointConfig::default();
	let endpoint = Endpoint::new(config, Some(server_config), socket, Arc::new(TokioRuntime))?;

	Ok(endpoint)
}

pub fn setup_client(
	bind: SocketAddr,
	cert: Option<&Path>,
	ignore_server_cert: bool,
) -> Result<Endpoint> {
	let socket = UdpSocket::bind(bind)?;

	let config = EndpointConfig::default();
	let mut endpoint = Endpoint::new(config, None, socket, Arc::new(TokioRuntime)).unwrap();
	let mut root_certs = RootCertStore::empty();
	root_certs.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
		OwnedTrustAnchor::from_subject_spki_name_constraints(
			ta.subject,
			ta.spki,
			ta.name_constraints,
		)
	}));
	if let Some(cert) = cert {
		let server_cert = std::fs::read(cert)?;
		root_certs.add(&Certificate(server_cert)).unwrap();
	}
	let mut client_config = ClientTlsConfig::builder()
		.with_safe_defaults()
		.with_root_certificates(Arc::new(root_certs))
		.with_no_client_auth();
	if ignore_server_cert {
		client_config
			.dangerous()
			.set_certificate_verifier(Arc::new(FakeCertVerifier));
	}
	endpoint.set_default_client_config(ClientConfig::new(Arc::new(client_config)));
	Ok(endpoint)
}

pub async fn accept_conn(endpoint: &Endpoint) -> Result<Connection> {
	if let Some(conn) = endpoint.accept().await {
		let conn = conn.await?;
		return Ok(conn);
	}
	Err(anyhow!("Could not establish a connection"))
}

pub async fn initiate_conn(endpoint: &Endpoint, remote: SocketAddr) -> Result<Connection> {
	let conn = endpoint.connect(remote, "selfsign")?;
	let conn = conn.await?;
	Ok(conn)
}

pub async fn send(conn: Connection, base_path: &Path) -> Result<()> {
	let walkdir = WalkDir::new(base_path);

	futures_util::stream::iter(walkdir)
		.for_each_concurrent(Some(CONCURRENCY), |item| async {
			let mut send = conn.open_uni().await.unwrap();
			if let Ok(direntry) = item {
				let file_type = direntry.file_type();
				if file_type.is_file() {
					let path = direntry.path();
					let contents = tokio::fs::read(&path).await.unwrap();
					let path = path.strip_prefix(base_path).unwrap().to_owned();
					let message = Message::FileContents {
						path,
						contents: &contents,
					};
					let data = postcard::to_allocvec(&message).unwrap();
					send.write_all(&data).await.unwrap();
				}
				else if file_type.is_dir() {
					let path = direntry.path();
					let path = path.strip_prefix(base_path).unwrap().to_owned();
					let message = Message::Directory { path };
					let data = postcard::to_allocvec(&message).unwrap();
					send.write_all(&data).await.unwrap();
				}
			}
			send.finish().await.unwrap();
		})
		.await;

	Ok(())
}

pub async fn recv(conn: Connection, base_path: &Path) -> Result<()> {
	while let Ok(mut recv) = conn.accept_uni().await {
		let base_path = base_path.to_owned();
		spawn(async move {
			if let Ok(message) = recv.read_to_end(MAX_FILE_SIZE).await {
				if let Ok(decoded) = postcard::from_bytes::<Message>(&message) {
					match decoded {
						Message::Directory { path } => {
							let rebased = base_path.join(path).normalize();
							assert!(rebased.starts_with(base_path));
							tokio::fs::create_dir_all(rebased).await.unwrap()
						}
						Message::FileContents { path, contents } => {
							tokio::io::stdout()
								.write_all(format!("File: {}\n", path.display()).as_bytes())
								.await
								.unwrap();
							let rebased = base_path.join(path).normalize();
							assert!(rebased.starts_with(base_path));
							tokio::fs::write(rebased, contents).await.unwrap()
						}
					}
				}
			}
		});
	}

	Ok(())
}
