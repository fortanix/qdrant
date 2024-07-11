use std::fs::File;
use std::path::Path;
use std::{io, result};

use reqwest::header::{HeaderMap, HeaderValue, InvalidHeaderValue};
use storage::content_manager::errors::StorageError;
#[cfg(feature = "rustls-mbedtls")]
use {rustls::crypto::CryptoProvider, std::io::BufReader, std::sync::Arc};

use super::auth::HTTP_HEADER_API_KEY;
use crate::settings::{Settings, TlsConfig};

#[derive(Clone)]
pub struct HttpClient {
    tls_config: Option<TlsConfig>,
    verify_https_client_certificate: bool,
}

impl HttpClient {
    pub fn from_settings(settings: &Settings) -> Result<Self> {
        let tls_config = if settings.service.enable_tls {
            let Some(tls_config) = settings.tls.clone() else {
                return Err(Error::TlsConfigUndefined);
            };

            Some(tls_config)
        } else {
            None
        };

        let verify_https_client_certificate = settings.service.verify_https_client_certificate;

        let http_client = Self {
            tls_config,
            verify_https_client_certificate,
        };

        Ok(http_client)
    }

    /// Create a new HTTP(S) client
    ///
    /// An API key can be optionally provided to be used in this HTTP client. It'll send the API
    /// key as `Api-key` header in every request.
    ///
    /// # Warning
    ///
    /// Setting an API key may leak when the client is used to send a request to a malicious
    /// server. This is potentially dangerous if a user has control over what URL is accessed.
    ///
    /// For this reason the API key is not set by default as provided in the configuration. It must
    /// be explicitly provided when creating the HTTP client.
    pub fn client(&self, api_key: Option<&str>) -> Result<reqwest::Client> {
        https_client(
            api_key,
            self.tls_config.as_ref(),
            self.verify_https_client_certificate,
        )
    }
}

fn https_client(
    api_key: Option<&str>,
    tls_config: Option<&TlsConfig>,
    verify_https_client_certificate: bool,
) -> Result<reqwest::Client> {
    let mut builder = create_rustls_client_builder(tls_config, verify_https_client_certificate)?;

    // Attach API key as sensitive header
    if let Some(api_key) = api_key {
        let mut headers = HeaderMap::new();
        let mut api_key_value = HeaderValue::from_str(api_key).map_err(Error::MalformedApiKey)?;
        api_key_value.set_sensitive(true);
        headers.insert(HTTP_HEADER_API_KEY, api_key_value);
        builder = builder.default_headers(headers);
    }

    let client = builder.build()?;

    Ok(client)
}

#[cfg(not(feature = "rustls-mbedtls"))]
fn create_rustls_client_builder(
    tls_config: Option<&TlsConfig>,
    verify_https_client_certificate: bool,
) -> Result<reqwest::ClientBuilder> {
    let mut builder = reqwest::Client::builder();

    // Configure TLS root certificate and validation
    if let Some(tls_config) = tls_config {
        builder = builder.add_root_certificate(https_client_ca_cert(tls_config.ca_cert.as_ref())?);

        if verify_https_client_certificate {
            builder = builder.identity(https_client_identity(
                tls_config.cert.as_ref(),
                tls_config.key.as_ref(),
            )?);
        }
    };

    Ok(builder)
}

#[cfg(not(feature = "rustls-mbedtls"))]
fn https_client_ca_cert(ca_cert: &Path) -> Result<reqwest::tls::Certificate> {
    let ca_cert_pem = std::fs::read(ca_cert)
        .map_err(|err| Error::failed_to_read(err, "CA certificate", ca_cert))?;

    let ca_cert = reqwest::Certificate::from_pem(&ca_cert_pem)?;

    Ok(ca_cert)
}

#[cfg(not(feature = "rustls-mbedtls"))]
fn https_client_identity(cert: &Path, key: &Path) -> Result<reqwest::tls::Identity> {
    let mut identity_pem =
        std::fs::read(cert).map_err(|err| Error::failed_to_read(err, "certificate", cert))?;

    let mut key_file = File::open(key).map_err(|err| Error::failed_to_read(err, "key", key))?;

    // Concatenate certificate and key into a single PEM bytes
    io::copy(&mut key_file, &mut identity_pem)
        .map_err(|err| Error::failed_to_read(err, "key", key))?;

    let identity = reqwest::Identity::from_pem(&identity_pem)?;

    Ok(identity)
}

#[cfg(feature = "rustls-mbedtls")]
pub fn get_mbedtls_crypto_provider() -> Arc<CryptoProvider> {
    static MBEDTLS_CRYPTO_PROVIDER: std::sync::OnceLock<Arc<CryptoProvider>> =
        std::sync::OnceLock::new();
    let crypto_provider = MBEDTLS_CRYPTO_PROVIDER
        .get_or_init(|| Arc::new(rustls_mbedcrypto_provider::mbedtls_crypto_provider()));
    crypto_provider.clone()
}

#[cfg(feature = "rustls-mbedtls")]
fn create_rustls_client_builder(
    tls_config: Option<&TlsConfig>,
    verify_https_client_certificate: bool,
) -> Result<reqwest::ClientBuilder> {
    let crypto_provider = get_mbedtls_crypto_provider();
    let rustls_client_cfg = rustls::ClientConfig::builder_with_provider(crypto_provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(Error::Rustls)?;

    // Configure TLS root certificate
    let mut root_certs: Vec<_> = rustls_native_certs::load_native_certs()
        .map_err(|err| Error::io(err, "could not load platform certs"))?;
    if let Some(tls_config) = tls_config {
        let mut certs = https_client_ca_cert(tls_config.ca_cert.as_ref())?;
        root_certs.append(&mut certs);
    }
    let client_cert_verifier = rustls_mbedpki_provider::MbedTlsServerCertVerifier::new(&root_certs)
        .map_err(rustls_mbedtls_provider_utils::error::mbedtls_err_into_rustls_err)
        .map_err(Error::Rustls)?;
    let rustls_client_cfg = rustls_client_cfg
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(client_cert_verifier));

    // Configure TLS client certificate validation
    let rustls_client_cfg = match (tls_config, verify_https_client_certificate) {
        (Some(tls_config), true) => {
            let (certs, key) =
                https_client_identity(tls_config.cert.as_ref(), tls_config.key.as_ref())?;
            rustls_client_cfg
                .with_client_auth_cert(certs, key)
                .map_err(Error::Rustls)?
        }
        _ => rustls_client_cfg.with_no_client_auth(),
    };
    Ok(reqwest::Client::builder().use_preconfigured_tls(rustls_client_cfg))
}

#[cfg(feature = "rustls-mbedtls")]
fn https_client_ca_cert(ca_cert: &Path) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>> {
    let file = File::open(ca_cert).map_err(|err| Error::io(err, "CA certificate"))?;
    let mut reader = BufReader::new(file);

    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| Error::io(err, "CA certificate"))
}

#[cfg(feature = "rustls-mbedtls")]
fn https_client_identity(
    cert: &Path,
    key: &Path,
) -> Result<(
    Vec<rustls_pki_types::CertificateDer<'static>>,
    rustls_pki_types::PrivateKeyDer<'static>,
)> {
    let cert_file =
        File::open(cert).map_err(|err| Error::failed_to_read(err, "certificate", cert))?;
    let mut cert_file_reader = BufReader::new(cert_file);
    let certs: Vec<rustls_pki_types::CertificateDer> = rustls_pemfile::certs(&mut cert_file_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|err| Error::io(err, "CA certificate"))?;

    let key_file = File::open(key).map_err(|err| Error::failed_to_read(err, "key", key))?;
    let mut key_file_reader = BufReader::new(key_file);
    let private_key = rustls_pemfile::private_key(&mut key_file_reader)
        .map_err(|err| Error::failed_to_read(err, "key", key))?
        .ok_or(Error::NoPrivateKey)?;

    Ok((certs, private_key))
}

pub type Result<T, E = Error> = result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("TLS config is not defined in the Qdrant config file")]
    TlsConfigUndefined,

    #[error("{1}: {0}")]
    Io(#[source] io::Error, String),

    #[error("failed to setup HTTPS client: {0}")]
    Reqwest(#[from] reqwest::Error),

    #[error("failed to setup HTTPS client: {0}")]
    Rustls(#[from] rustls::Error),

    #[error("failed to setup HTTPS client: no private key found")]
    NoPrivateKey,

    #[error("malformed API key")]
    MalformedApiKey(#[source] InvalidHeaderValue),
}

impl Error {
    pub fn io(source: io::Error, context: impl Into<String>) -> Self {
        Self::Io(source, context.into())
    }

    pub fn failed_to_read(source: io::Error, file: &str, path: &Path) -> Self {
        Self::io(
            source,
            format!("failed to read HTTPS client {file} file {}", path.display()),
        )
    }
}

impl From<Error> for StorageError {
    fn from(err: Error) -> Self {
        StorageError::service_error(format!("failed to initialize HTTP(S) client: {err}"))
    }
}

impl From<Error> for io::Error {
    fn from(err: Error) -> Self {
        io::Error::new(io::ErrorKind::Other, err)
    }
}
