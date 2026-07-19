use crate::types::TlsInfo;
use crate::Error;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use tokio_rustls::rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use tokio_rustls::rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio_rustls::TlsConnector;
use x509_parser::prelude::*;

/// Extract TLS certificate data from a target host and port.
/// This function accepts all server certificates.
#[allow(dead_code)]
pub async fn probe_tls(host: &str, port: u16) -> Result<Option<TlsInfo>, Error> {
    let addr = format!("{}:{}", host, port);

    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(NoopVerifier))
        .with_no_client_auth();

    let connector = TlsConnector::from(Arc::new(config));

    let stream = match TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    let server_name = match ServerName::try_from(host.to_string()) {
        Ok(n) => n,
        Err(_) => return Ok(None),
    };

    let tls_stream = match connector.connect(server_name, stream).await {
        Ok(s) => s,
        Err(_) => return Ok(None),
    };

    let (_stream, session) = tls_stream.into_inner();
    let certs = session.peer_certificates().unwrap_or_default();

    if certs.is_empty() {
        return Ok(None);
    }

    let der = certs[0].as_ref();
    let (_rem, x509) = X509Certificate::from_der(der).map_err(|e| Error::Tls(e.to_string()))?;

    let not_before = x509.validity().not_before.to_rfc2822().unwrap_or_default();
    let not_after = x509.validity().not_after.to_rfc2822().unwrap_or_default();

    let issuer = x509.issuer().to_string();
    let subject = x509.subject().to_string();

    let sans: Vec<String> = x509
        .subject_alternative_name()
        .ok()
        .flatten()
        .map(|san| {
            san.value
                .general_names
                .iter()
                .map(|n| n.to_string())
                .collect()
        })
        .unwrap_or_default();

    Ok(Some(TlsInfo {
        domain: host.to_string(),
        issuer: Some(issuer),
        subject: Some(subject),
        not_before: Some(not_before),
        not_after: Some(not_after),
        sans,
        self_signed: false,
    }))
}

#[allow(dead_code)]
#[derive(Debug)]
struct NoopVerifier;

impl ServerCertVerifier for NoopVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, tokio_rustls::rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, tokio_rustls::rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}
