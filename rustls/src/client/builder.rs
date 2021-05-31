use crate::anchors;
use crate::client::handy;
use crate::client::{ClientConfig, ResolvesClientCert};
use crate::error::Error;
use crate::key;
use crate::keylog::NoKeyLog;
use crate::kx::SupportedKxGroup;
use crate::suites::{Tls12CipherSuite, Tls13CipherSuite};
use crate::verify;

use std::sync::Arc;

/// Building a [`ClientConfig`] in a linker-friendly way.
///
/// Linker-friendly: meaning unused cipher suites, protocol
/// versions, key exchange mechanisms, etc. can be discarded
/// by the linker as they'll be unreferenced.
///
/// Example:
///
/// ```no_run
/// # use rustls::ConfigBuilder;
/// # let root_certs = rustls::RootCertStore::empty();
/// # let trusted_ct_logs = &[];
/// # let certs = vec![];
/// # let private_key = rustls::PrivateKey(vec![]);
/// ConfigBuilder::with_safe_default_cipher_suites()
///     .with_safe_default_kx_groups()
///     .for_client()
///     .unwrap()
///     .with_root_certificates(root_certs, trusted_ct_logs)
///     .with_single_cert(certs, private_key)
///     .expect("bad certificate/key");
/// ```
///
/// This may be shortened to:
///
/// ```
/// # use rustls::ConfigBuilder;
/// # let root_certs = rustls::RootCertStore::empty();
/// # let trusted_ct_logs = &[];
/// ConfigBuilder::with_safe_defaults()
///     .for_client()
///     .unwrap()
///     .with_root_certificates(root_certs, trusted_ct_logs)
///     .with_no_client_auth();
/// ```
///
/// # Resulting [`ConfigConfig`] defaults
/// * [`ClientConfig::max_fragment_size`]: the default is `None`: TLS packets are not fragmented to a specific size.
/// * [`ClientConfig::session_storage`]: the default stores 256 sessions in memory.
/// * [`ClientConfig::alpn_protocols`]: the default is empty -- no ALPN protocol is negotiated.
/// * [`ClientConfig::key_log`]: key material is not logged.
pub struct ClientConfigBuilder {
    pub(crate) tls13_cipher_suites: Vec<&'static Tls13CipherSuite>,
    pub(crate) tls12_cipher_suites: Vec<&'static Tls12CipherSuite>,
    pub(crate) kx_groups: Vec<&'static SupportedKxGroup>,
}

impl ClientConfigBuilder {
    /// Choose how to verify client certificates.
    pub fn with_root_certificates(
        self,
        root_store: anchors::RootCertStore,
        ct_logs: &'static [&'static sct::Log],
    ) -> ClientConfigBuilderWithCertVerifier {
        let verifier = Arc::new(verify::WebPkiVerifier::new(root_store, ct_logs));

        ClientConfigBuilderWithCertVerifier {
            tls13_cipher_suites: self.tls13_cipher_suites,
            tls12_cipher_suites: self.tls12_cipher_suites,
            kx_groups: self.kx_groups,
            verifier,
        }
    }

    #[cfg(feature = "dangerous_configuration")]
    pub fn with_custom_certificate_verifier(
        self,
        verifier: Arc<dyn verify::ServerCertVerifier>,
    ) -> ClientConfigBuilderWithCertVerifier {
        ClientConfigBuilderWithCertVerifier {
            tls13_cipher_suites: self.tls13_cipher_suites,
            tls12_cipher_suites: self.tls12_cipher_suites,
            kx_groups: self.kx_groups,
            verifier,
        }
    }
}

/// A [`ClientConfigBuilder`] where we know the cipher suites, key exchange
/// groups, enabled versions, and server certificate auth policy.
pub struct ClientConfigBuilderWithCertVerifier {
    tls13_cipher_suites: Vec<&'static Tls13CipherSuite>,
    tls12_cipher_suites: Vec<&'static Tls12CipherSuite>,
    kx_groups: Vec<&'static SupportedKxGroup>,
    verifier: Arc<dyn verify::ServerCertVerifier>,
}

impl ClientConfigBuilderWithCertVerifier {
    /// Sets a single certificate chain and matching private key for use
    /// in client authentication.
    ///
    /// `cert_chain` is a vector of DER-encoded certificates.
    /// `key_der` is a DER-encoded RSA, ECDSA, or Ed25519 private key.
    ///
    /// This function fails if `key_der` is invalid.
    pub fn with_single_cert(
        self,
        cert_chain: Vec<key::Certificate>,
        key_der: key::PrivateKey,
    ) -> Result<ClientConfig, Error> {
        let resolver = handy::AlwaysResolvesClientCert::new(cert_chain, &key_der)?;
        Ok(self.with_client_cert_resolver(Arc::new(resolver)))
    }

    /// Do not support client auth.
    pub fn with_no_client_auth(self) -> ClientConfig {
        self.with_client_cert_resolver(Arc::new(handy::FailResolveClientCert {}))
    }

    /// Sets a custom [`ResolvesClientCert`].
    pub fn with_client_cert_resolver(
        self,
        client_auth_cert_resolver: Arc<dyn ResolvesClientCert>,
    ) -> ClientConfig {
        ClientConfig {
            tls13_cipher_suites: self.tls13_cipher_suites,
            tls12_cipher_suites: self.tls12_cipher_suites,
            kx_groups: self.kx_groups,
            alpn_protocols: Vec::new(),
            session_storage: handy::ClientSessionMemoryCache::new(256),
            max_fragment_size: None,
            client_auth_cert_resolver,
            enable_tickets: true,
            enable_sni: true,
            verifier: self.verifier,
            key_log: Arc::new(NoKeyLog {}),
            enable_early_data: false,
        }
    }
}
