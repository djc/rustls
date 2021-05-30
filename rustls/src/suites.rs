use crate::cipher::{self, Tls12AeadAlgorithm};
use crate::msgs::enums::ProtocolVersion;
use crate::msgs::enums::{CipherSuite, SignatureAlgorithm, SignatureScheme};
use crate::msgs::handshake::DecomposedSignatureScheme;
use crate::msgs::handshake::KeyExchangeAlgorithm;

use std::fmt;

/// Bulk symmetric encryption scheme used by a cipher suite.
#[allow(non_camel_case_types)]
#[derive(Debug, PartialEq)]
pub enum BulkAlgorithm {
    /// AES with 128-bit keys in Galois counter mode.
    Aes128Gcm,

    /// AES with 256-bit keys in Galois counter mode.
    Aes256Gcm,

    /// Chacha20 for confidentiality with poly1305 for authenticity.
    Chacha20Poly1305,
}

/// Common state for cipher suites (both for TLS 1.2 and TLS 1.3)
pub struct CipherSuiteCommon {
    /// The TLS enumeration naming this cipher suite.
    pub suite: CipherSuite,

    /// How to do bulk encryption.
    pub bulk: BulkAlgorithm,

    pub(crate) aead_algorithm: &'static ring::aead::Algorithm,
}

/// A cipher suite supported by rustls.
///
/// All possible instances of this type are provided by the library in
/// the `ALL_CIPHER_SUITES` array.
#[derive(Clone, Copy, PartialEq)]
pub enum SupportedCipherSuite {
    /// A TLS 1.2 cipher suite
    Tls12(&'static Tls12CipherSuite),
    /// A TLS 1.3 cipher suite
    Tls13(&'static Tls13CipherSuite),
}

pub struct Tls13CipherSuite {
    pub common: CipherSuiteCommon,
    pub(crate) hkdf_algorithm: ring::hkdf::Algorithm,
}

impl Tls13CipherSuite {
    /// Which hash function to use with this suite.
    pub fn get_hash(&self) -> &'static ring::digest::Algorithm {
        self.hkdf_algorithm
            .hmac_algorithm()
            .digest_algorithm()
    }

    /// Can a session using suite self resume from suite prev?
    pub fn can_resume_from(&self, prev: SupportedCipherSuite) -> Option<&'static Tls13CipherSuite> {
        match prev {
            SupportedCipherSuite::Tls13(inner) if inner.get_hash() == self.get_hash() => {
                Some(inner)
            }
            _ => None,
        }
    }

    const VERSION: ProtocolVersion = ProtocolVersion::TLSv1_3;
}

impl From<&'static Tls13CipherSuite> for SupportedCipherSuite {
    fn from(s: &'static Tls13CipherSuite) -> Self {
        SupportedCipherSuite::Tls13(s)
    }
}

impl PartialEq for Tls13CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

pub struct Tls12CipherSuite {
    pub common: CipherSuiteCommon,
    pub(crate) hmac_algorithm: ring::hmac::Algorithm,
    /// How to exchange/agree keys.
    pub kx: KeyExchangeAlgorithm,

    /// How to sign messages for authentication.
    pub sign: &'static [SignatureScheme],

    /// How long the fixed part of the 'IV' is.
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    pub fixed_iv_len: usize,

    /// This is a non-standard extension which extends the
    /// key block to provide an initial explicit nonce offset,
    /// in a deterministic and safe way.  GCM needs this,
    /// chacha20poly1305 works this way by design.
    pub explicit_nonce_len: usize,

    pub(crate) aead_alg: &'static dyn Tls12AeadAlgorithm,
}

impl Tls12CipherSuite {
    /// Resolve the set of supported `SignatureScheme`s from the
    /// offered `SupportedSignatureSchemes`.  If we return an empty
    /// set, the handshake terminates.
    pub fn resolve_sig_schemes(&self, offered: &[SignatureScheme]) -> Vec<SignatureScheme> {
        self.sign
            .iter()
            .filter(|pref| offered.contains(pref))
            .cloned()
            .collect()
    }

    /// Which hash function to use with this suite.
    pub fn get_hash(&self) -> &'static ring::digest::Algorithm {
        self.hmac_algorithm.digest_algorithm()
    }

    const VERSION: ProtocolVersion = ProtocolVersion::TLSv1_2;
}

impl From<&'static Tls12CipherSuite> for SupportedCipherSuite {
    fn from(s: &'static Tls12CipherSuite) -> Self {
        SupportedCipherSuite::Tls12(s)
    }
}

impl PartialEq for Tls12CipherSuite {
    fn eq(&self, other: &Self) -> bool {
        self.common.suite == other.common.suite
    }
}

impl fmt::Debug for SupportedCipherSuite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let common = self.common();
        f.debug_struct("SupportedCipherSuite")
            .field("suite", &common.suite)
            .field("bulk", &common.bulk)
            .finish()
    }
}

impl SupportedCipherSuite {
    /// Which hash function to use with this suite.
    pub fn get_hash(&self) -> &'static ring::digest::Algorithm {
        match self {
            SupportedCipherSuite::Tls12(inner) => inner.get_hash(),
            SupportedCipherSuite::Tls13(inner) => inner.get_hash(),
        }
    }

    /// The cipher suite's identifier
    pub fn suite(&self) -> CipherSuite {
        self.common().suite
    }

    pub(crate) fn common(&self) -> &CipherSuiteCommon {
        match self {
            SupportedCipherSuite::Tls12(inner) => &inner.common,
            SupportedCipherSuite::Tls13(inner) => &inner.common,
        }
    }

    pub(crate) fn tls13(&self) -> Option<&'static Tls13CipherSuite> {
        match self {
            SupportedCipherSuite::Tls12(_) => None,
            SupportedCipherSuite::Tls13(inner) => Some(inner),
        }
    }

    /// Return true if this suite is usable for TLS `version`.
    pub fn usable_for_version(&self, version: ProtocolVersion) -> bool {
        match self {
            SupportedCipherSuite::Tls12(_) => version == Tls12CipherSuite::VERSION,
            SupportedCipherSuite::Tls13(_) => version == Tls13CipherSuite::VERSION,
        }
    }

    /// Return true if this suite is usable for a key only offering `sigalg`
    /// signatures.  This resolves to true for all TLS1.3 suites.
    pub fn usable_for_sigalg(&self, sigalg: SignatureAlgorithm) -> bool {
        match self {
            SupportedCipherSuite::Tls13(_) => true, // no constraint expressed by ciphersuite (e.g., TLS1.3)
            &SupportedCipherSuite::Tls12(inner) => inner
                .sign
                .iter()
                .any(|scheme| scheme.sign() == sigalg),
        }
    }
}

static TLS12_ECDSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::ED25519,
    SignatureScheme::ECDSA_NISTP521_SHA512,
    SignatureScheme::ECDSA_NISTP384_SHA384,
    SignatureScheme::ECDSA_NISTP256_SHA256,
];

static TLS12_RSA_SCHEMES: &[SignatureScheme] = &[
    SignatureScheme::RSA_PSS_SHA512,
    SignatureScheme::RSA_PSS_SHA384,
    SignatureScheme::RSA_PSS_SHA256,
    SignatureScheme::RSA_PKCS1_SHA512,
    SignatureScheme::RSA_PKCS1_SHA384,
    SignatureScheme::RSA_PKCS1_SHA256,
];

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256.
pub static TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        bulk: BulkAlgorithm::Chacha20Poly1305,
        aead_algorithm: &ring::aead::CHACHA20_POLY1305,
    },
    hmac_algorithm: ring::hmac::HMAC_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    aead_alg: &cipher::ChaCha20Poly1305,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
pub static TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        bulk: BulkAlgorithm::Chacha20Poly1305,
        aead_algorithm: &ring::aead::CHACHA20_POLY1305,
    },
    hmac_algorithm: ring::hmac::HMAC_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    fixed_iv_len: 12,
    explicit_nonce_len: 0,
    aead_alg: &cipher::ChaCha20Poly1305,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        bulk: BulkAlgorithm::Aes128Gcm,
        aead_algorithm: &ring::aead::AES_128_GCM,
    },
    hmac_algorithm: ring::hmac::HMAC_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    aead_alg: &cipher::AesGcm,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        bulk: BulkAlgorithm::Aes256Gcm,
        aead_algorithm: &ring::aead::AES_256_GCM,
    },
    hmac_algorithm: ring::hmac::HMAC_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_RSA_SCHEMES,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    aead_alg: &cipher::AesGcm,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
pub static TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        bulk: BulkAlgorithm::Aes128Gcm,
        aead_algorithm: &ring::aead::AES_128_GCM,
    },
    hmac_algorithm: ring::hmac::HMAC_SHA256,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    aead_alg: &cipher::AesGcm,
};

/// The TLS1.2 ciphersuite TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
pub static TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: &Tls12CipherSuite = &Tls12CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        bulk: BulkAlgorithm::Aes256Gcm,
        aead_algorithm: &ring::aead::AES_256_GCM,
    },
    hmac_algorithm: ring::hmac::HMAC_SHA384,
    kx: KeyExchangeAlgorithm::ECDHE,
    sign: TLS12_ECDSA_SCHEMES,
    fixed_iv_len: 4,
    explicit_nonce_len: 8,
    aead_alg: &cipher::AesGcm,
};

/// The TLS1.3 ciphersuite TLS_CHACHA20_POLY1305_SHA256
pub static TLS13_CHACHA20_POLY1305_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        bulk: BulkAlgorithm::Chacha20Poly1305,
        aead_algorithm: &ring::aead::CHACHA20_POLY1305,
    },
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
};

/// The TLS1.3 ciphersuite TLS_AES_256_GCM_SHA384
pub static TLS13_AES_256_GCM_SHA384: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_256_GCM_SHA384,
        bulk: BulkAlgorithm::Aes256Gcm,
        aead_algorithm: &ring::aead::AES_256_GCM,
    },
    hkdf_algorithm: ring::hkdf::HKDF_SHA384,
};

/// The TLS1.3 ciphersuite TLS_AES_128_GCM_SHA256
pub static TLS13_AES_128_GCM_SHA256: &Tls13CipherSuite = &Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        bulk: BulkAlgorithm::Aes128Gcm,
        aead_algorithm: &ring::aead::AES_128_GCM,
    },
    hkdf_algorithm: ring::hkdf::HKDF_SHA256,
};

/// A list of all the cipher suites supported by rustls.
pub static ALL_CIPHER_SUITES: &[SupportedCipherSuite] = &[
    // TLS1.3 suites
    SupportedCipherSuite::Tls13(&TLS13_AES_256_GCM_SHA384),
    SupportedCipherSuite::Tls13(&TLS13_AES_128_GCM_SHA256),
    SupportedCipherSuite::Tls13(&TLS13_CHACHA20_POLY1305_SHA256),
    // TLS1.2 suites
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
    SupportedCipherSuite::Tls12(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256),
    SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
    SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
    SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256),
];

/// The cipher suite configuration that an application should use by default.
///
/// This will be `ALL_CIPHER_SUITES` sans any supported cipher suites that
/// shouldn't be enabled by most applications.
pub static DEFAULT_CIPHER_SUITES: &[SupportedCipherSuite] = ALL_CIPHER_SUITES;

// These both O(N^2)!
pub fn choose_ciphersuite_preferring_client(
    client_suites: &[CipherSuite],
    server_suites: &[SupportedCipherSuite],
) -> Option<SupportedCipherSuite> {
    for client_suite in client_suites {
        if let Some(selected) = server_suites
            .iter()
            .find(|x| *client_suite == x.suite())
        {
            return Some(*selected);
        }
    }

    None
}

pub fn choose_ciphersuite_preferring_server(
    client_suites: &[CipherSuite],
    server_suites: &[SupportedCipherSuite],
) -> Option<SupportedCipherSuite> {
    if let Some(selected) = server_suites
        .iter()
        .find(|x| client_suites.contains(&x.suite()))
    {
        return Some(*selected);
    }

    None
}

/// Return a list of the cipher suites in `all` with the suites
/// incompatible with `SignatureAlgorithm` `sigalg` removed.
pub fn reduce_given_sigalg(
    all: &[SupportedCipherSuite],
    sigalg: SignatureAlgorithm,
) -> Vec<SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_sigalg(sigalg))
        .copied()
        .collect()
}

/// Return a list of the cipher suites in `all` with the suites
/// incompatible with the chosen `version` removed.
pub fn reduce_given_version(
    all: &[SupportedCipherSuite],
    version: ProtocolVersion,
) -> Vec<SupportedCipherSuite> {
    all.iter()
        .filter(|&&suite| suite.usable_for_version(version))
        .copied()
        .collect()
}

/// Return true if `sigscheme` is usable by any of the given suites.
pub fn compatible_sigscheme_for_suites(
    sigscheme: SignatureScheme,
    common_suites: &[SupportedCipherSuite],
) -> bool {
    let sigalg = sigscheme.sign();
    common_suites
        .iter()
        .any(|&suite| suite.usable_for_sigalg(sigalg))
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::msgs::enums::CipherSuite;

    #[test]
    fn test_client_pref() {
        let client = vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        let server = vec![
            SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        ];
        let chosen = choose_ciphersuite_preferring_client(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(
            chosen.unwrap(),
            SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)
        );
    }

    #[test]
    fn test_server_pref() {
        let client = vec![
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ];
        let server = vec![
            SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
            SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
        ];
        let chosen = choose_ciphersuite_preferring_server(&client, &server);
        assert!(chosen.is_some());
        assert_eq!(
            chosen.unwrap(),
            SupportedCipherSuite::Tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384)
        );
    }

    #[test]
    fn test_pref_fails() {
        assert!(
            choose_ciphersuite_preferring_client(
                &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
                ALL_CIPHER_SUITES
            )
            .is_none()
        );
        assert!(
            choose_ciphersuite_preferring_server(
                &[CipherSuite::TLS_NULL_WITH_NULL_NULL],
                ALL_CIPHER_SUITES
            )
            .is_none()
        );
    }

    #[test]
    fn test_scs_is_debug() {
        println!("{:?}", ALL_CIPHER_SUITES);
    }

    #[test]
    fn test_usable_for_version() {
        fn ok_tls13(suite: &'static Tls13CipherSuite) {
            let scs = SupportedCipherSuite::from(suite);
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_0));
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(scs.usable_for_version(ProtocolVersion::TLSv1_3));
        }

        fn ok_tls12(suite: &'static Tls12CipherSuite) {
            let scs = SupportedCipherSuite::from(suite);
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_0));
            assert!(scs.usable_for_version(ProtocolVersion::TLSv1_2));
            assert!(!scs.usable_for_version(ProtocolVersion::TLSv1_3));
        }

        ok_tls13(&TLS13_CHACHA20_POLY1305_SHA256);
        ok_tls13(&TLS13_AES_256_GCM_SHA384);
        ok_tls13(&TLS13_AES_128_GCM_SHA256);

        ok_tls12(&TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256);
        ok_tls12(&TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256);
        ok_tls12(&TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384);
        ok_tls12(&TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        ok_tls12(&TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384);
    }

    #[test]
    fn test_can_resume_to() {
        assert!(
            TLS13_AES_128_GCM_SHA256
                .can_resume_from(TLS13_CHACHA20_POLY1305_SHA256.into())
                .is_some()
        );
        assert!(
            TLS13_AES_256_GCM_SHA384
                .can_resume_from(TLS13_CHACHA20_POLY1305_SHA256.into())
                .is_none()
        );
    }
}
