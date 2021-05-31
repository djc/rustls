use crate::msgs::enums::ProtocolVersion;

/// A TLS protocl version supported by rustls.
///
/// All possible instances of this class are provided by the library in
/// the [`ALL_VERSIONS`] array, as well as individually as [`TLS12`]
/// and [`TLS13`].
#[derive(Debug, PartialEq)]
pub struct SupportedProtocolVersion {
    /// The TLS enumeration naming this version.
    pub version: ProtocolVersion,
    is_private: (),
}

/// TLS1.2
pub const TLS12: SupportedProtocolVersion = SupportedProtocolVersion {
    version: ProtocolVersion::TLSv1_2,
    is_private: (),
};

/// TLS1.3
pub const TLS13: SupportedProtocolVersion = SupportedProtocolVersion {
    version: ProtocolVersion::TLSv1_3,
    is_private: (),
};

/// A list of all the protocol versions supported by rustls.
pub const ALL_VERSIONS: &[&SupportedProtocolVersion] = &[&TLS13, &TLS12];

/// The version configuration that an application should use by default.
///
/// This will be [`ALL_VERSIONS`] for now, but gives space in the future
/// to remove a version from here and require users to opt-in to older
/// versions.
pub const DEFAULT_VERSIONS: &[&SupportedProtocolVersion] = ALL_VERSIONS;
