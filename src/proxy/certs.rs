use moka::sync::Cache;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use time::Duration;

/// Errors that can occur during certificate operations
#[derive(Debug, Clone)]
pub enum CertError {
    Generation(String),
    Invalid(String),
}

impl std::fmt::Display for CertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertError::Generation(msg) => write!(f, "Certificate generation error: {}", msg),
            CertError::Invalid(msg) => write!(f, "Invalid certificate: {}", msg),
        }
    }
}

impl std::error::Error for CertError {}

impl From<rcgen::Error> for CertError {
    fn from(err: rcgen::Error) -> Self {
        CertError::Generation(err.to_string())
    }
}

impl From<&'static str> for CertError {
    fn from(err: &'static str) -> Self {
        CertError::Invalid(err.to_string())
    }
}

/// Certificate Authority for issuing MITM certificates
///
/// Generates a root CA certificate and issues server certificates on-demand
/// for specific hostnames. Certificates are cached (2-hour TTL) to avoid regeneration.
pub struct CertificateAuthority {
    /// Root CA certificate parameters (needed for Issuer creation)
    ca_params: CertificateParams,

    /// Root CA key pair
    ca_key_pair: KeyPair,

    /// Root CA certificate in DER format
    ca_cert_der: CertificateDer<'static>,

    /// Root CA private key in DER format
    ca_key_der: PrivateKeyDer<'static>,

    /// Cache of issued certificates (hostname -> Arc<(cert_der, key_der)>)
    /// 2-hour TTL matches certificate validity, max 100 entries
    /// Wrapped in Arc since PrivateKeyDer doesn't implement Clone
    cert_cache: Cache<String, std::sync::Arc<(CertificateDer<'static>, PrivateKeyDer<'static>)>>,
}

impl std::fmt::Debug for CertificateAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CertificateAuthority")
            .field("ca_params", &"<CertificateParams>")
            .field("ca_key_pair", &"<KeyPair>")
            .field("ca_cert_der", &format!("{} bytes", self.ca_cert_der.len()))
            .field(
                "ca_key_der",
                &format!("{} bytes", self.ca_key_der.secret_der().len()),
            )
            .field(
                "cert_cache",
                &format!("{} entries", self.cert_cache.entry_count()),
            )
            .finish()
    }
}

impl CertificateAuthority {
    /// Generate a new root CA certificate
    ///
    /// Following hermit's pattern:
    /// - 6 hour validity (1 hour before, 5 hours after)
    /// - Unconstrained CA capabilities
    /// - Can sign other certificates
    pub fn generate() -> Result<Self, CertError> {
        let mut params = CertificateParams::default();

        // CA identity
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, "SBC International Root CA");
        dn.push(DnType::OrganizationName, "SBC International");
        params.distinguished_name = dn;

        // CA capabilities - can sign other certificates
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![
            KeyUsagePurpose::KeyCertSign,
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::CrlSign,
        ];

        // 6 hour validity window (hermit pattern)
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - Duration::hours(1);
        params.not_after = now + Duration::hours(5);

        // Generate the CA certificate
        let key_pair = KeyPair::generate()?;
        let ca_cert = params.self_signed(&key_pair)?;

        // Convert to DER format for rustls
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());
        let ca_key_der = PrivateKeyDer::try_from(key_pair.serialize_der())?;

        Ok(Self {
            ca_params: params,
            ca_key_pair: key_pair,
            ca_cert_der,
            ca_key_der,
            cert_cache: Cache::builder()
                .time_to_live(std::time::Duration::from_secs(2 * 3600)) // 2 hours
                .max_capacity(100)
                .build(),
        })
    }

    /// Issue a certificate for a specific hostname
    ///
    /// Certificates are cached, so repeated calls for the same hostname
    /// return the same certificate. Server certificates have 2 hour validity.
    #[tracing::instrument(level = "debug", skip(self), fields(cache_hit))]
    pub fn issue_for_host(
        &self,
        hostname: &str,
    ) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), CertError> {
        // Check cache first
        if let Some(cached) = self.cert_cache.get(hostname) {
            let _ = tracing::Span::current().record("cache_hit", true);
            let (cert, key) = cached.as_ref();
            return Ok((cert.clone(), key.clone_key()));
        }

        let _ = tracing::Span::current().record("cache_hit", false);

        // Generate new certificate
        let mut params = CertificateParams::new(vec![hostname.to_string()])?;

        // Set the Common Name (CN) to match the hostname
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, hostname);
        params.distinguished_name = dn;

        // Server authentication certificate
        params.extended_key_usages = vec![
            rcgen::ExtendedKeyUsagePurpose::ServerAuth,
            rcgen::ExtendedKeyUsagePurpose::ClientAuth,
        ];
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];

        // 2 hour validity (hermit pattern)
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;
        params.not_after = now + Duration::hours(2);

        // Generate and sign with CA
        let key_pair = KeyPair::generate()?;
        let issuer = Issuer::from_params(&self.ca_params, &self.ca_key_pair);
        let cert = params.signed_by(&key_pair, &issuer)?;

        let cert_der = CertificateDer::from(cert.der().to_vec());
        let key_der = PrivateKeyDer::try_from(key_pair.serialize_der())?;

        // Cache and return
        let cached = std::sync::Arc::new((cert_der.clone(), key_der.clone_key()));
        self.cert_cache.insert(hostname.to_string(), cached);

        Ok((cert_der, key_der))
    }

    /// Get the CA certificate in PEM format
    ///
    /// This is used for injection into job sandboxes so they trust
    /// certificates issued by this CA.
    pub fn ca_cert_pem(&self) -> Result<String, CertError> {
        // Generate the CA certificate from params for PEM export
        let ca_cert = self.ca_params.self_signed(&self.ca_key_pair)?;
        Ok(ca_cert.pem())
    }

    /// Get the CA certificate in DER format (for rustls)
    pub fn ca_cert_der(&self) -> &CertificateDer<'static> {
        &self.ca_cert_der
    }

    /// Get the CA private key in DER format (for rustls)
    pub fn ca_key_der(&self) -> &PrivateKeyDer<'static> {
        &self.ca_key_der
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ca_generation() {
        let ca = CertificateAuthority::generate().expect("Failed to generate CA");

        // CA cert PEM should be valid
        let pem = ca.ca_cert_pem().expect("Failed to get CA PEM");
        assert!(pem.contains("BEGIN CERTIFICATE"));
        assert!(pem.contains("END CERTIFICATE"));
        assert!(pem.len() > 100);
    }

    #[test]
    fn test_issue_server_cert() {
        let ca = CertificateAuthority::generate().expect("Failed to generate CA");

        // Issue certificate for api.anthropic.com
        let (cert_der, key_der) = ca
            .issue_for_host("api.anthropic.com")
            .expect("Failed to issue certificate");

        // Certificate should be non-empty
        assert!(!cert_der.is_empty());
        assert!(!key_der.secret_der().is_empty());
    }

    #[test]
    fn test_cert_caching() {
        let ca = CertificateAuthority::generate().expect("Failed to generate CA");

        // Issue certificate twice for same hostname
        let (cert1, key1) = ca
            .issue_for_host("example.com")
            .expect("Failed to issue first certificate");
        let (cert2, key2) = ca
            .issue_for_host("example.com")
            .expect("Failed to issue second certificate");

        // Should be the same certificate (pointer equality for Arc)
        assert_eq!(cert1.as_ref(), cert2.as_ref());
        assert_eq!(key1.secret_der(), key2.secret_der());
    }

    #[test]
    fn test_multiple_hostnames() {
        let ca = CertificateAuthority::generate().expect("Failed to generate CA");

        // Issue certificates for different hostnames
        let (cert1, _) = ca
            .issue_for_host("example.com")
            .expect("Failed to issue for example.com");
        let (cert2, _) = ca
            .issue_for_host("api.anthropic.com")
            .expect("Failed to issue for api.anthropic.com");

        // Should be different certificates
        assert_ne!(cert1.as_ref(), cert2.as_ref());
    }
}
