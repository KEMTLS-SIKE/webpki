// Copyright 2015 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! webpki: Web PKI X.509 Certificate Validation.
//!
//! <code>git clone https://github.com/briansmith/webpki</code>
//!
//! See `EndEntityCert`'s documentation for a description of the certificate
//! processing steps necessary for a TLS connection.

#![doc(html_root_url="https://briansmith.org/rustdoc/")]

#![no_std]

#![allow(
    missing_debug_implementations,
)]

// `#[derive(...)]` uses `#[allow(unused_qualifications)]` internally.
#![deny(
    unused_qualifications,
)]

#![forbid(
    anonymous_parameters,
    box_pointers,
    missing_copy_implementations,
    missing_docs,
    trivial_casts,
    trivial_numeric_casts,
    unsafe_code,
    unstable_features,
    unused_extern_crates,
    unused_import_braces,
    unused_results,
    variant_size_differences,
    warnings,
)]

#[cfg(any(test, feature = "trust_anchor_util"))]
#[macro_use(format)]
extern crate std;

extern crate ring;

#[cfg(test)]
extern crate base64;

extern crate untrusted;

#[macro_use]
mod der;

mod cert;
mod name;
mod signed_data;
mod calendar;
mod time;
mod error;

#[cfg(feature = "trust_anchor_util")]
pub mod trust_anchor_util;

mod verify_cert;

pub use error::Error;
pub use name::{DNSNameRef, InvalidDNSNameError};

#[cfg(feature = "std")]
pub use name::DNSName;


pub use signed_data::{
    SignatureAlgorithm,
    ECDSA_P256_SHA256,
    ECDSA_P256_SHA384,
    ECDSA_P384_SHA256,
    ECDSA_P384_SHA384,
    RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384,
    RSA_PKCS1_2048_8192_SHA512,
    RSA_PKCS1_3072_8192_SHA384,
    RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    ED25519,

    DILITHIUM2,
    DILITHIUM3,
    DILITHIUM4,
    FALCON512,
    FALCON1024,
    MQDSS3148,
    MQDSS3164,
    RAINBOW_IA_CLASSIC,
    RAINBOW_IA_CYCLIC,
    RAINBOW_IA_CYCLIC_COMPRESSED,
    RAINBOW_II_ICCLASSIC,
    RAINBOW_II_IC_CYCLIC,
    RAINBOW_II_IC_CYCLIC_COMPRESSED,
    RAINBOW_VC_CLASSIC,
    RAINBOW_VC_CYCLIC,
    RAINBOW_VC_CYCLIC_COMPRESSED,
    SPHINCS_HARAKA128F_ROBUST,
    SPHINCS_HARAKA128F_SIMPLE,
    SPHINCS_HARAKA128S_ROBUST,
    SPHINCS_HARAKA128S_SIMPLE,
    SPHINCS_HARAKA192F_ROBUST,
    SPHINCS_HARAKA192F_SIMPLE,
    SPHINCS_HARAKA192S_ROBUST,
    SPHINCS_HARAKA192S_SIMPLE,
    SPHINCS_HARAKA256F_ROBUST,
    SPHINCS_HARAKA256F_SIMPLE,
    SPHINCS_HARAKA256S_ROBUST,
    SPHINCS_HARAKA256S_SIMPLE,
    SPHINCS_SHA256128F_ROBUST,
    SPHINCS_SHA256128F_SIMPLE,
    SPHINCS_SHA256128S_ROBUST,
    SPHINCS_SHA256128S_SIMPLE,
    SPHINCS_SHA256192F_ROBUST,
    SPHINCS_SHA256192F_SIMPLE,
    SPHINCS_SHA256192S_ROBUST,
    SPHINCS_SHA256192S_SIMPLE,
    SPHINCS_SHA256256F_ROBUST,
    SPHINCS_SHA256256F_SIMPLE,
    SPHINCS_SHA256256S_ROBUST,
    SPHINCS_SHA256256S_SIMPLE,
    SPHINCS_SHAKE256128F_ROBUST,
    SPHINCS_SHAKE256128F_SIMPLE,
    SPHINCS_SHAKE256128S_ROBUST,
    SPHINCS_SHAKE256128S_SIMPLE,
    SPHINCS_SHAKE256192F_ROBUST,
    SPHINCS_SHAKE256192F_SIMPLE,
    SPHINCS_SHAKE256192S_ROBUST,
    SPHINCS_SHAKE256192S_SIMPLE,
    SPHINCS_SHAKE256256F_ROBUST,
    SPHINCS_SHAKE256256F_SIMPLE,
    SPHINCS_SHAKE256256S_ROBUST,
    SPHINCS_SHAKE256256S_SIMPLE,
    PICNIC_L1_FS,
    PICNIC_L1_UR,
    PICNIC_L3_FS,
    PICNIC_L3_UR,
    PICNIC_L5_FS,
    PICNIC_L5_UR,
    PICNIC2_L1_FS,
    PICNIC2_L3_FS,
    PICNIC2_L5_FS,
    Q_TESLA_PI,
    Q_TESLA_PIII,
    XMSS,

};

pub use time::Time;

mod kem;
pub use kem::*;

/// An end-entity certificate.
///
/// Server certificate processing in a TLS connection consists of several
/// steps. All of these steps are necessary:
///
/// * `EndEntityCert.verify_is_valid_tls_server_cert`: Verify that the server's
///   certificate is currently valid *for use by a TLS server*.
/// * `EndEntityCert.verify_is_valid_for_dns_name`: Verify that the server's
///   certificate is valid for the host that is being connected to.
/// * `EndEntityCert.verify_signature`: Verify that the signature of server's
///   `ServerKeyExchange` message is valid for the server's certificate.
///
/// Client certificate processing in a TLS connection consists of analogous
/// steps. All of these steps are necessary:
///
/// * `EndEntityCert.verify_is_valid_tls_client_cert`: Verify that the client's
///   certificate is currently valid *for use by a TLS client*.
/// * `EndEntityCert.verify_is_valid_for_dns_name` or
///   `EndEntityCert.verify_is_valid_for_at_least_one_dns_name`: Verify that the
///   client's certificate is valid for the identity or identities used to
///   identify the client. (Currently client authentication only works when the
///   client is identified by one or more DNS hostnames.)
/// * `EndEntityCert.verify_signature`: Verify that the client's signature in
///   its `CertificateVerify` message is valid using the public key from the
///   client's certificate.
///
/// Although it would be less error-prone to combine all these steps into a
/// single function call, some significant optimizations are possible if the
/// three steps are processed separately (in parallel). It does not matter much
/// which order the steps are done in, but **all of these steps must completed
/// before application data is sent and before received application data is
/// processed**. `EndEntityCert::from` is an inexpensive operation and is
/// deterministic, so if these tasks are done in multiple threads, it is
/// probably best to just call `EndEntityCert::from` multiple times (before each
/// operation) for the same DER-encoded ASN.1 certificate bytes.
pub struct EndEntityCert<'a> {
    inner: cert::Cert<'a>,
}

impl <'a> EndEntityCert<'a> {
    /// Parse the ASN.1 DER-encoded X.509 encoding of the certificate
    /// `cert_der`.
    pub fn from(cert_der: untrusted::Input<'a>) -> Result<Self, Error> {
        Ok(Self {
            inner: cert::parse_cert(cert_der, cert::EndEntityOrCA::EndEntity)?
        })
    }

    /// Verifies that the end-entity certificate is valid for use by a TLS
    /// server.
    ///
    /// `supported_sig_algs` is the list of signature algorithms that are
    /// trusted for use in certificate signatures; the end-entity certificate's
    /// public key is not validated against this list. `trust_anchors` is the
    /// list of root CAs to trust. `intermediate_certs` is the sequence of
    /// intermediate certificates that the server sent in the TLS handshake.
    /// `time` is the time for which the validation is effective (usually the
    /// current time).
    pub fn verify_is_valid_tls_server_cert(
            &self, supported_sig_algs: &[&SignatureAlgorithm],
            &TLSServerTrustAnchors(trust_anchors): &TLSServerTrustAnchors,
            intermediate_certs: &[untrusted::Input], time: Time)
            -> Result<(), Error> {
        verify_cert::build_chain(verify_cert::EKU_SERVER_AUTH,
                                 supported_sig_algs, trust_anchors,
                                 intermediate_certs, &self.inner, time, 0)
    }

    /// Verifies that the end-entity certificate is valid for use by a TLS
    /// client.
    ///
    /// If the certificate is not valid for any of the given names then this
    /// fails with `Error::CertNotValidForName`.
    ///
    /// `supported_sig_algs` is the list of signature algorithms that are
    /// trusted for use in certificate signatures; the end-entity certificate's
    /// public key is not validated against this list. `trust_anchors` is the
    /// list of root CAs to trust. `intermediate_certs` is the sequence of
    /// intermediate certificates that the client sent in the TLS handshake.
    /// `cert` is the purported end-entity certificate of the client. `time` is
    /// the time for which the validation is effective (usually the current
    /// time).
    pub fn verify_is_valid_tls_client_cert(
            &self, supported_sig_algs: &[&SignatureAlgorithm],
            &TLSClientTrustAnchors(trust_anchors): &TLSClientTrustAnchors,
            intermediate_certs: &[untrusted::Input], time: Time)
            -> Result<(), Error> {
        verify_cert::build_chain(verify_cert::EKU_CLIENT_AUTH,
                                 supported_sig_algs, trust_anchors,
                                 intermediate_certs, &self.inner, time, 0)
    }

    /// Verifies that the certificate is valid for the given DNS host name.
    pub fn verify_is_valid_for_dns_name(&self, dns_name: DNSNameRef)
                                        -> Result<(), Error> {
        name::verify_cert_dns_name(&self, dns_name)
    }

    /// Verifies that the certificate is valid for at least one of the given DNS
    /// host names.
    ///
    /// If the certificate is not valid for any of the given names then this
    /// fails with `Error::CertNotValidForName`. Otherwise the DNS names for
    /// which the certificate is valid are returned.
    ///
    /// Requires the `std` default feature; i.e. this isn't available in
    /// `#![no_std]` configurations.
    #[cfg(feature = "std")]
    pub fn verify_is_valid_for_at_least_one_dns_name<'names, Names>(
            &self, dns_names: Names)
            -> Result<std::vec::Vec<DNSNameRef<'names>>, Error>
            where Names: Iterator<Item=DNSNameRef<'names>> {
        let result: std::vec::Vec<DNSNameRef<'names>> = dns_names
            .filter(|n| self.verify_is_valid_for_dns_name(*n).is_ok())
            .collect();
        if result.is_empty() {
            return Err(Error::CertNotValidForName);
        }
        Ok(result)
    }

    /// Verifies the signature `signature` of message `msg` using the
    /// certificate's public key.
    ///
    /// `signature_alg` is the algorithm to use to
    /// verify the signature; the certificate's public key is verified to be
    /// compatible with this algorithm.
    ///
    /// For TLS 1.2, `signature` corresponds to TLS's
    /// `DigitallySigned.signature` and `signature_alg` corresponds to TLS's
    /// `DigitallySigned.algorithm` of TLS type `SignatureAndHashAlgorithm`. In
    /// TLS 1.2 a single `SignatureAndHashAlgorithm` may map to multiple
    /// `SignatureAlgorithm`s. For example, a TLS 1.2
    /// `ignatureAndHashAlgorithm` of (ECDSA, SHA-256) may map to any or all
    /// of {`ECDSA_P256_SHA256`, `ECDSA_P384_SHA256`}, depending on how the TLS
    /// implementation is configured.
    ///
    /// For current TLS 1.3 drafts, `signature_alg` corresponds to TLS's
    /// `algorithm` fields of type `SignatureScheme`. There is (currently) a
    /// one-to-one correspondence between TLS 1.3's `SignatureScheme` and
    /// `SignatureAlgorithm`.
    pub fn verify_signature(&self, signature_alg: &SignatureAlgorithm,
                            msg: untrusted::Input,
                            signature: untrusted::Input) -> Result<(), Error> {
        signed_data::verify_signature(signature_alg, self.inner.spki, msg,
                                      signature)
    }

    /// Check if this is a KEM cert by checking if we know how to get the public key
    pub fn is_kem_cert(&self) -> bool {
        signed_data::parse_spki_value(self.inner.spki).map(
            |spki| key_id_to_kem(spki.algorithm_id_value)).is_ok()
    }

    /// Get the public key data from the certificate
    ///
    /// Returns algorithm id and key value
    pub fn public_key(&'a self) -> Result<(&'static KemAlgorithm, untrusted::Input<'a>), Error>{
        let spki = signed_data::parse_spki_value(self.inner.spki)?;
        let algorithm = key_id_to_kem(spki.algorithm_id_value)?;
        let key_value = spki.key_value;
        Ok((algorithm, key_value))
    }

    /// Decapsulate
    pub fn decapsulate(&self, private_key_der: untrusted::Input, ciphertext: untrusted::Input) -> Result<std::vec::Vec<u8>, Error> {
        let spki = signed_data::parse_spki_value(self.inner.spki)?;
        let algorithm = key_id_to_kem(spki.algorithm_id_value)?;
        let private_key = private_key_der.read_all(Error::ThomMarker, |private_key_der| {
            der::nested_mut(private_key_der, der::Tag::Sequence, Error::BadDER, |data| {
                let _ = der::small_nonnegative_integer(data)?;
                let m1 = data.mark();
                der::nested_mut(data, der::Tag::Sequence, Error::BadDER, |keyinfo| {
                    let _ = der::expect_tag_and_get_value(keyinfo, der::Tag::OID)?;
                    Ok(())
                })?;
                let m2 = data.mark();
                let privkey_algorithm = untrusted::Input::from(&data.get_input_between_marks(m1, m2).unwrap().as_slice_less_safe()[2..]);
                let privkey_algorithm = key_id_to_kem(privkey_algorithm)?;
                assert_eq!(privkey_algorithm, algorithm, "Public key doesn't match private key in OID");

                der::nested_mut(data, der::Tag::OctetString, Error::BadDER, |data| {
                    der::expect_tag_and_get_value(data, der::Tag::OctetString)
                })
            })
        })?;

        let private_key = ring::agreement::PrivateKey::from(algorithm.kem, private_key);
        decapsulate(algorithm, &private_key, ciphertext)
    }

    /// Encapsulate
    pub fn encapsulate(&self) -> Result<(ring::agreement::Ciphertext, ring::agreement::SharedSecret), Error> {
        let spki = signed_data::parse_spki_value(self.inner.spki)?;
        let algorithm = key_id_to_kem(spki.algorithm_id_value)?;
        encapsulate(algorithm, spki.key_value)
    }

    /// Convert DER to the private key that belongs to this certificate.
    pub fn get_private_key(&self, encoded: &'a [u8]) -> Option<&'a [u8]> {
        let spki = signed_data::parse_spki_value(self.inner.spki);
        if let Ok(spki) = spki {
            Some(&encoded[0..spki.algorithm_id_value.len()])
        } else {
            None
        }
    }
}

/// A trust anchor (a.k.a. root CA).
///
/// Traditionally, certificate verification libraries have represented trust
/// anchors as full X.509 root certificates. However, those certificates
/// contain a lot more data than is needed for verifying certificates. The
/// `TrustAnchor` representation allows an application to store just the
/// essential elements of trust anchors. The `webpki::trust_anchor_util` module
/// provides functions for converting X.509 certificates to to the minimized
/// `TrustAnchor` representation, either at runtime or in a build script.
#[derive(Debug)]
pub struct TrustAnchor<'a> {
    /// The value of the `subject` field of the trust anchor.
    pub subject: &'a [u8],

    /// The value of the `subjectPublicKeyInfo` field of the trust anchor.
    pub spki: &'a [u8],

    /// The value of a DER-encoded NameConstraints, containing name
    /// constraints to apply to the trust anchor, if any.
    pub name_constraints: Option<&'a [u8]>
}

/// Trust anchors which may be used for authenticating servers.
#[derive(Debug)]
pub struct TLSServerTrustAnchors<'a>(pub &'a [TrustAnchor<'a>]);

/// Trust anchors which may be used for authenticating clients.
#[derive(Debug)]
pub struct TLSClientTrustAnchors<'a>(pub &'a [TrustAnchor<'a>]);
