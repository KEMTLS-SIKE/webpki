use crate::{error, signed_data::AlgorithmIdentifier};
use secsidh;

/// NIKE struct
pub struct NikeAlgorithm {
    /// alg id
    pub(crate) public_key_alg_id: AlgorithmIdentifier,
    /// SECSIDH alg id
    pub alg: secsidh::Algorithm,
}

/// Derive a shared secret from a network public key and our secret.
pub fn derive(
    alg: &NikeAlgorithm,
    public_key: untrusted::Input,
    private_key: &[u8],
) -> Result<Vec<u8>, error::Error> {
    let pk = secsidh::PublicKey::from_bytes(alg.alg, public_key.as_slice_less_safe())
        .ok_or(error::Error::KEMFailure)?;
    let sk = secsidh::SecretKey::from_bytes(alg.alg, private_key)
        .ok_or(error::Error::KEMFailure)?;
    secsidh::derive(&pk, &sk)
        .ok_or(error::Error::KEMFailure)
}

/// check if the nike is correct
fn check_key_id(nike: &NikeAlgorithm, encoded: untrusted::Input) -> bool {
    nike.public_key_alg_id.matches_algorithm_id_value(encoded)
}

/// convert a key id to a nike
pub fn key_id_to_nike(algorithm_id: untrusted::Input) -> Result<&'static NikeAlgorithm, error::Error> {
    include!("generated/get_nike.rs");

    Err(error::Error::KEMFailure)
}

include!("generated/nikes.rs");
