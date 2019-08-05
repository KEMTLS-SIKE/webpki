use std::vec::Vec;
use crate::error;
use signed_data::AlgorithmIdentifier;

/// Kem struct
pub struct KemAlgorithm {
    /// alg id
    pub(crate) public_key_alg_id: AlgorithmIdentifier,
    /// kem alg
    pub kem: &'static ring::agreement::Algorithm,
}

/// Decapsulate
///
/// Assumes you have the correct KEM!
pub fn decapsulate(alg: &KemAlgorithm,
                   private_key: &ring::agreement::PrivateKey,
                   ciphertext: untrusted::Input
 ) -> Result<Vec<u8>, error::Error> {
    (alg.kem.decapsulate)(private_key, ciphertext).map_err(|_| error::Error::KEMFailure)
}

/// Encapsulate
pub fn encapsulate(alg: &KemAlgorithm, public_key: untrusted::Input) -> Result<(ring::agreement::Ciphertext, ring::agreement::SharedSecret), error::Error> {
    let rng = ring::rand::SystemRandom::new();
    (alg.kem.encapsulate)(public_key, &rng).map_err(|_| error::Error::KEMFailure)
}


/// check if the kem is correct
pub fn check_key_id(kem: &KemAlgorithm, encoded: untrusted::Input) -> bool {
    kem.public_key_alg_id.matches_algorithm_id_value(encoded)
}


macro_rules! get_kem {
    ($kem:ident, $algorithm_id: expr) => {
        if check_key_id(&$kem, $algorithm_id) {
            return Ok(&$kem);
        }
    };
}

/// convert a key id to a kem
pub fn key_id_to_kem(algorithm_id: untrusted::Input) -> Result<&'static KemAlgorithm, error::Error> {
    get_kem!(CSIDH, algorithm_id);
    get_kem!(KYBER512, algorithm_id);
    get_kem!(KYBER768, algorithm_id);
    get_kem!(KYBER1024, algorithm_id);

    Err(error::Error::KEMFailure)
}



const CSIDH_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x64\x05\x00"
};

/// csidh kem
pub static CSIDH: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: CSIDH_ID,
    kem: &ring::agreement::CSIDH,
};



const KYBER512_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x65\x05\x00"
};

/// kyber512 kem
pub static KYBER512: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER512_ID,
    kem: &ring::agreement::KYBER512,
};



const KYBER768_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x66\x05\x00"
};

/// kyber768 kem
pub static KYBER768: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER768_ID,
    kem: &ring::agreement::KYBER768,
};



const KYBER1024_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x67\x05\x00"
};

/// kyber1024 kem
pub static KYBER1024: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER1024_ID,
    kem: &ring::agreement::KYBER1024,
};
