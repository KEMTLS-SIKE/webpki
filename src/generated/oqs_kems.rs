
const KYBER512_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-kyber512.der")),
};

/// kyber512 KEM
pub static KYBER512: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER512_ID,
    kem: oqs::kem::Algorithm::Kyber512,
};
