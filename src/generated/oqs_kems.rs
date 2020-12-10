
const KYBER512_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-kyber512.der")),
};

/// kyber512 KEM
pub static KYBER512: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER512_ID,
    kem: oqs::kem::Algorithm::Kyber512,
};

const LIGHTSABER_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-lightsaber.der")),
};

/// lightsaber KEM
pub static LIGHTSABER: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: LIGHTSABER_ID,
    kem: oqs::kem::Algorithm::Lightsaber,
};

const SIDHP434_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-SidhP434.der")),
};

/// SidhP434 KEM
pub static SIDHP434: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIDHP434_ID,
    kem: oqs::kem::Algorithm::SidhP434,
};
