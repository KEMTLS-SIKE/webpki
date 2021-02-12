
const KYBER512_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-kyber512.der")),
};

/// kyber512 KEM
pub static KYBER512: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER512_ID,
    kem: oqs::kem::Algorithm::Kyber512,
};

const KYBER768_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-kyber768.der")),
};

/// kyber768 KEM
pub static KYBER768: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER768_ID,
    kem: oqs::kem::Algorithm::Kyber768,
};

const KYBER1024_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-kyber1024.der")),
};

/// kyber1024 KEM
pub static KYBER1024: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER1024_ID,
    kem: oqs::kem::Algorithm::Kyber1024,
};

const MCELIECE348864_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece348864.der")),
};

/// mceliece348864 KEM
pub static MCELIECE348864: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE348864_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece348864,
};

const MCELIECE348864F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece348864f.der")),
};

/// mceliece348864f KEM
pub static MCELIECE348864F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE348864F_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece348864f,
};

const MCELIECE460896_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece460896.der")),
};

/// mceliece460896 KEM
pub static MCELIECE460896: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE460896_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece460896,
};

const MCELIECE460896F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece460896f.der")),
};

/// mceliece460896f KEM
pub static MCELIECE460896F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE460896F_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece460896f,
};

const MCELIECE6688128_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece6688128.der")),
};

/// mceliece6688128 KEM
pub static MCELIECE6688128: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE6688128_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece6688128,
};

const MCELIECE6688128F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece6688128f.der")),
};

/// mceliece6688128f KEM
pub static MCELIECE6688128F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE6688128F_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece6688128f,
};

const MCELIECE6960119_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece6960119.der")),
};

/// mceliece6960119 KEM
pub static MCELIECE6960119: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE6960119_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece6960119,
};

const MCELIECE6960119F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece6960119f.der")),
};

/// mceliece6960119f KEM
pub static MCELIECE6960119F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE6960119F_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece6960119f,
};

const MCELIECE8192128_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece8192128.der")),
};

/// mceliece8192128 KEM
pub static MCELIECE8192128: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE8192128_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece8192128,
};

const MCELIECE8192128F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-mceliece8192128f.der")),
};

/// mceliece8192128f KEM
pub static MCELIECE8192128F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE8192128F_ID,
    kem: oqs::kem::Algorithm::ClassicMcEliece8192128f,
};

const LIGHTSABER_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-lightsaber.der")),
};

/// lightsaber KEM
pub static LIGHTSABER: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: LIGHTSABER_ID,
    kem: oqs::kem::Algorithm::Lightsaber,
};

const SABER_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-saber.der")),
};

/// saber KEM
pub static SABER: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SABER_ID,
    kem: oqs::kem::Algorithm::Saber,
};

const FIRESABER_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-firesaber.der")),
};

/// firesaber KEM
pub static FIRESABER: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FIRESABER_ID,
    kem: oqs::kem::Algorithm::Firesaber,
};

const NTRUHPS2048509_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-ntruhps2048509.der")),
};

/// ntruhps2048509 KEM
pub static NTRUHPS2048509: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRUHPS2048509_ID,
    kem: oqs::kem::Algorithm::NtruHps2048509,
};

const SIDHP434_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-SidhP434.der")),
};

/// SidhP434 KEM
pub static SIDHP434: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIDHP434_ID,
    kem: oqs::kem::Algorithm::SidhP434,
};
