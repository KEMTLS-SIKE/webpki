
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

const NTRUHPS2048677_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-ntruhps2048677.der")),
};

/// ntruhps2048677 KEM
pub static NTRUHPS2048677: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRUHPS2048677_ID,
    kem: oqs::kem::Algorithm::NtruHps2048677,
};

const NTRUHPS4096821_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-ntruhps4096821.der")),
};

/// ntruhps4096821 KEM
pub static NTRUHPS4096821: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRUHPS4096821_ID,
    kem: oqs::kem::Algorithm::NtruHps4096821,
};

const NTRUHRSS701_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-ntruhrss701.der")),
};

/// ntruhrss701 KEM
pub static NTRUHRSS701: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRUHRSS701_ID,
    kem: oqs::kem::Algorithm::NtruHrss701,
};

const NTRULPR653_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-ntrulpr653.der")),
};

/// ntrulpr653 KEM
pub static NTRULPR653: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRULPR653_ID,
    kem: oqs::kem::Algorithm::NtruPrimeNtrulpr653,
};

const NTRULPR761_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-ntrulpr761.der")),
};

/// ntrulpr761 KEM
pub static NTRULPR761: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRULPR761_ID,
    kem: oqs::kem::Algorithm::NtruPrimeNtrulpr761,
};

const NTRULPR857_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-ntrulpr857.der")),
};

/// ntrulpr857 KEM
pub static NTRULPR857: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRULPR857_ID,
    kem: oqs::kem::Algorithm::NtruPrimeNtrulpr857,
};

const SNTRUP653_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sntrup653.der")),
};

/// sntrup653 KEM
pub static SNTRUP653: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SNTRUP653_ID,
    kem: oqs::kem::Algorithm::NtruPrimeSntrup653,
};

const SNTRUP761_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sntrup761.der")),
};

/// sntrup761 KEM
pub static SNTRUP761: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SNTRUP761_ID,
    kem: oqs::kem::Algorithm::NtruPrimeSntrup761,
};

const SNTRUP857_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sntrup857.der")),
};

/// sntrup857 KEM
pub static SNTRUP857: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SNTRUP857_ID,
    kem: oqs::kem::Algorithm::NtruPrimeSntrup857,
};

const FRODOKEM640AES_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-frodokem640aes.der")),
};

/// frodokem640aes KEM
pub static FRODOKEM640AES: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM640AES_ID,
    kem: oqs::kem::Algorithm::FrodoKem640Aes,
};

const FRODOKEM640SHAKE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-frodokem640shake.der")),
};

/// frodokem640shake KEM
pub static FRODOKEM640SHAKE: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM640SHAKE_ID,
    kem: oqs::kem::Algorithm::FrodoKem640Shake,
};

const FRODOKEM976AES_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-frodokem976aes.der")),
};

/// frodokem976aes KEM
pub static FRODOKEM976AES: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM976AES_ID,
    kem: oqs::kem::Algorithm::FrodoKem976Aes,
};

const FRODOKEM976SHAKE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-frodokem976shake.der")),
};

/// frodokem976shake KEM
pub static FRODOKEM976SHAKE: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM976SHAKE_ID,
    kem: oqs::kem::Algorithm::FrodoKem976Shake,
};

const FRODOKEM1344AES_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-frodokem1344aes.der")),
};

/// frodokem1344aes KEM
pub static FRODOKEM1344AES: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM1344AES_ID,
    kem: oqs::kem::Algorithm::FrodoKem1344Aes,
};

const FRODOKEM1344SHAKE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-frodokem1344shake.der")),
};

/// frodokem1344shake KEM
pub static FRODOKEM1344SHAKE: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM1344SHAKE_ID,
    kem: oqs::kem::Algorithm::FrodoKem1344Shake,
};

const SIKEP434_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sikep434.der")),
};

/// sikep434 KEM
pub static SIKEP434: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIKEP434_ID,
    kem: oqs::kem::Algorithm::SikeP434,
};

const SIKEP434COMPRESSED_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sikep434compressed.der")),
};

/// sikep434compressed KEM
pub static SIKEP434COMPRESSED: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIKEP434COMPRESSED_ID,
    kem: oqs::kem::Algorithm::SikeP434Compressed,
};

const SIKEP503_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sikep503.der")),
};

/// sikep503 KEM
pub static SIKEP503: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIKEP503_ID,
    kem: oqs::kem::Algorithm::SikeP503,
};

const SIKEP503COMPRESSED_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sikep503compressed.der")),
};

/// sikep503compressed KEM
pub static SIKEP503COMPRESSED: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIKEP503COMPRESSED_ID,
    kem: oqs::kem::Algorithm::SikeP503Compressed,
};

const SIKEP610_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sikep610.der")),
};

/// sikep610 KEM
pub static SIKEP610: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIKEP610_ID,
    kem: oqs::kem::Algorithm::SikeP610,
};

const SIKEP610COMPRESSED_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sikep610compressed.der")),
};

/// sikep610compressed KEM
pub static SIKEP610COMPRESSED: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIKEP610COMPRESSED_ID,
    kem: oqs::kem::Algorithm::SikeP610Compressed,
};

const SIKEP751_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sikep751.der")),
};

/// sikep751 KEM
pub static SIKEP751: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIKEP751_ID,
    kem: oqs::kem::Algorithm::SikeP751,
};

const SIKEP751COMPRESSED_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sikep751compressed.der")),
};

/// sikep751compressed KEM
pub static SIKEP751COMPRESSED: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIKEP751COMPRESSED_ID,
    kem: oqs::kem::Algorithm::SikeP751Compressed,
};

const BIKEL1FO_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-bikel1fo.der")),
};

/// bikel1fo KEM
pub static BIKEL1FO: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: BIKEL1FO_ID,
    kem: oqs::kem::Algorithm::BikeL1Fo,
};

const BIKEL3FO_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-bikel3fo.der")),
};

/// bikel3fo KEM
pub static BIKEL3FO: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: BIKEL3FO_ID,
    kem: oqs::kem::Algorithm::BikeL3Fo,
};
