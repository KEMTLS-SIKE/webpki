use std::println;
use std::vec::Vec;
use std::fmt;
use crate::error;
use signed_data::AlgorithmIdentifier;

/// Kem struct
#[derive(Debug, PartialEq)]
pub struct KemAlgorithm {
    /// alg id
    pub(crate) public_key_alg_id: AlgorithmIdentifier,
    /// kem alg
    pub kem: &'static ring::agreement::Algorithm,
}

impl fmt::Display for KemAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x?}", self.public_key_alg_id)
    }
}

/// Decapsulate
///
/// Assumes you have the correct KEM!
pub fn decapsulate(alg: &KemAlgorithm,
                   private_key: &ring::agreement::PrivateKey,
                   ciphertext: untrusted::Input
 ) -> Result<Vec<u8>, error::Error> {
    (alg.kem.decapsulate)(private_key, ciphertext).map_err(|e| {
        println!("{:#?}", e);
        error::Error::KEMFailure
    })
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
    get_kem!(X25519, algorithm_id);
    get_kem!(CSIDH, algorithm_id);
    get_kem!(KYBER512, algorithm_id);
    get_kem!(KYBER768, algorithm_id);
    get_kem!(KYBER1024, algorithm_id);
    get_kem!(KYBER51290S, algorithm_id);
    get_kem!(KYBER76890S, algorithm_id);
    get_kem!(KYBER102490S, algorithm_id);
    get_kem!(BABYBEAR, algorithm_id);
    get_kem!(BABYBEAREPHEM, algorithm_id);
    get_kem!(MAMABEAR, algorithm_id);
    get_kem!(MAMABEAREPHEM, algorithm_id);
    get_kem!(PAPABEAR, algorithm_id);
    get_kem!(PAPABEAREPHEM, algorithm_id);
    get_kem!(LIGHTSABER, algorithm_id);
    get_kem!(SABER, algorithm_id);
    get_kem!(FIRESABER, algorithm_id);
    get_kem!(LEDAKEMLT12, algorithm_id);
    get_kem!(LEDAKEMLT32, algorithm_id);
    get_kem!(LEDAKEMLT52, algorithm_id);
    get_kem!(NEWHOPE512CPA, algorithm_id);
    get_kem!(NEWHOPE512CCA, algorithm_id);
    get_kem!(NEWHOPE1024CPA, algorithm_id);
    get_kem!(NEWHOPE1024CCA, algorithm_id);
    get_kem!(NTRUHPS2048509, algorithm_id);
    get_kem!(NTRUHPS2048677, algorithm_id);
    get_kem!(NTRUHPS4096821, algorithm_id);
    get_kem!(NTRUHRSS701, algorithm_id);
    get_kem!(FRODOKEM640AES, algorithm_id);
    get_kem!(FRODOKEM640SHAKE, algorithm_id);
    get_kem!(FRODOKEM976AES, algorithm_id);
    get_kem!(FRODOKEM976SHAKE, algorithm_id);
    get_kem!(FRODOKEM1344AES, algorithm_id);
    get_kem!(FRODOKEM1344SHAKE, algorithm_id);
    get_kem!(MCELIECE348864, algorithm_id);
    get_kem!(MCELIECE348864F, algorithm_id);
    get_kem!(MCELIECE460896, algorithm_id);
    get_kem!(MCELIECE460896F, algorithm_id);
    get_kem!(MCELIECE6688128, algorithm_id);
    get_kem!(MCELIECE6688128F, algorithm_id);
    get_kem!(MCELIECE6960119, algorithm_id);
    get_kem!(MCELIECE6960119F, algorithm_id);
    get_kem!(MCELIECE8192128, algorithm_id);
    get_kem!(MCELIECE8192128F, algorithm_id);
    get_kem!(HQC1281CCA2, algorithm_id);
    get_kem!(HQC1921CCA2, algorithm_id);
    get_kem!(HQC1922CCA2, algorithm_id);
    get_kem!(HQC2561CCA2, algorithm_id);
    get_kem!(HQC2562CCA2, algorithm_id);
    get_kem!(HQC2563CCA2, algorithm_id);
    get_kem!(BIKEL1FO, algorithm_id);
    get_kem!(SIKEP434COMPRESSED, algorithm_id);

    std::println!("Didn't find any KEM key");
    Err(error::Error::KEMFailure)
}


const X25519_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: b"\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00"
};

/// X25519 KEM
pub static X25519: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: X25519_ID,
    kem: &ring::agreement::X25519,
};

const CSIDH_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x3F\x05\x00"
};

/// csidh kem
pub static CSIDH: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: CSIDH_ID,
    kem: &ring::agreement::CSIDH,
};


const KYBER512_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x40\x05\x00"
};

/// kyber512 kem
pub static KYBER512: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER512_ID,
    kem: &ring::agreement::KYBER512,
};


const KYBER768_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x41\x05\x00"
};

/// kyber768 kem
pub static KYBER768: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER768_ID,
    kem: &ring::agreement::KYBER768,
};


const KYBER1024_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x42\x05\x00"
};

/// kyber1024 kem
pub static KYBER1024: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER1024_ID,
    kem: &ring::agreement::KYBER1024,
};


const KYBER51290S_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x43\x05\x00"
};

/// kyber51290s kem
pub static KYBER51290S: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER51290S_ID,
    kem: &ring::agreement::KYBER51290S,
};


const KYBER76890S_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x44\x05\x00"
};

/// kyber76890s kem
pub static KYBER76890S: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER76890S_ID,
    kem: &ring::agreement::KYBER76890S,
};


const KYBER102490S_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x45\x05\x00"
};

/// kyber102490s kem
pub static KYBER102490S: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: KYBER102490S_ID,
    kem: &ring::agreement::KYBER102490S,
};


const BABYBEAR_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x46\x05\x00"
};

/// babybear kem
pub static BABYBEAR: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: BABYBEAR_ID,
    kem: &ring::agreement::BABYBEAR,
};


const BABYBEAREPHEM_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x47\x05\x00"
};

/// babybearephem kem
pub static BABYBEAREPHEM: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: BABYBEAREPHEM_ID,
    kem: &ring::agreement::BABYBEAREPHEM,
};


const MAMABEAR_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x48\x05\x00"
};

/// mamabear kem
pub static MAMABEAR: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MAMABEAR_ID,
    kem: &ring::agreement::MAMABEAR,
};


const MAMABEAREPHEM_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x49\x05\x00"
};

/// mamabearephem kem
pub static MAMABEAREPHEM: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MAMABEAREPHEM_ID,
    kem: &ring::agreement::MAMABEAREPHEM,
};


const PAPABEAR_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x4A\x05\x00"
};

/// papabear kem
pub static PAPABEAR: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: PAPABEAR_ID,
    kem: &ring::agreement::PAPABEAR,
};


const PAPABEAREPHEM_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x4B\x05\x00"
};

/// papabearephem kem
pub static PAPABEAREPHEM: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: PAPABEAREPHEM_ID,
    kem: &ring::agreement::PAPABEAREPHEM,
};


const LIGHTSABER_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x4C\x05\x00"
};

/// lightsaber kem
pub static LIGHTSABER: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: LIGHTSABER_ID,
    kem: &ring::agreement::LIGHTSABER,
};


const SABER_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x4D\x05\x00"
};

/// saber kem
pub static SABER: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SABER_ID,
    kem: &ring::agreement::SABER,
};


const FIRESABER_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x4E\x05\x00"
};

/// firesaber kem
pub static FIRESABER: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FIRESABER_ID,
    kem: &ring::agreement::FIRESABER,
};


const LEDAKEMLT12_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x4F\x05\x00"
};

/// ledakemlt12 kem
pub static LEDAKEMLT12: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: LEDAKEMLT12_ID,
    kem: &ring::agreement::LEDAKEMLT12,
};


const LEDAKEMLT32_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x50\x05\x00"
};

/// ledakemlt32 kem
pub static LEDAKEMLT32: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: LEDAKEMLT32_ID,
    kem: &ring::agreement::LEDAKEMLT32,
};


const LEDAKEMLT52_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x51\x05\x00"
};

/// ledakemlt52 kem
pub static LEDAKEMLT52: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: LEDAKEMLT52_ID,
    kem: &ring::agreement::LEDAKEMLT52,
};


const NEWHOPE512CPA_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x52\x05\x00"
};

/// newhope512cpa kem
pub static NEWHOPE512CPA: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NEWHOPE512CPA_ID,
    kem: &ring::agreement::NEWHOPE512CPA,
};


const NEWHOPE512CCA_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x53\x05\x00"
};

/// newhope512cca kem
pub static NEWHOPE512CCA: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NEWHOPE512CCA_ID,
    kem: &ring::agreement::NEWHOPE512CCA,
};


const NEWHOPE1024CPA_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x54\x05\x00"
};

/// newhope1024cpa kem
pub static NEWHOPE1024CPA: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NEWHOPE1024CPA_ID,
    kem: &ring::agreement::NEWHOPE1024CPA,
};


const NEWHOPE1024CCA_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x55\x05\x00"
};

/// newhope1024cca kem
pub static NEWHOPE1024CCA: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NEWHOPE1024CCA_ID,
    kem: &ring::agreement::NEWHOPE1024CCA,
};


const NTRUHPS2048509_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x56\x05\x00"
};

/// ntruhps2048509 kem
pub static NTRUHPS2048509: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRUHPS2048509_ID,
    kem: &ring::agreement::NTRUHPS2048509,
};


const NTRUHPS2048677_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x57\x05\x00"
};

/// ntruhps2048677 kem
pub static NTRUHPS2048677: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRUHPS2048677_ID,
    kem: &ring::agreement::NTRUHPS2048677,
};


const NTRUHPS4096821_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x58\x05\x00"
};

/// ntruhps4096821 kem
pub static NTRUHPS4096821: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRUHPS4096821_ID,
    kem: &ring::agreement::NTRUHPS4096821,
};


const NTRUHRSS701_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x59\x05\x00"
};

/// ntruhrss701 kem
pub static NTRUHRSS701: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: NTRUHRSS701_ID,
    kem: &ring::agreement::NTRUHRSS701,
};


const FRODOKEM640AES_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x5A\x05\x00"
};

/// frodokem640aes kem
pub static FRODOKEM640AES: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM640AES_ID,
    kem: &ring::agreement::FRODOKEM640AES,
};


const FRODOKEM640SHAKE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x5B\x05\x00"
};

/// frodokem640shake kem
pub static FRODOKEM640SHAKE: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM640SHAKE_ID,
    kem: &ring::agreement::FRODOKEM640SHAKE,
};


const FRODOKEM976AES_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x5C\x05\x00"
};

/// frodokem976aes kem
pub static FRODOKEM976AES: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM976AES_ID,
    kem: &ring::agreement::FRODOKEM976AES,
};


const FRODOKEM976SHAKE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x5D\x05\x00"
};

/// frodokem976shake kem
pub static FRODOKEM976SHAKE: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM976SHAKE_ID,
    kem: &ring::agreement::FRODOKEM976SHAKE,
};


const FRODOKEM1344AES_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x5E\x05\x00"
};

/// frodokem1344aes kem
pub static FRODOKEM1344AES: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM1344AES_ID,
    kem: &ring::agreement::FRODOKEM1344AES,
};


const FRODOKEM1344SHAKE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x5F\x05\x00"
};

/// frodokem1344shake kem
pub static FRODOKEM1344SHAKE: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: FRODOKEM1344SHAKE_ID,
    kem: &ring::agreement::FRODOKEM1344SHAKE,
};


const MCELIECE348864_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x60\x05\x00"
};

/// mceliece348864 kem
pub static MCELIECE348864: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE348864_ID,
    kem: &ring::agreement::MCELIECE348864,
};


const MCELIECE348864F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x61\x05\x00"
};

/// mceliece348864f kem
pub static MCELIECE348864F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE348864F_ID,
    kem: &ring::agreement::MCELIECE348864F,
};


const MCELIECE460896_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x62\x05\x00"
};

/// mceliece460896 kem
pub static MCELIECE460896: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE460896_ID,
    kem: &ring::agreement::MCELIECE460896,
};


const MCELIECE460896F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x63\x05\x00"
};

/// mceliece460896f kem
pub static MCELIECE460896F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE460896F_ID,
    kem: &ring::agreement::MCELIECE460896F,
};


const MCELIECE6688128_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x64\x05\x00"
};

/// mceliece6688128 kem
pub static MCELIECE6688128: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE6688128_ID,
    kem: &ring::agreement::MCELIECE6688128,
};


const MCELIECE6688128F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x65\x05\x00"
};

/// mceliece6688128f kem
pub static MCELIECE6688128F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE6688128F_ID,
    kem: &ring::agreement::MCELIECE6688128F,
};


const MCELIECE6960119_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x66\x05\x00"
};

/// mceliece6960119 kem
pub static MCELIECE6960119: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE6960119_ID,
    kem: &ring::agreement::MCELIECE6960119,
};


const MCELIECE6960119F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x67\x05\x00"
};

/// mceliece6960119f kem
pub static MCELIECE6960119F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE6960119F_ID,
    kem: &ring::agreement::MCELIECE6960119F,
};


const MCELIECE8192128_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x68\x05\x00"
};

/// mceliece8192128 kem
pub static MCELIECE8192128: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE8192128_ID,
    kem: &ring::agreement::MCELIECE8192128,
};


const MCELIECE8192128F_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x69\x05\x00"
};

/// mceliece8192128f kem
pub static MCELIECE8192128F: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: MCELIECE8192128F_ID,
    kem: &ring::agreement::MCELIECE8192128F,
};


const HQC1281CCA2_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x6A\x05\x00"
};

/// hqc1281cca2 kem
pub static HQC1281CCA2: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: HQC1281CCA2_ID,
    kem: &ring::agreement::HQC1281CCA2,
};


const HQC1921CCA2_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x6B\x05\x00"
};

/// hqc1921cca2 kem
pub static HQC1921CCA2: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: HQC1921CCA2_ID,
    kem: &ring::agreement::HQC1921CCA2,
};


const HQC1922CCA2_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x6C\x05\x00"
};

/// hqc1922cca2 kem
pub static HQC1922CCA2: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: HQC1922CCA2_ID,
    kem: &ring::agreement::HQC1922CCA2,
};


const HQC2561CCA2_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x6D\x05\x00"
};

/// hqc2561cca2 kem
pub static HQC2561CCA2: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: HQC2561CCA2_ID,
    kem: &ring::agreement::HQC2561CCA2,
};


const HQC2562CCA2_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x6E\x05\x00"
};

/// hqc2562cca2 kem
pub static HQC2562CCA2: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: HQC2562CCA2_ID,
    kem: &ring::agreement::HQC2562CCA2,
};


const HQC2563CCA2_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x6F\x05\x00"
};

/// hqc2563cca2 kem
pub static HQC2563CCA2: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: HQC2563CCA2_ID,
    kem: &ring::agreement::HQC2563CCA2,
};


const BIKEL1FO_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x70\x05\x00"
};

/// bikel1fo kem
pub static BIKEL1FO: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: BIKEL1FO_ID,
    kem: &ring::agreement::BIKEL1FO,
};


const SIKEP434COMPRESSED_ID: AlgorithmIdentifier = AlgorithmIdentifier {
     asn1_id_value: b"\x06\x0B\x2A\x06\x01\x04\x01\x82\x37\x59\x02\xFE\x71\x05\x00"
};

/// sikep434compressed kem
pub static SIKEP434COMPRESSED: KemAlgorithm = KemAlgorithm {
    public_key_alg_id: SIKEP434COMPRESSED_ID,
    kem: &ring::agreement::SIKEP434COMPRESSED,
};
