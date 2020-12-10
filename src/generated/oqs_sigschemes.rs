
const DILITHIUM2_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-dilithium2.der")),
};

/// dilithium2 signatures
pub static DILITHIUM2: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: DILITHIUM2_ID,
    signature_alg_id: DILITHIUM2_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::Dilithium2),
};

const DILITHIUM3_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-dilithium3.der")),
};

/// dilithium3 signatures
pub static DILITHIUM3: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: DILITHIUM3_ID,
    signature_alg_id: DILITHIUM3_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::Dilithium3),
};

const FALCON512_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-falcon512.der")),
};

/// falcon512 signatures
pub static FALCON512: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: FALCON512_ID,
    signature_alg_id: FALCON512_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::Falcon512),
};

const SPHINCSSHA256128FROBUST_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256128frobust.der")),
};

/// sphincssha256128frobust signatures
pub static SPHINCSSHA256128FROBUST: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256128FROBUST_ID,
    signature_alg_id: SPHINCSSHA256128FROBUST_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256128fRobust),
};

const SPHINCSSHA256128FSIMPLE_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-sphincssha256128fsimple.der")),
};

/// sphincssha256128fsimple signatures
pub static SPHINCSSHA256128FSIMPLE: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: SPHINCSSHA256128FSIMPLE_ID,
    signature_alg_id: SPHINCSSHA256128FSIMPLE_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::SphincsSha256128fSimple),
};
