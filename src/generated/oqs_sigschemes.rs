
const DILITHIUM2_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-dilithium2.der")),
};

/// dilithium2 signatures
pub static DILITHIUM2: SignatureAlgorithm = SignatureAlgorithm {
    public_key_alg_id: DILITHIUM2_ID,
    signature_alg_id: DILITHIUM2_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::Dilithium2),
};
