
const CSIDH2047D221_ID: AlgorithmIdentifier = AlgorithmIdentifier {
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-csidh2047d221.der")),
};

/// csidh2047d221 NIKE
pub static CSIDH2047D221: NikeAlgorithm = NikeAlgorithm {
    public_key_alg_id: CSIDH2047D221_ID,
    alg: secsidh::Algorithm::CSIDH2047d221,
};
