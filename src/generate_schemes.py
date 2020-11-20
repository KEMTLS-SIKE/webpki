import subprocess
import os

# sigs
kems = [('kyber512', 'Kyber512')]
sigalgs = [('dilithium2', 'Dilithium2')]

for index, (alg, oqsalg) in enumerate(sigalgs):
    with open(f'data/alg-{alg}.ascii', 'w') as fh:
        fh.write(f"OBJECT_IDENTIFIER {{ 1.3.6.1.4.1.44363.46.{index} }}\n")

    subprocess.run(
        ["ascii2der", "-i", f"data/alg-{alg}.ascii", "-o", f"data/alg-{alg}.der"],
        check=True)
    subprocess.run(["git", "add", f"data/alg-{alg}.der"], check=True)
    os.remove(f'data/alg-{alg}.ascii')


with open('generated/oqs_sigschemes.rs', 'w') as fh:
    for alg, oqsalg in sigalgs:
        fh.write(f"""
const {alg.upper()}_ID: AlgorithmIdentifier = AlgorithmIdentifier {{
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-{alg}.der")),
}};

/// {alg} signatures
pub static {alg.upper()}: SignatureAlgorithm = SignatureAlgorithm {{
    public_key_alg_id: {alg.upper()}_ID,
    signature_alg_id: {alg.upper()}_ID,
    verification_alg: VerificationAlgorithm::Oqs(&oqs::sig::Algorithm::{oqsalg}),
}};
""")

with open('generated/oqs_sigschemes_use.rs', 'w') as fh:
    for alg, oqsalg in sigalgs:
        fh.write(f"pub use signed_data::{alg.upper()};\n")

## KEMs
for index, (alg, oqsalg) in enumerate(kems):
    with open(f'data/alg-{alg}.ascii', 'w') as fh:
        fh.write(f"OBJECT_IDENTIFIER {{ 1.3.6.1.4.1.44363.46.{index} }}\n")

    subprocess.run(
        ["ascii2der", "-i", f"data/alg-{alg}.ascii", "-o", f"data/alg-{alg}.der"],
        check=True)
    subprocess.run(["git", "add", f"data/alg-{alg}.der"], check=True)
    os.remove(f'data/alg-{alg}.ascii')

with open('generated/oqs_kems.rs', 'w') as fh:
    for alg, oqsalg in kems:
        fh.write(f"""
const {alg.upper()}_ID: AlgorithmIdentifier = AlgorithmIdentifier {{
    asn1_id_value: untrusted::Input::from(include_bytes!("../data/alg-{alg}.der")),
}};

/// {alg} KEM
pub static {alg.upper()}: KemAlgorithm = KemAlgorithm {{
    public_key_alg_id: {alg.upper()}_ID,
    kem: oqs::kem::Algorithm::{oqsalg},
}};
""")

with open('generated/get_kem.rs', 'w') as fh:
    for alg, oqsalg in kems:
        fh.write(f"""
        if check_key_id(&{alg.upper()}, algorithm_id) {{
            return Ok(&{alg.upper()});
        }}
""")
