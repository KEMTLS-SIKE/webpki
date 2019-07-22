extern crate webpki;
extern crate untrusted;

use std::fs;

use webpki::*;
use untrusted::Input;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read("kyber512.der")?;
    let sk = fs::read("kyber512.key.bin")?;
    let input = Input::from(&data);
    let cert = EndEntityCert::from(input)?;

    let hostname = DNSNameRef::try_from_ascii(Input::from(b"localhost"))?;
    if cert.verify_is_valid_for_dns_name(hostname).is_ok() {
        println!("Valid for localhost");
    }

    let (id, pk) = cert.public_key()?;
    println!("Key id: {:?}", id.kem);

    let rng = ring::rand::SystemRandom::new();
    let epk = ring::agreement::EphemeralPrivateKey::generate(id.kem, &rng)?;
    let (ct, ss) = epk.encapsulate(pk, (), |x| Ok(x.to_vec())).unwrap();
    println!("SS1: {:?}", ss);
    let ss2 = cert.decapsulate(Input::from(&sk), Input::from(ct.as_ref()))?;

    assert_eq!(ss, ss2);


    //println!("Public key: {:?}", pk.as_slice_less_safe());


    Ok(())

}
