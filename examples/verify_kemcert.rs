extern crate webpki;
extern crate untrusted;

use std::fs;

use webpki::*;
use untrusted::Input;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read("kyber512.der")?;
    let pk = fs::read("kyber512.pub.bin")?;
    let sk = fs::read("kyber512.key.bin")?;
    let input = Input::from(&data);
    let cert = EndEntityCert::from(input)?;

    let hostname = DNSNameRef::try_from_ascii(Input::from(b"localhost"))?;
    if cert.verify_is_valid_for_dns_name(hostname).is_ok() {
        println!("Valid for localhost");
    }

    let (id, pk_cert) = cert.public_key()?;
    assert_eq!(pk.len(), pk_cert.len(), "Public key len doesn't match actual");
    assert_eq!(pk.as_slice(), pk_cert.as_slice_less_safe(), "Public key doesn't match actual");
    //println!("Key id: {}", id);

    let (ct, ss) = cert.encapsulate().unwrap();
    let ss2 = cert.decapsulate(Input::from(&sk), Input::from(ct.as_ref()))?;

    assert_eq!(ss, ss2);
    println!("SS: {:?}", ss);




    Ok(())

}
