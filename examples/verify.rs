extern crate webpki;
extern crate untrusted;

use std::fs;

use webpki::*;
use untrusted::Input;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read("x25519.der")?;
    let private = fs::read("x25519.key.der")?;
    let input = Input::from(&data);
    let private = Input::from(&private);
    let cert = EndEntityCert::from(input)?;

    let hostname = DNSNameRef::try_from_ascii(Input::from(b"localhost"))?;
    if cert.verify_is_valid_for_dns_name(hostname).is_ok() {
        println!("Valid for localhost");
    }

    println!("PK: {:x?}", cert.public_key()?);

    let (ct, ss) = cert.encapsulate()?;
    let ct = Input::from(&ct.as_ref());
    println!("len of ct: {}", ct.len());
    println!("len of private: {}", private.len());
    let ss2 = cert.decapsulate(private, ct)?;

    assert_eq!(ss, ss2);

    Ok(())

}
