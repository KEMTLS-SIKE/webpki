extern crate webpki;
extern crate untrusted;

use std::fs;

use webpki::*;
use untrusted::Input;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let data = fs::read("sphincsshake256128fsimple.crt.bin")?;
    let input = Input::from(&data);
    let cert = EndEntityCert::from(input)?;

    let hostname = DNSNameRef::try_from_ascii(Input::from(b"localhost"))?;
    if cert.verify_is_valid_for_dns_name(hostname).is_ok() {
        println!("Valid for localhost");
    }

    Ok(())

}
