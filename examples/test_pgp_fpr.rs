use pgp::composed::{Deserializable, SignedPublicKey};
use pgp::types::KeyDetails;

fn main() {
    let key = SignedPublicKey::from_string("").unwrap().0;
    let fpr = key.fingerprint();
    let fpr_hex = hex::encode(fpr.as_bytes());
    println!("{}", fpr_hex);
}
