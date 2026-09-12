use pgp::composed::{Deserializable, SignedPublicKey, DetachedSignature};

fn main() {
    let pubkey_str = "";
    let sig_str = "";
    
    let cert = SignedPublicKey::from_string(pubkey_str).unwrap().0;
    let sig = DetachedSignature::from_string(sig_str).unwrap().0;
    
    sig.verify(&cert, b"hello world").unwrap();
}
