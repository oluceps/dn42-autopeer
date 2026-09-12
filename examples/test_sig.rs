use ssh_key::SshSig;
use std::str::FromStr;

fn main() {
    let raw = "-----BEGIN SSH SIGNATURE-----\nU1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg4HP5IGfw7XvjgnVdDc6nAgaZee\nRZH27ymsAXkZ8gvQEAAAAEZG40MgAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUx\nOQAAAECZVQFNpwqDgDRXFg6MFedpFt2I3MQiYxoEq814g5wylzRRVwwrsy/dK53te5BRhJ\nPwqHknBTTKpQvCgd7b+HgN\n-----END SSH SIGNATURE-----\n";
    match SshSig::from_str(raw) {
        Ok(_) => println!("Parsed armored!"),
        Err(e) => println!("Error armored: {}", e),
    }

    let raw2 = "U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg4HP5IGfw7XvjgnVdDc6nAgaZeeRZH27ymsAXkZ8gvQEAAAAEZG40MgAAAAAAAAAGc2hhNTEyAAAAUwAAAAtzc2gtZWQyNTUxOQAAAECZVQFNpwqDgDRXFg6MFedpFt2I3MQiYxoEq814g5wylzRRVwwrsy/dK53te5BRhJPwqHknBTTKpQvCgd7b+HgN";
    match SshSig::from_str(raw2) {
        Ok(_) => println!("Parsed base64!"),
        Err(e) => println!("Error base64: {}", e),
    }
}
