use askama::Template;
use std::net::Ipv6Addr;

// the #[derive(Template)] macro reads the file at compile time
// and implements the render() method automatically.
#[derive(Template)]
#[template(path = "dn42_peer.conf")]
pub struct PeerConfigTemplate<'a> {
    pub iface_name: &'a str,
    pub protocol_name: String,  // dynamic strings can be owned or borrowed
    pub remote_ll_ip: Ipv6Addr, // askama automatically calls .to_string() for standard types
    pub asn: u32,
    pub local_ll_ip: Ipv6Addr,
}

// usage example in your route handler:
fn generate_config() {
    let tmpl = PeerConfigTemplate {
        iface_name: "wg-peer-4242",
        protocol_name: "wg_peer_4242".to_string(),
        remote_ll_ip: "fe80::2".parse().unwrap(),
        asn: 4242420000,
        local_ll_ip: "fe80::1".parse().unwrap(),
    };

    // renders the elegant way, returns a string
    let bird_conf = tmpl.render().unwrap();
    println!("{}", bird_conf);
}

// ==========================================
// 1. 定义 BIRD 专用的 Escaper 模块
// ==========================================
use askama::filters::Escaper as AskamaEscaper;
use std::fmt::{self, Write};

// Askama 宏硬性要求结构体名字必须叫 Escaper
#[derive(Copy, Clone)]
pub struct Escaper;

// 实现官方指定的 trait
impl AskamaEscaper for Escaper {
    fn write_escaped_str<W: Write>(&self, mut dest: W, string: &str) -> fmt::Result {
        for c in string.chars() {
            match c {
                // escape double quotes to prevent string closure in bird
                '"' => dest.write_str("\\\"")?,

                // escape backslash
                '\\' => dest.write_str("\\\\")?,

                // replace newlines with space to prevent multiline injection
                '\n' | '\r' => dest.write_char(' ')?,

                // drop other ascii control characters safely
                c if c.is_ascii_control() => {}

                // write all other characters normally
                _ => dest.write_char(c)?,
            }
        }
        Ok(())
    }

    // optional: override write_escaped_char for slight performance gain
    // if askama processes individual chars anywhere, though the default is usually fine
    #[inline]
    fn write_escaped_char<W: Write>(&self, mut dest: W, c: char) -> fmt::Result {
        match c {
            '"' => dest.write_str("\\\""),
            '\\' => dest.write_str("\\\\"),
            '\n' | '\r' => dest.write_char(' '),
            c if c.is_ascii_control() => Ok(()),
            _ => dest.write_char(c),
        }
    }
}
