use askama::Template;
use std::net::Ipv6Addr;

// the #[derive(Template)] macro reads the file at compile time
// and implements the render() method automatically.
#[derive(Template)]
#[template(path = "peer.conf")]
pub struct PeerTemplate<'a> {
    pub peer_id: u32,
    pub peer_name: &'a str,
    pub asn: u32,
    pub local_asn: u32,
    pub iface: &'a str,
    pub local_ll_ip: Ipv6Addr,
    pub remote_ll_ip: Ipv6Addr,
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_peer_template_rendering() {
        let tmpl = PeerTemplate {
            peer_id: 7,
            peer_name: "fra1",
            asn: 4242421234,
            local_asn: 4242420291,
            iface: "wg-peer-4242",
            local_ll_ip: Ipv6Addr::from_str("fe80::1").unwrap(),
            remote_ll_ip: Ipv6Addr::from_str("fe80::2").unwrap(),
        };

        let result = tmpl.render().unwrap();
        assert!(result.contains("protocol bgp dn42_4242421234_7"));
        assert!(result.contains("Peer name: fra1 (ID 7)"));
        assert!(result.contains("local fe80::1 as 4242420291;"));
        assert!(result.contains("neighbor fe80::2 % 'wg-peer-4242' as 4242421234;"));
        assert!(result.contains("table dn42_v6;"));
        assert!(result.contains("import where dn42_import_from_peer(4242421234, 7);"));
        assert!(result.contains("export where dn42_export_to_peer(4242421234, 7);"));
        assert!(result.contains("table dn42_v4;"));
        assert!(result.contains("import where dn42_import_from_peer_v4(4242421234, 7);"));
        assert!(result.contains("export where dn42_export_to_peer_v4(4242421234, 7);"));
    }

    #[test]
    fn test_escaper_prevents_injection() {
        let tmpl = PeerTemplate {
            peer_id: 7,
            peer_name: "fra1",
            asn: 4242421234,
            local_asn: 4242420291,
            iface: "wg-peer';\n  include \"/etc/shadow\";\n  #",
            local_ll_ip: Ipv6Addr::from_str("fe80::1").unwrap(),
            remote_ll_ip: Ipv6Addr::from_str("fe80::2").unwrap(),
        };

        let result = tmpl.render().unwrap();
        // The template engine only escapes the variables!
        // Let's check if the injected newline in `iface` is replaced by space.
        assert!(result.contains("wg-peer';   include \\\"/etc/shadow\\\";   #"));
    }
}
