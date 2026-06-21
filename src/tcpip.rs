use crate::ethernet::EtherType;
use std::fmt;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("truncated packet: got {0} bytes, expected {1}")]
    Truncated(usize, usize),
    #[error("arp packet has invalid or unsupported size: {0}")]
    UnsupportedArpPacket(usize),
    #[error("malformed ipv4 header")]
    MalformedIpv4Header,
    #[error("malformed ipv6 header")]
    MalformedIpv6Header,
    #[error("malformed arp packet")]
    MalformedArpPacket,
    #[error("unknown ether type: {0:x}")]
    UnknownEtherType(u16),
}

pub enum NetworkPacket<'a> {
    Ipv4(v4::Packet<'a>),
    Ipv6(v6::Packet<'a>),
    Arp(arp::Packet<'a>),
}

impl<'a> NetworkPacket<'a> {
    pub fn parse(ether_type: EtherType, payload: &'a [u8]) -> Result<Self, Error> {
        match ether_type {
            EtherType::Ipv4 => v4::Packet::from_bytes(payload).map(Self::Ipv4),
            EtherType::Ipv6 => v6::Packet::from_bytes(payload).map(Self::Ipv6),
            EtherType::Arp => arp::Packet::from_bytes(payload).map(Self::Arp),
            EtherType::Other(v) => Err(Error::UnknownEtherType(v)),
        }
    }
}

impl<'a> fmt::Display for NetworkPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Arp(v) => v.fmt(f),
            Self::Ipv4(v) => v.fmt(f),
            Self::Ipv6(v) => v.fmt(f),
        }
    }
}

trait Parse<'a>
where
    // returning Result requires both of its arguments to have
    // a known fixed size at compile-time, hence the trait bound
    Self: Sized,
{
    fn from_bytes(payload: &'a [u8]) -> Result<Self, Error>;
}

mod ip {
    // consts in a separate module to reference both in IpProtocol enum and scan_for_fragment fn,
    // since both share the same namespace of ipv6 headers;
    pub const NH_HOP_BY_HOP: u8 = 0;
    pub const NH_ICMP_V4: u8 = 1;
    pub const NH_IGMP: u8 = 2;
    pub const NH_TCP: u8 = 6;
    pub const NH_UDP: u8 = 17;
    pub const V6_IN_V4_ENCAP: u8 = 41; // ipv6 encapsulation
    pub const NH_ROUTING: u8 = 43;
    pub const NH_FRAGMENT: u8 = 44;
    pub const NH_ESP: u8 = 50;
    pub const NH_AH: u8 = 51;
    pub const NH_ICMP_V6: u8 = 58;
    pub const NH_NO_NEXT: u8 = 59;
    pub const NH_DEST_OPTS: u8 = 60;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(u8)]
    pub enum Proto {
        ICMPv4 = NH_ICMP_V4,
        IGMP = NH_IGMP,
        TCP = NH_TCP,
        UDP = NH_UDP,
        ENCAP = V6_IN_V4_ENCAP,
        ICMPv6 = NH_ICMP_V6,
        Unknown(u8),
    }

    impl From<u8> for Proto {
        fn from(v: u8) -> Self {
            match v {
                NH_ICMP_V4 => Self::ICMPv4,
                NH_IGMP => Self::IGMP,
                NH_TCP => Self::TCP,
                NH_UDP => Self::UDP,
                V6_IN_V4_ENCAP => Self::ENCAP,
                NH_ICMP_V6 => Self::ICMPv6,
                v => Self::Unknown(v),
            }
        }
    }
}

pub mod v4 {
    use super::{Error, Parse, ip};
    use crate::ethernet::HexSlice;
    use std::fmt;

    // 32 bits, or 4 bytes
    const ADDRESS_SIZE: usize = 32 / 8;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct Addr(pub [u8; ADDRESS_SIZE]);

    impl fmt::Display for Addr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            let a = self.0;
            write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3])
        }
    }

    impl From<[u8; ADDRESS_SIZE]> for Addr {
        fn from(bytes: [u8; ADDRESS_SIZE]) -> Self {
            Self(bytes)
        }
    }

    impl From<u32> for Addr {
        fn from(value: u32) -> Self {
            Self(value.to_be_bytes())
        }
    }

    pub struct Packet<'a> {
        pub src: Addr,
        pub dst: Addr,
        pub next_protocol: ip::Proto,
        ttl: u8,
        pub headers: Headers<'a>,
        pub payload: &'a [u8],
    }

    pub struct Headers<'a> {
        identification: u16,
        flags_and_fragment_offset: u16,
        header_checksum: u16,
        options: &'a [u8],
    }

    impl<'a> Parse<'a> for Packet<'a> {
        fn from_bytes(payload: &'a [u8]) -> Result<Self, Error> {
            const MIN_IPV4_HEADER_BYTES: usize = 20;

            let packet_len = payload.len();

            if packet_len < MIN_IPV4_HEADER_BYTES {
                return Err(Error::Truncated(packet_len, MIN_IPV4_HEADER_BYTES));
            }

            // networking communication always uses big endian format,
            // which is why it is also called network byte order
            let version_and_ihl = u8::from_be(payload[0]);

            const MIN_HEADER_WORDS: u8 = 5;

            if version_and_ihl & 0xF0 != 0x40 || version_and_ihl & 0x0F < MIN_HEADER_WORDS {
                // version (upper 4 bits) must always be 4
                // headers length (lower 4 bits) must be at least 5
                // https://en.wikipedia.org/wiki/IPv4
                return Err(Error::MalformedIpv4Header);
            }

            // ipv4 does not have a fixed header size due to options header
            // which is optional
            let headers_len = version_and_ihl & 0x0F;

            // parsing ip headers
            let total_len = u16::from_be_bytes(payload[2..4].try_into().unwrap()) as usize;

            let identification = u16::from_be_bytes(payload[4..6].try_into().unwrap());
            let flags_and_fragment_offset = u16::from_be_bytes(payload[6..8].try_into().unwrap());
            let ttl = u8::from_be(payload[8]);
            let next_protocol = u8::from_be(payload[9]);
            let header_checksum = u16::from_be_bytes(payload[10..12].try_into().unwrap());

            let src_address = u32::from_be_bytes(payload[12..16].try_into().unwrap());
            let dst_address = u32::from_be_bytes(payload[16..20].try_into().unwrap());

            // validate length against announced total length from headers
            if packet_len < total_len {
                return Err(Error::Truncated(packet_len, total_len));
            }

            // would never overflow because of the if guard on first byte earlier (MIN_HEADER_WORDS)
            let header_len = 4 * headers_len as usize;

            // full IPv4 header cannot exceed announced total length
            if header_len > total_len {
                return Err(Error::MalformedIpv4Header);
            }

            let ipv4_options = &payload[20..header_len];

            // size is dictated by total_len dual-byte value, thus largest possible value is 65535 including headers
            // ip packets may be fragmented by sender or router, in which case the recieving host must reassemble them
            let ipv4_payload = &payload[header_len..total_len];

            Ok(Self {
                src: src_address.into(),
                dst: dst_address.into(),
                ttl,
                next_protocol: next_protocol.into(),
                headers: Headers {
                    identification,
                    flags_and_fragment_offset,
                    header_checksum,
                    options: ipv4_options,
                },
                payload: ipv4_payload,
            })
        }
    }

    impl<'a> fmt::Display for Packet<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "IPv4[{} -> {}] ttl: {}, proto: {:?}, payload_len: {}, payload: {}",
                self.src,
                self.dst,
                self.ttl,
                self.next_protocol,
                self.payload.len(),
                HexSlice(self.payload),
            )
        }
    }
}

mod v6 {
    use super::{Error, Parse, ip};
    use crate::ethernet::HexSlice;
    use std::fmt;

    // 32 bits, or 4 bytes
    const ADDRESS_SIZE: usize = 128 / 8;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Addr(pub [u8; ADDRESS_SIZE]);

    impl From<[u8; ADDRESS_SIZE]> for Addr {
        fn from(bytes: [u8; ADDRESS_SIZE]) -> Self {
            Self(bytes)
        }
    }

    impl fmt::Display for Addr {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            for (idx, byte) in self.0.iter().enumerate() {
                if idx > 0 && idx % 2 == 0 {
                    f.write_str(":")?
                }

                write!(f, "{byte:02x}")?;
            }

            Ok(())
        }
    }

    pub struct Packet<'a> {
        pub src: Addr,
        pub dst: Addr,
        pub next_protocol: ip::Proto,
        pub payload: &'a [u8],
        pub fragmentation: Option<FragmentationMetadata>,
    }

    impl<'a> Parse<'a> for Packet<'a> {
        fn from_bytes(payload: &'a [u8]) -> Result<Self, Error> {
            const IPV6_HEADER_BYTES: usize = 40;

            let packet_len = payload.len();

            if packet_len < IPV6_HEADER_BYTES {
                return Err(Error::Truncated(packet_len, IPV6_HEADER_BYTES));
            }

            // https://en.wikipedia.org/wiki/IPv6
            // version, traffic class, flow label
            let _metadata = u32::from_be_bytes(payload[..4].try_into().unwrap()); // unused
            let payload_len = u16::from_be_bytes(payload[4..6].try_into().unwrap()) as usize;
            let next_header = u8::from_be(payload[6]);
            let _hop_limit = u8::from_be(payload[7]); // unused

            let src = Addr(payload[8..24].try_into().unwrap());
            let dst = Addr(payload[24..40].try_into().unwrap());

            let total_len = IPV6_HEADER_BYTES + payload_len;

            if packet_len < total_len {
                return Err(Error::Truncated(packet_len, total_len));
            }

            let scan = scan_for_fragment_extension(
                &payload[IPV6_HEADER_BYTES..total_len],
                next_header,
                0,
            )?;

            let ipv6_payload = &payload[scan.payload_start..total_len];

            Ok(Self {
                src,
                dst,
                next_protocol: scan.next_protocol,
                payload: ipv6_payload,
                fragmentation: scan.metadata,
            })
        }
    }

    impl<'a> fmt::Display for Packet<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "IPv6[{} -> {}] next_proto: {:?}, payload_len: {}, payload: {}",
                self.src,
                self.dst,
                self.next_protocol,
                self.payload.len(),
                HexSlice(self.payload),
            )
        }
    }

    // defragmentation machinery for ipv6
    // implementing defragmentation means merging multiple packets together based on key;
    // since payload from multiple packets must be kept alive, zero-copy borrow cannot suffice
    // and reconstructed packets must own the bytes
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FragmentKey {
        pub src: Addr,
        pub dst: Addr,
        pub identification: u32,
        pub next_protocol: ip::Proto,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FragmentationMetadata {
        pub identification: u32,
        pub fragment_offset: u16, // offset within the reassembled fragmentable part, in 8-octet units
        pub more_fragments: bool,
    }

    const FRAGMENT_HEADER_LEN: usize = 8;

    struct ExtensionScan {
        next_protocol: ip::Proto,
        metadata: Option<FragmentationMetadata>,
        payload_start: usize,
    }

    fn scan_for_fragment_extension<'a>(
        payload: &'a [u8],
        mut next_header: u8,
        mut offset: usize,
    ) -> Result<ExtensionScan, Error> {
        loop {
            match next_header {
                ip::NH_FRAGMENT => {
                    // handle fragmentation header: parse, return fragmented state
                    let header = parse_fragment_header(
                        payload
                            .get(offset..offset + FRAGMENT_HEADER_LEN)
                            .ok_or(Error::MalformedIpv6Header)?,
                    )?;

                    let metadata = FragmentationMetadata {
                        identification: header.identification,
                        fragment_offset: header.fragment_offset,
                        more_fragments: header.more_fragments,
                    };

                    return Ok(ExtensionScan {
                        metadata: Some(metadata),
                        next_protocol: header.next_protocol,
                        payload_start: offset + FRAGMENT_HEADER_LEN,
                    });
                }
                ip::NH_HOP_BY_HOP | ip::NH_ROUTING | ip::NH_DEST_OPTS => {
                    // skip without interpreting header contents (out of scope for now)
                    // and continue to the next iteration
                    next_header = payload[offset];
                    offset = skip_hdr_ext_len_header(payload, offset)?;
                }
                ip::NH_AH => {
                    // authorization header - has to be skipped in a slightly different way
                    // then continue to the next iteration
                    next_header = payload[offset];
                    offset = skip_ah(payload, offset)?;
                }
                ip::NH_ICMP_V4
                | ip::NH_IGMP
                | ip::NH_TCP
                | ip::NH_UDP
                | ip::NH_ICMP_V6
                | ip::NH_ESP
                | ip::NH_NO_NEXT => {
                    // explicit return on known next header values
                    return Ok(ExtensionScan {
                        metadata: None,
                        next_protocol: next_header.into(),
                        payload_start: offset,
                    });
                }
                _ => {
                    // unknown extension or protocol - stop walking
                    return Ok(ExtensionScan {
                        metadata: None,
                        next_protocol: next_header.into(),
                        payload_start: offset,
                    });
                }
            }
        }
    }

    // helper pure functions that valudate and skip ipv6 headers that are not used
    // by current pcap reader implementation in any way
    fn skip_hdr_ext_len_header(payload: &[u8], offset: usize) -> Result<usize, Error> {
        let remaining = payload
            .len()
            .checked_sub(offset)
            .ok_or(Error::MalformedIpv6Header)?;

        if remaining < 8 {
            return Err(Error::MalformedIpv6Header);
        }

        let hdr_ext_len = payload[offset + 1] as usize;
        let len = (hdr_ext_len + 1) * 8;

        if remaining < len {
            return Err(Error::MalformedIpv6Header);
        }

        Ok(offset + len)
    }

    fn skip_ah(payload: &[u8], offset: usize) -> Result<usize, Error> {
        let remaining = payload
            .len()
            .checked_sub(offset)
            .ok_or(Error::MalformedIpv6Header)?;

        if remaining < 4 {
            return Err(Error::MalformedIpv6Header);
        }

        let payload_len = payload[offset + 1] as usize;
        let len = (payload_len + 2) * 4;

        if remaining < len {
            return Err(Error::MalformedIpv6Header);
        }

        Ok(offset + len)
    }

    struct RawFragmentHeader {
        next_protocol: ip::Proto,
        fragment_offset: u16, // 13-bit value
        more_fragments: bool,
        identification: u32,
    }

    fn parse_fragment_header(bytes: &[u8]) -> Result<RawFragmentHeader, Error> {
        if bytes.len() != FRAGMENT_HEADER_LEN {
            return Err(Error::MalformedIpv6Header);
        }

        let next_protocol = bytes[0];
        let frag_info = u16::from_be_bytes([bytes[2], bytes[3]]);

        Ok(RawFragmentHeader {
            next_protocol: next_protocol.into(),
            fragment_offset: frag_info >> 3,
            more_fragments: (frag_info & 0x0004) != 0,
            identification: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
        })
    }
}

mod arp {
    use super::{Error, Parse, v4};
    use crate::ethernet::{EtherType, MacAddress};
    use std::fmt;

    pub struct Packet<'a> {
        pub operation: ArpOperation,
        pub protocol_type: EtherType,
        pub addresses: Addresses<'a>,
    }

    impl<'a> Parse<'a> for Packet<'a> {
        fn from_bytes(payload: &'a [u8]) -> Result<Self, Error> {
            // NOTE: generally arp may be used for different internet and link level protocols
            // rather than ipv4 + ethernet, but for the sake of simplicity, only this combination
            // is considered in this implementation for simplicity;
            // ip v6 actually usually uses Neighbor Discovery Protocol, which is built on ICMPv6,
            // for address discovery instead of arp.
            const ARP_PACKET_BYTES: usize = 28;

            match payload.len() {
                ARP_PACKET_BYTES => {
                    // indexing is safe due to enclosing match expression
                    let _hardware_type = u16::from_be_bytes(payload[0..2].try_into().unwrap()); // unused
                    let protocol_type = u16::from_be_bytes(payload[2..4].try_into().unwrap());
                    let operation = u16::from_be_bytes(payload[6..8].try_into().unwrap());

                    let addresses = match EtherType::from(protocol_type) {
                        EtherType::Ipv4 => {
                            let hardware_len = u8::from_be(payload[4]);
                            let protocol_len = u8::from_be(payload[5]);

                            // for ethernet, hardware address length (mac address) must be 6 octets
                            // for ipv4, internetwork address (ip) must be 4 octets
                            if hardware_len != 6 || protocol_len != 4 {
                                return Err(Error::MalformedArpPacket);
                            }

                            Addresses::EthernetIpv4 {
                                sender_hw_addr: MacAddress(payload[8..14].try_into().unwrap()),
                                sender_proto_addr: v4::Addr(payload[14..18].try_into().unwrap()),
                                target_hw_addr: MacAddress(payload[18..24].try_into().unwrap()),
                                target_proto_addr: v4::Addr(payload[24..28].try_into().unwrap()),
                            }
                        }
                        _ => Addresses::Raw {
                            sender_hw_addr: &payload[8..14],
                            sender_proto_addr: &payload[14..18],
                            target_hw_addr: &payload[18..24],
                            target_proto_addr: &payload[24..28],
                        },
                    };

                    Ok(Self {
                        operation: operation.into(),
                        protocol_type: EtherType::from(protocol_type),
                        addresses,
                    })
                }
                v @ 0..ARP_PACKET_BYTES => Err(Error::Truncated(v, ARP_PACKET_BYTES)),
                v => Err(Error::UnsupportedArpPacket(v)),
            }
        }
    }

    impl<'a> fmt::Display for Packet<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self.addresses {
                Addresses::EthernetIpv4 {
                    sender_proto_addr,
                    target_proto_addr,
                    ..
                } => write!(
                    f,
                    "Arp[{} -> {}] operation: {:?}, proto: {:?}",
                    sender_proto_addr, target_proto_addr, self.operation, self.protocol_type,
                ),
                Addresses::Raw { .. } => write!(
                    f,
                    "Arp[unknown address type] operation: {:?}, proto: {:?}",
                    self.operation, self.protocol_type,
                ),
            }
        }
    }

    #[derive(Debug)]
    #[repr(u16)]
    pub enum ArpOperation {
        Request = 1,
        Reply = 2,
        Unknown,
    }

    impl From<u16> for ArpOperation {
        fn from(value: u16) -> Self {
            match value {
                1 => Self::Request,
                2 => Self::Reply,
                _ => Self::Unknown,
            }
        }
    }

    pub enum Addresses<'a> {
        EthernetIpv4 {
            sender_hw_addr: MacAddress,
            sender_proto_addr: v4::Addr,
            target_hw_addr: MacAddress,
            target_proto_addr: v4::Addr,
        },
        Raw {
            sender_hw_addr: &'a [u8],
            sender_proto_addr: &'a [u8],
            target_hw_addr: &'a [u8],
            target_proto_addr: &'a [u8],
        },
    }
}
