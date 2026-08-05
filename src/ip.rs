use crate::{ethernet::EtherType, transport};

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

// Addr trait to make transport layer types generic over ip protocol
// uses a private module that only implements Sealed trait to v4/v6 addrs
pub trait Addr: private::SealedAddr {}

impl Addr for v4::Addr {}
impl Addr for v6::Addr {}

// GAT (Generic Associated Types) Pattern for ip families:
// at first, separate v4::Packet and v6::Packet types were used,
// but packing and unpacking v4/v6 variants over and over in enums
// with match arms became tedious so a Version trait, implemented for v4 and v6
// was finally defined
pub trait Version: private::SealedVersion {
    type Addr: Addr;
    type Headers<'a>;
}

mod private {
    use super::{v4, v6};
    use std::{fmt, hash};

    pub trait SealedAddr: hash::Hash + Eq + Copy + Clone + fmt::Debug + fmt::Display {}

    impl SealedAddr for v4::Addr {}
    impl SealedAddr for v6::Addr {}

    pub trait SealedVersion {}

    impl SealedVersion for v4::Version {}
    impl SealedVersion for v6::Version {}
}

pub mod markers {
    use std::fmt;

    use super::{Packet, Version, frag, v4, v6};

    // A "type constructor" encoded as a trait with a GAT
    pub trait Constructor {
        type Apply<'a, V: Version>;
    }

    pub enum Family<'a, C: Constructor> {
        Ipv4(C::Apply<'a, v4::Version>),
        Ipv6(C::Apply<'a, v6::Version>),
    }

    // generic Display implementation to reduce boilerplate match expressions
    impl<'a, C: Constructor> fmt::Display for Family<'a, C>
    where
        C::Apply<'a, v4::Version>: fmt::Display,
        C::Apply<'a, v6::Version>: fmt::Display,
    {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Family::Ipv4(v) => v.fmt(f),
                Family::Ipv6(v) => v.fmt(f),
            }
        }
    }

    pub struct PacketCtor;
    impl Constructor for PacketCtor {
        type Apply<'a, V: Version> = Packet<'a, V>;
    }

    pub struct DatagramCtor;
    impl Constructor for DatagramCtor {
        type Apply<'a, V: Version> = frag::Datagram<V>;
    }
}

// Version-agnostic IP packet using GAT pattern
pub struct Packet<'a, V: Version> {
    pub src: V::Addr,
    pub dst: V::Addr,
    pub next_protocol: Proto,
    pub headers: V::Headers<'a>,
    pub payload: &'a [u8],
    ttl: u8,
}

trait Parse<'a>
where
    // returning Result requires both of its arguments to have
    // a known fixed size at compile-time, hence the trait bound
    Self: Sized,
{
    type Error;
    fn from_bytes(payload: &'a [u8]) -> Result<Self, Self::Error>;
}

pub enum NetworkPacket<'a> {
    Ipv4(v4::Packet<'a>),
    Ipv6(v6::Packet<'a>),
    Arp(arp::Packet),
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

pub struct NetworkReassembler {
    v4: frag::DatagramReassembler<v4::Version>,
    v6: frag::DatagramReassembler<v6::Version>,
}

pub type IpPacket<'a> = markers::Family<'a, markers::PacketCtor>;

/// Light facade for DataframReassembler that produces proto-agnostic ReassemblyResult
impl NetworkReassembler {
    pub fn with_reassemblers(
        v4: frag::DatagramReassembler<v4::Version>,
        v6: frag::DatagramReassembler<v6::Version>,
    ) -> Self {
        Self { v4, v6 }
    }

    pub fn process(&mut self, packet: &IpPacket<'_>) -> ReassemblyResult {
        use markers::Family;

        match packet {
            Family::Ipv4(p) => Self::map(p, &mut self.v4, Family::Ipv4),
            Family::Ipv6(p) => Self::map(p, &mut self.v6, Family::Ipv6),
        }
    }

    fn map<V: Version>(
        packet: &Packet<'_, V>,
        reassembler: &mut frag::DatagramReassembler<V>,
        convert: impl FnOnce(frag::Datagram<V>) -> Reassembled,
    ) -> ReassemblyResult
    // fragmentable is only implemented for the concrete aliases (v4::Packer, v6::Packer),
    // not for arbitrary V: Version. In a generic map, V: Version alone does not imply that bound
    // fix: add the missing bound on map
    where
        for<'a> Packet<'a, V>: frag::Fragmentable<V>,
    {
        match reassembler.process(packet) {
            frag::ReassemblyResult::Complete(d) | frag::ReassemblyResult::NotFragmented(d) => {
                ReassemblyResult::Ready(convert(d))
            }
            frag::ReassemblyResult::Incomplete => ReassemblyResult::Incomplete,
            frag::ReassemblyResult::Rejected(e) => ReassemblyResult::Rejected(e),
        }
    }
}
impl Default for NetworkReassembler {
    fn default() -> Self {
        Self::with_reassemblers(
            frag::DatagramReassembler::default(),
            frag::DatagramReassembler::default(),
        )
    }
}

pub enum ReassemblyResult {
    Ready(Reassembled),
    Incomplete,
    Rejected(frag::Error),
    NotIp,
}

// 'static is a placeholder: DatagramCtorMarker::Apply ignores the lifetime.
pub type Reassembled = markers::Family<'static, markers::DatagramCtor>;

impl Reassembled {
    pub fn parse_transport(self) -> Result<transport::Packet, transport::Error> {
        match self {
            markers::Family::Ipv4(v) => {
                transport::Segment::parse(v.id.next_protocol, v.id.src, v.id.dst, v.payload)
                    .map(markers::Family::Ipv4)
            }
            markers::Family::Ipv6(v) => {
                transport::Segment::parse(v.id.next_protocol, v.id.src, v.id.dst, v.payload)
                    .map(markers::Family::Ipv6)
            }
        }
    }
}

mod proto {
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
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Proto {
    ICMPv4 = proto::NH_ICMP_V4,
    IGMP = proto::NH_IGMP,
    TCP = proto::NH_TCP,
    UDP = proto::NH_UDP,
    ENCAP = proto::V6_IN_V4_ENCAP,
    ICMPv6 = proto::NH_ICMP_V6,
    Unknown(u8),
}

impl From<u8> for Proto {
    fn from(v: u8) -> Self {
        match v {
            proto::NH_ICMP_V4 => Self::ICMPv4,
            proto::NH_IGMP => Self::IGMP,
            proto::NH_TCP => Self::TCP,
            proto::NH_UDP => Self::UDP,
            proto::V6_IN_V4_ENCAP => Self::ENCAP,
            proto::NH_ICMP_V6 => Self::ICMPv6,
            v => Self::Unknown(v),
        }
    }
}

pub mod v4 {
    use super::{Error, Parse, Proto, frag, frag::Fragmentable};
    use std::fmt;

    pub struct Version;

    impl super::Version for Version {
        type Addr = Addr;
        type Headers<'a> = Headers<'a>;
    }

    // 32 bits, or 4 bytes
    const ADDRESS_SIZE: usize = 32 / 8;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

    pub type Packet<'a> = super::Packet<'a, Version>;

    pub struct Headers<'a> {
        identification: u16,
        flags_and_fragment_offset: u16,
        _header_checksum: u16,
        _options: &'a [u8],
    }

    impl<'a> Parse<'a> for Packet<'a> {
        type Error = Error;

        fn from_bytes(payload: &'a [u8]) -> Result<Self, Self::Error> {
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
                    _header_checksum: header_checksum,
                    _options: ipv4_options,
                },
                payload: ipv4_payload,
            })
        }
    }

    impl<'a> fmt::Display for Packet<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use crate::slices::Hex;

            write!(
                f,
                "IPv4[{} -> {}] ttl: {}, proto: {:?}, fragmented: {}, payload_len: {}, payload: {}",
                self.src,
                self.dst,
                self.ttl,
                self.next_protocol,
                self.is_fragmented(),
                self.payload.len(),
                Hex(self.payload),
            )
        }
    }

    impl<'a> frag::Fragmentable<Version> for Packet<'a> {
        fn fragment_key(&self) -> Option<(frag::FragmentKey<Addr>, frag::FragmentInfo)> {
            // only return a key if this packet is actually fragmented
            let flags = self.headers.flags_and_fragment_offset;

            // note that ipv4 stores offset in lower 13 bits of this 2-byte header
            // while ipv6 stores the same 13-bit offset in upper-bits of its fragment extension header
            let fragment_offset_octets = flags & 0x1FFF; // lower 13 bits
            let more_fragments = (flags & 0x2000) != 0; // bit 13 (MF flag)

            // if offset is 0 and MF is false, this is a complete unfragmented packet
            if fragment_offset_octets == 0 && !more_fragments {
                return None;
            }

            Some((
                frag::FragmentKey {
                    datagram: self.datagram_id(),
                    identification: self.headers.identification as u32, // pad to u32 to match IPv6
                },
                frag::FragmentInfo {
                    offset_octets: fragment_offset_octets,
                    has_more: more_fragments,
                },
            ))
        }

        fn payload(&self) -> &[u8] {
            self.payload
        }

        fn src(&self) -> Addr {
            self.src
        }

        fn dst(&self) -> Addr {
            self.dst
        }

        fn next_protocol(&self) -> Proto {
            self.next_protocol
        }
    }
}

pub mod v6 {
    use super::{Error, Parse, Proto, frag};
    use crate::{ip::frag::Fragmentable, slices::Hex};
    use std::fmt;

    pub struct Version;

    impl super::Version for Version {
        type Addr = Addr;
        type Headers<'a> = Option<FragmentationMetadata>;
    }

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

    pub type Packet<'a> = super::Packet<'a, Version>;

    impl<'a> Parse<'a> for Packet<'a> {
        type Error = Error;

        fn from_bytes(payload: &'a [u8]) -> Result<Self, Self::Error> {
            const IPV6_HEADER_BYTES: usize = 40;

            let packet_len = payload.len();

            if packet_len < IPV6_HEADER_BYTES {
                return Err(Error::Truncated(packet_len, IPV6_HEADER_BYTES));
            }

            // quickly validate the version nibble is 6;
            if (payload[0] >> 4) != 6 {
                return Err(Error::MalformedIpv6Header);
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
                headers: scan.metadata,
                ttl: 0,
            })
        }
    }

    impl<'a> fmt::Display for Packet<'a> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "IPv6[{} -> {}] next_proto: {:?}, fragmented: {}, payload_len: {}, payload: {}",
                self.src,
                self.dst,
                self.next_protocol,
                self.is_fragmented(),
                self.payload.len(),
                Hex(self.payload),
            )
        }
    }

    // defragmentation machinery for ipv6
    // implementing defragmentation means merging multiple packets together based on key;
    // since payload from multiple packets must be kept alive, zero-copy borrow cannot suffice
    // and reconstructed packets must own the bytes
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct FragmentationMetadata {
        pub identification: u32,
        pub fragment_offset_octets: u16, // offset within the reassembled fragmentable part, in 8-octet units
        pub more_fragments: bool,
    }

    const FRAGMENT_HEADER_LEN_BYTES: usize = 8;

    struct ExtensionScan {
        next_protocol: Proto,
        metadata: Option<FragmentationMetadata>,
        payload_start: usize,
    }

    fn scan_for_fragment_extension<'a>(
        payload: &'a [u8],
        mut next_header: u8,
        mut offset: usize,
    ) -> Result<ExtensionScan, Error> {
        use super::proto;

        loop {
            match next_header {
                proto::NH_FRAGMENT => {
                    // handle fragmentation header: parse, return fragmented state
                    let header = parse_fragment_header(
                        payload
                            .get(offset..offset + FRAGMENT_HEADER_LEN_BYTES)
                            .ok_or(Error::MalformedIpv6Header)?,
                    )?;

                    let metadata = FragmentationMetadata {
                        identification: header.identification,
                        fragment_offset_octets: header.fragment_offset_octets,
                        more_fragments: header.more_fragments,
                    };

                    return Ok(ExtensionScan {
                        metadata: Some(metadata),
                        next_protocol: header.next_protocol,
                        payload_start: offset + FRAGMENT_HEADER_LEN_BYTES,
                    });
                }
                proto::NH_HOP_BY_HOP | proto::NH_ROUTING | proto::NH_DEST_OPTS => {
                    // skip without interpreting header contents (out of scope for now)
                    // and continue to the next iteration
                    next_header = payload[offset];
                    offset = skip_hdr_ext_len_header(payload, offset)?;
                }
                proto::NH_AH => {
                    // authorization header - has to be skipped in a slightly different way
                    // then continue to the next iteration
                    next_header = payload[offset];
                    offset = skip_ah(payload, offset)?;
                }
                proto::NH_ICMP_V4
                | proto::NH_IGMP
                | proto::NH_TCP
                | proto::NH_UDP
                | proto::NH_ICMP_V6
                | proto::NH_ESP
                | proto::NH_NO_NEXT => {
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

    // helper pure functions that validate and skip ipv6 headers that are not used
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
        next_protocol: Proto,
        fragment_offset_octets: u16, // 13-bit value
        more_fragments: bool,
        identification: u32,
    }

    fn parse_fragment_header(bytes: &[u8]) -> Result<RawFragmentHeader, Error> {
        if bytes.len() != FRAGMENT_HEADER_LEN_BYTES {
            return Err(Error::MalformedIpv6Header);
        }

        let next_protocol = bytes[0];
        let frag_info = u16::from_be_bytes([bytes[2], bytes[3]]);

        // for IPv6, octet offset is the upper 13 bits
        // for IPv4, octet offset is the lower 13 bits
        Ok(RawFragmentHeader {
            next_protocol: next_protocol.into(),
            fragment_offset_octets: frag_info >> 3, // upper 13 bits
            more_fragments: (frag_info & 0x0004) != 0,
            identification: u32::from_be_bytes(bytes[4..8].try_into().unwrap()),
        })
    }

    impl<'a> frag::Fragmentable<Version> for Packet<'a> {
        fn fragment_key(&self) -> Option<(frag::FragmentKey<Addr>, frag::FragmentInfo)> {
            match self.headers {
                None => None,
                Some(v) => Some((
                    frag::FragmentKey {
                        datagram: self.datagram_id(),
                        identification: v.identification,
                    },
                    frag::FragmentInfo {
                        offset_octets: v.fragment_offset_octets,
                        has_more: v.more_fragments,
                    },
                )),
            }
        }

        fn is_fragmented(&self) -> bool {
            self.headers.is_some()
        }

        fn payload(&self) -> &[u8] {
            self.payload
        }

        fn src(&self) -> Addr {
            self.src
        }

        fn dst(&self) -> Addr {
            self.dst
        }

        fn next_protocol(&self) -> Proto {
            self.next_protocol
        }
    }
}

pub mod arp {
    use super::{Error, Parse, v4};
    use crate::ethernet::{EtherType, MacAddress};
    use std::fmt;

    pub struct Packet {
        pub operation: ArpOperation,
        pub protocol_type: EtherType,
        pub addresses: Addresses,
    }

    impl<'a> Parse<'a> for Packet {
        type Error = Error;

        fn from_bytes(payload: &'a [u8]) -> Result<Self, Self::Error> {
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
                        _ => Addresses::Raw,
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

    impl<'a> fmt::Display for Packet {
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

    pub enum Addresses {
        EthernetIpv4 {
            sender_hw_addr: MacAddress,
            target_hw_addr: MacAddress,
            sender_proto_addr: v4::Addr,
            target_proto_addr: v4::Addr,
        },
        Raw,
    }
}

pub mod frag {
    use super::Proto;
    use crate::{ip, slices};

    use std::{
        collections::BTreeMap,
        fmt::{self, Display},
        hash::Hash,
        num::NonZeroUsize,
    };
    use thiserror::Error;

    use lru::LruCache;

    #[derive(Error, Debug)]
    pub enum Error {
        #[error("fragment payload is not 8-aligned: {0} bytes")]
        UnalignedPayload(usize),
        #[error("duplicate offset fragment found: offset: {0}")]
        DuplicateFragmentOffset(u16),
        #[error("incomplete buffer: total_len not known")]
        IncompleteFragment,
        #[error("too many fragments: {0}")]
        TooManyFragments(usize),
    }
    // Fragmentable defines interface for fragment reassembly
    pub trait Fragmentable<V: ip::Version> {
        fn fragment_key(&self) -> Option<(FragmentKey<V::Addr>, FragmentInfo)>;

        fn is_fragmented(&self) -> bool {
            self.fragment_key().is_some()
        }

        fn payload(&self) -> &[u8];
        fn src(&self) -> V::Addr;
        fn dst(&self) -> V::Addr;
        fn next_protocol(&self) -> Proto;

        fn datagram_id(&self) -> DatagramId<V::Addr> {
            DatagramId {
                src: self.src(),
                dst: self.dst(),
                next_protocol: self.next_protocol(),
            }
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct DatagramId<A: ip::Addr> {
        pub src: A,
        pub dst: A,
        pub next_protocol: Proto,
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct FragmentKey<A: ip::Addr> {
        pub datagram: DatagramId<A>,
        pub identification: u32,
    }

    pub struct FragmentInfo {
        pub offset_octets: Offset,
        pub has_more: bool,
    }

    type Offset = u16;
    type Payload = Vec<u8>;

    pub struct DatagramReassemblyBuffer {
        fragments: BTreeMap<Offset, Payload>,
        total_len: Option<usize>,
        max_fragments: NonZeroUsize,
    }

    impl DatagramReassemblyBuffer {
        pub fn new(max_fragments: NonZeroUsize) -> Self {
            Self {
                fragments: BTreeMap::default(),
                total_len: None,
                max_fragments,
            }
        }

        pub fn insert(&mut self, info: FragmentInfo, payload: &[u8]) -> Result<(), Error> {
            if info.has_more && payload.len() % 8 != 0 {
                return Err(Error::UnalignedPayload(payload.len()));
            }

            let offset_octets = info.offset_octets;

            // NOTE: when a later fragment arrives with the same offset_octets as one already in the buffer,
            // we have 3 reasonable choices: ignore it (implemented below), overwrite (simple, less secure)
            // or reject and reset the whole reassembly buffer (strict, safest, may break retransmissions)
            if self.fragments.contains_key(&offset_octets) {
                return Err(Error::DuplicateFragmentOffset(offset_octets));
            }

            self.fragments.insert(offset_octets, payload.to_vec());

            // handle fragment buffer overflow
            if self.fragments.len() > self.max_fragments.get() {
                return Err(Error::TooManyFragments(self.fragments.len()));
            }

            if !info.has_more {
                // this is the last fragment thus we know the total length
                let offset = (offset_octets as usize) << 3;
                let end = offset + payload.len();

                self.total_len = Some(end);
            }

            Ok(())
        }

        fn covers_range(&self) -> bool {
            // each fragments has an offset and a corresponding payload
            // to ensure that current buffer contains all fragments after the final fragment arrives,
            // we must iterate over fragments, and check for offset contiguity:
            // i.e., offset + payload_len must match next_offset
            // fragments are always 8-padded, except for the last one
            match self.fragments.iter().fold(
                Ok(0usize),
                |acc, (&fragment_start_octets, payload)| {
                    let fragment_start = (fragment_start_octets as usize) << 3;

                    match acc {
                        Err(e) => Err(e),
                        Ok(v) => {
                            // fragments must be contiguous
                            if fragment_start != v {
                                Err(())
                            } else {
                                Ok(fragment_start + payload.len())
                            }
                        }
                    }
                },
            ) {
                Ok(_) => true,
                _ => false,
            }
        }

        fn assemble(&self) -> Option<Payload> {
            let Some(total_len) = self.total_len else {
                return None;
            };

            if !self.covers_range() {
                return None;
            }

            // join payloads from
            let mut out = Vec::with_capacity(total_len);

            for payload in self.fragments.values() {
                out.extend_from_slice(payload);
            }

            Some(out)
        }
    }

    pub struct DatagramReassemblyPolicy {
        pub max_buffers: NonZeroUsize,
        pub max_fragments_per_buffer: NonZeroUsize,
    }

    impl Default for DatagramReassemblyPolicy {
        fn default() -> Self {
            Self {
                max_buffers: const { NonZeroUsize::new(1000).unwrap() },
                max_fragments_per_buffer: const { NonZeroUsize::new(500).unwrap() },
            }
        }
    }

    pub struct DatagramReassembler<V: ip::Version> {
        buffers: LruCache<FragmentKey<V::Addr>, DatagramReassemblyBuffer>,
        max_fragments_per_buffer: NonZeroUsize,
    }

    impl<V: ip::Version> Default for DatagramReassembler<V> {
        fn default() -> Self {
            Self::with_policy(DatagramReassemblyPolicy::default())
        }
    }

    impl<V: ip::Version> DatagramReassembler<V> {
        pub fn with_policy(policy: DatagramReassemblyPolicy) -> Self {
            Self {
                buffers: LruCache::new(policy.max_buffers),
                max_fragments_per_buffer: policy.max_fragments_per_buffer,
            }
        }

        pub fn process<F>(&mut self, packet: &F) -> ReassemblyResult<V>
        where
            F: Fragmentable<V>,
        {
            let Some((key, info)) = packet.fragment_key() else {
                return ReassemblyResult::NotFragmented(Datagram {
                    id: packet.datagram_id(),
                    payload: packet.payload().to_vec(),
                });
            };

            let buffer = self.buffers.get_or_insert_mut(key.clone(), || {
                DatagramReassemblyBuffer::new(self.max_fragments_per_buffer)
            });

            if let Err(v) = buffer.insert(info, packet.payload()) {
                return ReassemblyResult::Rejected(v);
            }

            match buffer.assemble() {
                Some(b) => {
                    self.buffers.pop(&key);
                    ReassemblyResult::Complete(Datagram {
                        id: key.datagram,
                        payload: b,
                    })
                }
                None => ReassemblyResult::Incomplete,
            }
        }
    }

    #[derive(Debug)]
    pub struct Datagram<V: ip::Version> {
        pub id: DatagramId<V::Addr>,
        pub payload: Payload,
    }

    impl<A: ip::Version> Display for Datagram<A> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                f,
                "[{} -> {}] proto: {:?}, payload_len: {}, payload: {}",
                self.id.src,
                self.id.dst,
                self.id.next_protocol,
                self.payload.len(),
                slices::Hex(self.payload.as_slice()),
            )
        }
    }

    pub enum ReassemblyResult<V: ip::Version> {
        /// A complete datagram was reassembled
        Complete(Datagram<V>),
        /// Fragments were accepted but reassembly is incomplete
        Incomplete,
        /// This packet was not fragmented; pass it through
        NotFragmented(Datagram<V>),
        /// Rejected due to invalid fragment or duplicate
        Rejected(Error),
    }
}
