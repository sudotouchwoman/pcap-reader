use std::fmt;

use thiserror::Error;

use crate::ethernet::{EtherType, HexSlice, MacAddress};

#[derive(Error, Debug)]
pub enum Error {
    #[error("truncated packet: got {0} bytes, expected {1}")]
    Truncated(usize, usize),
    #[error("arp packet has invalid or unsupported size: {0}")]
    UnsupportedArpPacket(usize),
    #[error("malformed ipv4 header")]
    MalformedIpv4Header,
    #[error("malformed arp packet")]
    MalformedArpPacket,
    #[error("unknown ether type: {0:x}")]
    UnknownEtherType(u16),
}

pub enum NetworkPacket<'a> {
    Ipv4(Ipv4Packet<'a>),
    Ipv6(Ipv6Packet<'a>),
    Arp(ArpPacket<'a>),
}

impl<'a> NetworkPacket<'a> {
    pub fn parse(ether_type: EtherType, payload: &'a [u8]) -> Result<Self, Error> {
        match ether_type {
            EtherType::Ipv4 => Ipv4Packet::from_bytes(payload).map(Self::Ipv4),
            EtherType::Ipv6 => Ipv6Packet::from_bytes(payload).map(Self::Ipv6),
            EtherType::Arp => ArpPacket::from_bytes(payload).map(Self::Arp),
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

// 32 bits, or 4 bytes
const IPV4_ADDRESS_SIZE: usize = 32 / 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Address(pub [u8; IPV4_ADDRESS_SIZE]);

impl fmt::Display for Ipv4Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = self.0;
        write!(f, "{}.{}.{}.{}", a[0], a[1], a[2], a[3])
    }
}

impl From<[u8; IPV4_ADDRESS_SIZE]> for Ipv4Address {
    fn from(bytes: [u8; IPV4_ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }
}

impl From<u32> for Ipv4Address {
    fn from(value: u32) -> Self {
        Self(value.to_be_bytes())
    }
}

// 32 bits, or 4 bytes
const IPV6_ADDRESS_SIZE: usize = 128 / 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Address(pub [u8; IPV6_ADDRESS_SIZE]);

impl From<[u8; IPV6_ADDRESS_SIZE]> for Ipv6Address {
    fn from(bytes: [u8; IPV6_ADDRESS_SIZE]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Ipv6Address {
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

pub type IpProtocol = u8;

pub struct Ipv4Packet<'a> {
    pub src: Ipv4Address,
    pub dst: Ipv4Address,
    pub next_protocol: IpProtocol,
    ttl: u8,
    pub headers: Ipv4Headers<'a>,
    pub payload: &'a [u8],
}

pub struct Ipv4Headers<'a> {
    identification: u16,
    flags_and_fragment_offset: u16,
    header_checksum: u16,
    options: &'a [u8],
}

impl<'a> Parse<'a> for Ipv4Packet<'a> {
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

        // would never overflow because of the if guard on first byte earlier
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
            next_protocol,
            headers: Ipv4Headers {
                identification,
                flags_and_fragment_offset,
                header_checksum,
                options: ipv4_options,
            },
            payload: ipv4_payload,
        })
    }
}

impl<'a> fmt::Display for Ipv4Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv4[{} -> {}] ttl: {}, proto: {}, payload_len: {}, payload: {}",
            self.src,
            self.dst,
            self.ttl,
            self.next_protocol,
            self.payload.len(),
            HexSlice(self.payload),
        )
    }
}

pub struct Ipv6Packet<'a> {
    pub src: Ipv6Address,
    pub dst: Ipv6Address,
    pub next_protocol: IpProtocol,
    pub hop_limit: u8,
    pub payload: &'a [u8],
}

impl<'a> Parse<'a> for Ipv6Packet<'a> {
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
        let hop_limit = u8::from_be(payload[7]); // unused

        let src = Ipv6Address(payload[8..8 + IPV6_ADDRESS_SIZE].try_into().unwrap());
        let dst = Ipv6Address(payload[24..24 + IPV6_ADDRESS_SIZE].try_into().unwrap());

        let total_len = IPV6_HEADER_BYTES + payload_len;

        if packet_len < total_len {
            return Err(Error::Truncated(packet_len, total_len));
        }

        let ipv6_payload = &payload[IPV6_HEADER_BYTES..total_len];

        Ok(Self {
            src,
            dst,
            next_protocol: next_header,
            hop_limit,
            payload: ipv6_payload,
        })
    }
}

impl<'a> fmt::Display for Ipv6Packet<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "IPv6[{} -> {}] hop_limit: {}, proto: {}, payload_len {}: payload: {}",
            self.src,
            self.dst,
            self.hop_limit,
            self.next_protocol,
            self.payload.len(),
            HexSlice(self.payload),
        )
    }
}

pub struct ArpPacket<'a> {
    pub operation: ArpOperation,
    pub protocol_type: EtherType,
    pub addresses: ArpAddresses<'a>,
}

impl<'a> Parse<'a> for ArpPacket<'a> {
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

                        ArpAddresses::EthernetIpv4 {
                            sender_hw_addr: MacAddress(payload[8..14].try_into().unwrap()),
                            sender_proto_addr: Ipv4Address(payload[14..18].try_into().unwrap()),
                            target_hw_addr: MacAddress(payload[18..24].try_into().unwrap()),
                            target_proto_addr: Ipv4Address(payload[24..28].try_into().unwrap()),
                        }
                    }
                    _ => ArpAddresses::Raw {
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

impl<'a> fmt::Display for ArpPacket<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.addresses {
            ArpAddresses::EthernetIpv4 {
                sender_hw_addr,
                sender_proto_addr,
                target_hw_addr,
                target_proto_addr,
            } => write!(
                f,
                "Arp[{} ({}) -> {} ({})] operation: {:?}, proto: {:?}",
                sender_proto_addr,
                sender_hw_addr,
                target_proto_addr,
                target_hw_addr,
                self.operation,
                self.protocol_type,
            ),
            ArpAddresses::Raw { .. } => write!(
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
    Unknown(u16),
}

impl From<u16> for ArpOperation {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::Request,
            2 => Self::Reply,
            v => Self::Unknown(v),
        }
    }
}

pub enum ArpAddresses<'a> {
    EthernetIpv4 {
        sender_hw_addr: MacAddress,
        sender_proto_addr: Ipv4Address,
        target_hw_addr: MacAddress,
        target_proto_addr: Ipv4Address,
    },
    Raw {
        sender_hw_addr: &'a [u8],
        sender_proto_addr: &'a [u8],
        target_hw_addr: &'a [u8],
        target_proto_addr: &'a [u8],
    },
}
