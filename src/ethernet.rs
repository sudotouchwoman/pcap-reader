use thiserror::Error;

use std::fmt;

// parsing implementation for ethernet frames
// it is assumed that frames were parsed using the PcapReader but the logic is still decoupled

// https://wiki.wireshark.org/Ethernet
// https://external-content.duckduckgo.com/iu/?u=https%3A%2F%2Fcdn.comparitech.com%2Fwp-content%2Fuploads%2F2021%2F02%2FOSI-to-TCPIP-stack.jpg&f=1&nofb=1&ipt=26a4d632c8d209e1b78aac0a90375d1f9e2077f76f1427ca9f539e2964373c01

// TODO: implement parsing logic for ethernet frames:
// 1) check that pcap frame is ethernet (look at link type) - we would only support ethernet for now
// 2) validate ethernet frame header (has valid minimal length)
// 3) retrieve src, dst mac addresses and payload
// at this point, we have parsed ethernet frame and know its payload
// 4) based on the EtherType field, choose the "next protocol" decoder
// 5) only decode IPv4 for now, return error for other protocols for now
// at this point, we have parsed IPv4 packet: src, dst ip addresses
// 6) decode TCP header (protocol - TCP/UDP, port number) and payload

#[derive(Error, Debug)]
pub enum Error {
    #[error("truncated frame")]
    Truncated,
    #[error("unknown frame type: {0}")]
    UnknownFrameType(u16),
}

const ETHER_PAYLOAD_OFFSET: usize = 14;
const VLAN_TAGGED_OFFSET: usize = ETHER_PAYLOAD_OFFSET + 4;

pub const MAC_SIZE: usize = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress(pub [u8; MAC_SIZE]);

impl From<[u8; MAC_SIZE]> for MacAddress {
    fn from(bytes: [u8; MAC_SIZE]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5]
        )
    }
}

trait Parse<'a> {
    fn from_bytes(ether_type: u16, payload: &'a [u8]) -> Result<LinkFrame<'a>, Error>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkFrameKind {
    Ethernet,
    VlanTagged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EtherType {
    Ipv4,
    Ipv6,
    Arp,
    Other(u16),
}

impl From<u16> for EtherType {
    fn from(value: u16) -> Self {
        match value {
            0x0800 => Self::Ipv4,
            0x0806 => Self::Arp,
            0x86DD => Self::Ipv6,
            v => Self::Other(v),
        }
    }
}

pub struct LinkFrame<'a> {
    pub kind: LinkFrameKind,
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub ether_type: EtherType,
    pub payload: &'a [u8],
}

impl<'a> LinkFrame<'a> {
    pub fn parse(payload: &'a [u8]) -> Result<Self, Error> {
        const ETHER_TYPE_OFFSET: usize = 14;

        if payload.len() < ETHER_TYPE_OFFSET {
            return Err(Error::Truncated);
        }

        // here and in the literals below .unwrap() is safe because size checks
        // are always performed in advance
        let ether_type = u16::from_be_bytes(payload[12..14].try_into().unwrap());

        match ether_type {
            0x8100 | 0x88A8 => VlanTaggedFrame::from_bytes(ether_type, payload),
            0x0800..=0xFFFF => EthernetFrame::from_bytes(ether_type, payload),
            _ => Err(Error::UnknownFrameType(ether_type)),
        }
    }
}

impl fmt::Display for LinkFrame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?}: [{} => {}] proto: {:?}",
            self.kind, self.src_mac, self.dst_mac, self.ether_type,
        )
    }
}

// EthernetFrame and VlanTaggedFrame are empty struct markers that impl Parse
// and decouple logic from the base LinkFrame type
pub struct EthernetFrame;
pub struct VlanTaggedFrame;

impl<'a> Parse<'a> for EthernetFrame {
    fn from_bytes(ether_type: u16, payload: &'a [u8]) -> Result<LinkFrame<'a>, Error> {
        if payload.len() < ETHER_PAYLOAD_OFFSET {
            return Err(Error::Truncated);
        }

        // standard ethernet 2
        Ok(LinkFrame {
            kind: LinkFrameKind::Ethernet,
            dst_mac: MacAddress(payload[0..6].try_into().unwrap()),
            src_mac: MacAddress(payload[6..12].try_into().unwrap()),
            ether_type: ether_type.into(),
            payload: &payload[ETHER_PAYLOAD_OFFSET..],
        })
    }
}

impl<'a> Parse<'a> for VlanTaggedFrame {
    fn from_bytes(_: u16, payload: &'a [u8]) -> Result<LinkFrame<'a>, Error> {
        if payload.len() < VLAN_TAGGED_OFFSET {
            return Err(Error::Truncated);
        }

        // for VLAN-tagged frames, inner ether type is stored inside these tags
        // (see tests below, thus ether_type should be taken from bytes 16..18)
        Ok(LinkFrame {
            kind: LinkFrameKind::VlanTagged,
            dst_mac: MacAddress(payload[0..6].try_into().unwrap()),
            src_mac: MacAddress(payload[6..12].try_into().unwrap()),
            ether_type: u16::from_be_bytes(payload[16..18].try_into().unwrap()).into(),
            payload: &payload[VLAN_TAGGED_OFFSET..],
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn parse_ethernet_frame() {
        const ETHER_FRAME: [u8; ETHER_PAYLOAD_OFFSET + 6] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC: 00:11:22:33:44:55
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Source MAC: AA:BB:CC:DD:EE:FF
            0x08, 0x00, // EtherType (2 bytes, big-endian): 0x0800 = IPv4
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Payload (6 bytes) - minimal test data
        ];

        let f = LinkFrame::parse(&ETHER_FRAME).unwrap();
        assert_eq!(f.kind, LinkFrameKind::Ethernet);
        assert_eq!(f.dst_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into());
        assert_eq!(f.src_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].into());
        assert_eq!(f.ether_type, EtherType::Ipv4);
        assert_eq!(f.payload, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);

        const TRUNCATED_FRAME: [u8; 10] =
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB, 0xCC, 0xDD];

        assert_matches!(
            LinkFrame::parse(&TRUNCATED_FRAME).err(),
            Some(Error::Truncated)
        );

        const VLAN_FRAME: [u8; VLAN_TAGGED_OFFSET + 4] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC: 00:11:22:33:44:55
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Source MAC: AA:BB:CC:DD:EE:FF
            0x81, 0x00, // EtherType: 0x8100 = VLAN-tagged
            // VLAN tag (2 bytes: PCP + CFI + VLAN ID) + inner EtherType
            0x00, 0x01, 0x08, 0x00, // VLAN tag
            0x01, 0x02, 0x03, 0x04, // Payload (4 bytes)
        ];

        let f = LinkFrame::parse(&VLAN_FRAME).unwrap();
        assert_eq!(f.kind, LinkFrameKind::VlanTagged);
        assert_eq!(f.dst_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into());
        assert_eq!(f.src_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].into());
        assert_eq!(f.ether_type, EtherType::Ipv4);
        assert_eq!(f.payload, [0x01, 0x02, 0x03, 0x04]);
    }
}
