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

const MAC_SIZE: usize = 6;

const ETHER_PAYLOAD_OFFSET: usize = 14;
const VLAN_TAGGED_OFFSET: usize = ETHER_PAYLOAD_OFFSET + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddress([u8; MAC_SIZE]);
impl From<[u8; 6]> for MacAddress {
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

pub struct LinkFrame<'a> {
    src_mac: MacAddress,
    dst_mac: MacAddress,
    ether_type: u16,
    payload: &'a [u8],
}

pub enum ParsedLinkFrame<'a> {
    Ethernet(LinkFrame<'a>),
    VlanTagged(LinkFrame<'a>),
}

impl<'a> ParsedLinkFrame<'a> {
    pub fn parse(payload: &'a [u8]) -> Result<Self, Error> {
        if payload.len() < ETHER_PAYLOAD_OFFSET {
            return Err(Error::Truncated);
        }

        // here and in the literals below .unwrap() is safe because size checks
        // are always performed in advance
        let ether_type = u16::from_be_bytes(payload[12..14].try_into().unwrap());

        match ether_type {
            0x8100 | 0x88A8 => {
                // VLAN-tagged
                if payload.len() < VLAN_TAGGED_OFFSET {
                    return Err(Error::Truncated);
                }

                // for VLAN-tagged frames, inner ether type is stored inside these tags
                // (see tests below, thus ether_type should be taken from bytes 16..18)
                Ok(Self::VlanTagged(LinkFrame {
                    dst_mac: MacAddress(payload[0..6].try_into().unwrap()),
                    src_mac: MacAddress(payload[6..12].try_into().unwrap()),
                    ether_type: u16::from_be_bytes(payload[16..18].try_into().unwrap()),
                    payload: &payload[VLAN_TAGGED_OFFSET..],
                }))
            }

            0x0800..=0xFFFF => {
                // standard ethernet 2
                Ok(Self::Ethernet(LinkFrame {
                    dst_mac: MacAddress(payload[0..6].try_into().unwrap()),
                    src_mac: MacAddress(payload[6..12].try_into().unwrap()),
                    ether_type,
                    payload: &payload[ETHER_PAYLOAD_OFFSET..],
                }))
            }

            _ => Err(Error::UnknownFrameType(ether_type)),
        }
    }

    fn frame(&self) -> &LinkFrame<'a> {
        match self {
            Self::Ethernet(frame) | Self::VlanTagged(frame) => frame,
        }
    }
    fn kind(&self) -> &'static str {
        match self {
            Self::Ethernet(_) => "Eth2",
            Self::VlanTagged(_) => "VlanTagged",
        }
    }
}

impl fmt::Display for ParsedLinkFrame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let frame = self.frame();

        write!(
            f,
            "{}: [{} => {}] ether_type: {:#08x} payload: {}",
            self.kind(),
            frame.src_mac,
            frame.dst_mac,
            frame.ether_type,
            HexSlice(frame.payload),
        )
    }
}

struct HexSlice<'a>(&'a [u8]);
impl fmt::Display for HexSlice<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (idx, byte) in self.0.iter().enumerate() {
            if idx > 0 {
                f.write_str(":")?;
            }
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ethernet_frame() {
        const ETHER_FRAME: [u8; ETHER_PAYLOAD_OFFSET + 6] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC: 00:11:22:33:44:55
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Source MAC: AA:BB:CC:DD:EE:FF
            0x08, 0x00, // EtherType (2 bytes, big-endian): 0x0800 = IPv4
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, // Payload (6 bytes) - minimal test data
        ];

        assert!(matches!(
            ParsedLinkFrame::parse(&ETHER_FRAME),
            Ok(ParsedLinkFrame::Ethernet(_))
        ));

        if let Ok(ParsedLinkFrame::Ethernet(f)) = ParsedLinkFrame::parse(&ETHER_FRAME) {
            assert_eq!(f.dst_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into());
            assert_eq!(f.src_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].into());
            assert_eq!(f.ether_type, 0x0800);
            assert_eq!(f.payload, [0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        }

        const TRUNCATED_FRAME: [u8; 10] =
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xAA, 0xBB, 0xCC, 0xDD];

        assert!(matches!(
            ParsedLinkFrame::parse(&TRUNCATED_FRAME),
            Err(Error::Truncated)
        ));

        const VLAN_FRAME: [u8; VLAN_TAGGED_OFFSET + 4] = [
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Destination MAC: 00:11:22:33:44:55
            0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, // Source MAC: AA:BB:CC:DD:EE:FF
            0x81, 0x00, // EtherType: 0x8100 = VLAN-tagged
            // VLAN tag (2 bytes: PCP + CFI + VLAN ID) + inner EtherType
            0x00, 0x01, 0x08, 0x00, // VLAN tag
            0x01, 0x02, 0x03, 0x04, // Payload (4 bytes)
        ];

        assert!(matches!(
            ParsedLinkFrame::parse(&VLAN_FRAME),
            Ok(ParsedLinkFrame::VlanTagged(_))
        ));

        if let Ok(ParsedLinkFrame::VlanTagged(f)) = ParsedLinkFrame::parse(&VLAN_FRAME) {
            assert_eq!(f.dst_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55].into());
            assert_eq!(f.src_mac, [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF].into());
            assert_eq!(f.ether_type, 0x0800);
            assert_eq!(f.payload, [0x01, 0x02, 0x03, 0x04]);
        }
    }
}
