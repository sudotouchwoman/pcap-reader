use crate::ip;
use std::fmt;
use thiserror::Error;

// TODO: implement TCP reassembly and UDP parsing logic
// at transport level, we have (src_ip, dst_ip, src_port, dst_port, proto) tuples that
// identify a unique tcp stream. the protocols are usually TCP and UDP
// the ports are the new piece of information that IP did not have
// for other protocols like ICMP, the endpoint is just two IP addresses + ICMP type/code
// basically, we introduce another multiplexing level (ports), which allow two hosts
// share the same underlying transport and still communicate through multiple independent data streams!

#[derive(Error, Debug)]
pub enum Error {
    #[error("transport: {0}")]
    Truncated(#[from] ip::Error),
    #[error("inconsistent payload size: expect {0}, got {1}")]
    LengthInconsistent(usize, usize),
    #[error("transport proto not supported: {0:?}")]
    Unsupported(ip::Proto),
}

pub struct SockAddr<A: ip::Addr> {
    pub host: A,
    pub port: u16,
}

impl<A: ip::Addr> fmt::Display for SockAddr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

pub struct AddrPair<A: ip::Addr> {
    pub src: SockAddr<A>,
    pub dst: SockAddr<A>,
}

impl<A: ip::Addr> fmt::Display for AddrPair<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} -> {}", self.src, self.dst)
    }
}

trait ParseTransport<A: ip::Addr>
where
    Self: Sized,
{
    type Error;
    fn from_ip_packet(src: A, dst: A, payload: Vec<u8>) -> Result<Self, Self::Error>;
}

pub struct SegmentCtor;
impl ip::markers::Constructor for SegmentCtor {
    type Apply<'a, V: ip::Version> = Segment<V::Addr>;
}

// Packet enum over v4/v6 addr families using GAT pattern.
// 'static is a placeholder: Segment owns its buffer, so Apply ignores the lifetime.
pub type Packet = ip::markers::Family<'static, SegmentCtor>;

pub enum Segment<A: ip::Addr> {
    Tcp(tcp::Segment),
    Udp(udp::Segment<A>),
    Icmp(icmp::Message),
}

impl<A: ip::Addr> Segment<A> {
    pub fn parse(proto: ip::Proto, src: A, dst: A, payload: Vec<u8>) -> Result<Self, Error> {
        match proto {
            ip::Proto::UDP => Ok(Self::Udp(udp::Segment::from_ip_packet(src, dst, payload)?)),
            v => Err(Error::Unsupported(v)),
        }
    }
}

impl<A: ip::Addr> fmt::Display for Segment<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(v) => v.fmt(f),
            Self::Tcp(_) => write!(f, "TCP not implemented yet"),
            Self::Icmp(_) => write!(f, "ICMP not implemented yet"),
        }
    }
}

pub mod tcp {
    pub struct Segment {}
}

pub mod udp {
    use std::fmt;
    use std::ops::Range;

    use super::{AddrPair, ParseTransport, SockAddr};
    use crate::ip;

    // https://en.wikipedia.org/wiki/User_Datagram_Protocol
    pub struct Segment<A: ip::Addr> {
        pub addr: AddrPair<A>,
        buf: Vec<u8>,
        range: Range<usize>,
    }

    impl<A: ip::Addr> Segment<A> {
        fn payload(&self) -> &[u8] {
            &self.buf[self.range.clone()]
        }
    }

    impl<A: ip::Addr> ParseTransport<A> for Segment<A> {
        type Error = super::Error;

        fn from_ip_packet(src: A, dst: A, payload: Vec<u8>) -> Result<Self, Self::Error> {
            use crate::ip::Error::Truncated;

            const SEGMENT_HEADER_BYTES: usize = 8;

            if payload.len() < SEGMENT_HEADER_BYTES {
                return Err(Truncated(payload.len(), SEGMENT_HEADER_BYTES).into());
            }

            // Safety: payload.len() is at least 8 bytes
            let src_port = u16::from_be_bytes(payload[..2].try_into().unwrap());
            let dst_port = u16::from_be_bytes(payload[2..4].try_into().unwrap());

            // payload_len is not really required since for well-formed, fully reassembled traffic
            // one does not need the udp length field to discover how much data there is
            // still, it represents a self-contained datagram boundary, which carries its own size
            // so a receiver can parse udp without assuming "IP payload == udp datagram"
            let payload_len = u16::from_be_bytes(payload[4..6].try_into().unwrap()) as usize;

            if payload.len() < payload_len {
                // payload length from udp header should match
                // reassembled IP datagram length (or at least not exceed it)
                return Err(Self::Error::LengthInconsistent(payload.len(), payload_len));
            };

            // udp provides a checksum to verify its payload, but we skip this step
            let _checksum = u16::from_be_bytes(payload[6..8].try_into().unwrap());

            Ok(Self {
                addr: AddrPair {
                    src: SockAddr {
                        host: src,
                        port: src_port,
                    },
                    dst: SockAddr {
                        host: dst,
                        port: dst_port,
                    },
                },
                buf: payload,
                range: SEGMENT_HEADER_BYTES..payload_len,
            })
        }
    }

    impl<A: ip::Addr> fmt::Display for Segment<A> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use crate::slices;

            let data = self.payload();

            write!(f, "UDP: [{}] len: {}, payload: ", self.addr, data.len())?;

            if f.alternate() {
                write!(f, "{}", slices::Hex(data)) // {:#}
            } else {
                write!(f, "{}", slices::Utf8(data)) // {}
            }
        }
    }
}

pub mod icmp {
    pub struct Message {}
}
