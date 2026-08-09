use crate::{ethernet, ip, transport};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("link error: {0}")]
    Link(ethernet::Error),
    #[error("network error: {0}")]
    Network(ip::Error),
    #[error("non-IP packet passed to reassembler")]
    UnexpectedNotIp,
    #[error("{0}")]
    Transport(#[from] transport::Error),
}

pub enum Event<'a> {
    // link-level (ethernet frames)
    Ethernet(ethernet::LinkFrame<'a>),

    // network-level (arp operations / ipv4 / ipv6 packets)
    Arp(ip::arp::Packet),

    // reassembled ip4 / ipv6 datagrams
    Reassembled(ip::Reassembled),
    ReassemblyIncomplete,
    ReassemblyRejected(ip::frag::Error),

    // transport-level events (tcp/udp segments / icmp messages)
    Transport(transport::Packet),

    // tcp connection-level events (open / received data / close)
    TcpStream(transport::StreamEvent),

    // link- or network-level error
    Error(Error),
}

use std::fmt;

impl<'a> fmt::Display for Event<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Ethernet(link) => write!(f, "{link}"),
            Event::Arp(arp) => write!(f, "{arp}"),
            Event::Reassembled(d) => write!(f, "Reassembled: {d}"),
            Event::ReassemblyIncomplete => write!(f, "Reassembly: incomplete"),
            Event::ReassemblyRejected(e) => write!(f, "Reassembly: rejected ({e})"),
            Event::Transport(v) => write!(f, "{v}"),
            Event::TcpStream(v) => write!(f, "{v}"),
            Event::Error(e) => write!(f, "Error: {e}"),
        }
    }
}

pub struct Decoder {
    ip_reassembler: ip::NetworkReassembler,
    tcp_reassembler: transport::TcpStreamReassembler,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            ip_reassembler: ip::NetworkReassembler::default(),
            tcp_reassembler: transport::TcpStreamReassembler::default(),
        }
    }
    pub fn push_frame<'a>(&mut self, raw: &'a [u8]) -> Vec<Event<'a>> {
        let mut events = Vec::new();

        let link = match ethernet::LinkFrame::parse(raw) {
            Ok(v) => v,
            Err(e) => {
                events.push(Event::Error(Error::Link(e)));
                return events;
            }
        };

        let ether_type = link.ether_type;
        let payload = link.payload;

        events.push(Event::Ethernet(link));

        use ip::NetworkPacket as np;

        match np::parse(ether_type, payload) {
            Ok(np::Arp(v)) => events.push(Event::Arp(v)),
            Ok(np::Ipv4(v)) => self.handle_ip_packet(&mut events, ip::IpPacket::Ipv4(v)),
            Ok(np::Ipv6(v)) => self.handle_ip_packet(&mut events, ip::IpPacket::Ipv6(v)),
            Err(e) => events.push(Event::Error(Error::Network(e))),
        }

        events
    }

    pub fn handle_ip_packet<'a>(&mut self, events: &mut Vec<Event<'a>>, pkt: ip::IpPacket<'a>) {
        match self.ip_reassembler.process(&pkt) {
            ip::ReassemblyResult::Ready(d) => {
                // cannot push both events here, since handle_ip_datagram consumes d
                // events.push(Event::Reassembled(d));
                self.handle_ip_datagram(events, d);
            }
            ip::ReassemblyResult::Incomplete => events.push(Event::ReassemblyIncomplete),
            ip::ReassemblyResult::Rejected(e) => events.push(Event::ReassemblyRejected(e)),
            ip::ReassemblyResult::NotIp => events.push(Event::Error(Error::UnexpectedNotIp)),
        }
    }

    pub fn handle_ip_datagram<'a>(
        &mut self,
        events: &mut Vec<Event<'a>>,
        datagram: ip::Reassembled,
    ) {
        match datagram.parse_transport() {
            Ok(pkt) => {
                use crate::ip::markers::Family;
                use crate::transport::Segment;

                match &pkt {
                    // for tcp segments: feed them into tcp reassembler and emit produced events
                    // (single segment may emit multiple events, e.g. Open, Data, Closed)
                    Family::Ipv4(Segment::Tcp(_)) | Family::Ipv6(Segment::Tcp(_)) => events.extend(
                        self.tcp_reassembler
                            .process(&pkt)
                            .into_iter()
                            .map(Event::TcpStream),
                    ),
                    // for non-tcp segments (UDP, ICMP), emit transport-level event
                    _ => events.push(Event::Transport(pkt)),
                };
            }
            Err(e) => events.push(Event::Error(e.into())),
        }
    }
}
