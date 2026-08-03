use crate::{ethernet, ip};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("link error: {0}")]
    Link(ethernet::Error),
    #[error("network error: {0}")]
    Network(ip::Error),
    #[error("non-IP packet passed to reassembler")]
    UnexpectedNotIp,
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

    // link- or network-level error
    Error(Error),
}

use std::fmt;

impl<'a> fmt::Display for Event<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::Ethernet(link) => write!(f, "Ethernet: {link}"),
            Event::Arp(arp) => write!(f, "ARP: {arp}"),
            Event::Reassembled(d) => write!(f, "Reassembled: {d}"),
            Event::ReassemblyIncomplete => write!(f, "Reassembly: incomplete"),
            Event::ReassemblyRejected(e) => write!(f, "Reassembly: rejected ({e})"),
            Event::Error(e) => write!(f, "Error: {e}"),
        }
    }
}

pub struct Decoder {
    reassembler: ip::NetworkReassembler,
}

impl Decoder {
    pub fn new() -> Self {
        Self {
            reassembler: ip::NetworkReassembler::default(),
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
        match self.reassembler.process(&pkt) {
            ip::ReassemblyResult::Ready(d) => events.push(Event::Reassembled(d)),
            ip::ReassemblyResult::Incomplete => events.push(Event::ReassemblyIncomplete),
            ip::ReassemblyResult::Rejected(e) => events.push(Event::ReassemblyRejected(e)),
            ip::ReassemblyResult::NotIp => events.push(Event::Error(Error::UnexpectedNotIp)),
        }
    }
}
