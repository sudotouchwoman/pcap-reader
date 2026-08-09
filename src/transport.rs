use crate::ip;
use std::fmt;
use thiserror::Error;

pub use frag::{StreamEvent, TcpStreamReassembler};

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

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone, Copy)]
pub struct SockAddr<A: ip::Addr> {
    pub host: A,
    pub port: u16,
}

impl<A: ip::Addr> fmt::Display for SockAddr<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Clone, Copy)]
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
    Tcp(tcp::Segment<A>),
    Udp(udp::Segment<A>),
    Icmp(icmp::Message),
}

impl<A: ip::Addr> Segment<A> {
    pub fn parse(proto: ip::Proto, src: A, dst: A, payload: Vec<u8>) -> Result<Self, Error> {
        match proto {
            ip::Proto::UDP => Ok(Self::Udp(udp::Segment::from_ip_packet(src, dst, payload)?)),
            ip::Proto::TCP => Ok(Self::Tcp(tcp::Segment::from_ip_packet(src, dst, payload)?)),
            v => Err(Error::Unsupported(v)),
        }
    }
}

impl<A: ip::Addr> fmt::Display for Segment<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Udp(v) => v.fmt(f),
            Self::Tcp(v) => v.fmt(f),
            Self::Icmp(_) => write!(f, "ICMP not implemented yet"),
        }
    }
}

pub mod tcp {
    use std::fmt;
    use std::ops::Range;

    use super::{AddrPair, ParseTransport, SockAddr};
    use crate::ip;

    // https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    pub struct Segment<A: ip::Addr> {
        pub addr: AddrPair<A>,
        pub header: Header,
        pub data_range: Range<usize>,
        pub _opts_range: Range<usize>,
        pub buf: Vec<u8>,
    }

    impl<A: ip::Addr> Segment<A> {
        pub fn payload(&self) -> &[u8] {
            &self.buf[self.data_range.clone()]
        }

        fn _options(&self) -> &[u8] {
            &self.buf[self._opts_range.clone()]
        }
    }

    impl<A: ip::Addr> ParseTransport<A> for Segment<A> {
        type Error = super::Error;

        fn from_ip_packet(src: A, dst: A, payload: Vec<u8>) -> Result<Self, Self::Error> {
            use crate::ip::Error::Truncated;

            if payload.len() < SEGMENT_HEADER_BYTES {
                return Err(Truncated(payload.len(), SEGMENT_HEADER_BYTES).into());
            }

            let header =
                Header::from_be_bytes(payload[0..SEGMENT_HEADER_BYTES].try_into().unwrap());

            let data_offset_bytes = header.data_offset_bytes();

            if payload.len() < data_offset_bytes {
                // payload length from udp header should match
                // reassembled IP datagram length (or at least not exceed it)
                return Err(Self::Error::LengthInconsistent(
                    payload.len(),
                    data_offset_bytes,
                ));
            };

            Ok(Self {
                addr: AddrPair {
                    src: SockAddr {
                        host: src,
                        port: header.src_port,
                    },
                    dst: SockAddr {
                        host: dst,
                        port: header.dst_port,
                    },
                },
                header,
                data_range: data_offset_bytes..payload.len(),
                _opts_range: SEGMENT_HEADER_BYTES..data_offset_bytes,
                buf: payload,
            })
        }
    }

    impl<A: ip::Addr> fmt::Display for Segment<A> {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use crate::slices;

            let data = self.payload();

            write!(
                f,
                "TCP: [{}] flags: {} len: {}, payload: ",
                self.addr,
                self.header.flags,
                data.len()
            )?;

            if f.alternate() {
                write!(f, "{}", slices::Hex(data)) // {:#}
            } else {
                write!(f, "{}", slices::Utf8(data)) // {}
            }
        }
    }

    pub struct Header {
        pub src_port: u16,
        pub dst_port: u16,
        pub seq_number: u32,
        pub ack_number: u32,
        pub data_offset_and_reserved: u8,
        pub flags: Flags,
        pub window: u16,
        pub checksum: u16,
        pub urgent_ptr: u16,
    }

    const SEGMENT_HEADER_BYTES: usize = 20;

    impl Header {
        fn data_offset_bytes(self: &Self) -> usize {
            // take 4 upper bits, then multiply by 4 (offset is stored in 32-bit words)
            (self.data_offset_and_reserved >> 4 << 2) as usize
        }

        fn from_be_bytes(value: [u8; SEGMENT_HEADER_BYTES]) -> Self {
            // Safety: value.len() is exactly 20 bytes
            let src_port = u16::from_be_bytes(value[..2].try_into().unwrap());
            let dst_port = u16::from_be_bytes(value[2..4].try_into().unwrap());

            let seq_number = u32::from_be_bytes(value[4..8].try_into().unwrap());
            let ack_number = u32::from_be_bytes(value[8..12].try_into().unwrap());

            let data_offset_and_reserved = value[12];
            let flags = Flags::from_byte(value[13]);

            let window = u16::from_be_bytes(value[14..16].try_into().unwrap());

            // TODO verify checksum (out of scope for now)
            let checksum = u16::from_be_bytes(value[16..18].try_into().unwrap());
            let urgent_ptr = u16::from_be_bytes(value[18..20].try_into().unwrap());

            Self {
                src_port,
                dst_port,
                seq_number,
                ack_number,
                data_offset_and_reserved,
                flags,
                window,
                checksum,
                urgent_ptr,
            }
        }
    }

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct Flags(u8);

    impl Flags {
        pub const FIN: u8 = 1 << 0;
        pub const SYN: u8 = 1 << 1;
        pub const RST: u8 = 1 << 2;
        pub const PSH: u8 = 1 << 3;
        pub const ACK: u8 = 1 << 4;
        pub const URG: u8 = 1 << 5;
        pub const ECE: u8 = 1 << 6;
        pub const CWR: u8 = 1 << 7;

        pub fn from_byte(b: u8) -> Self {
            Self(b)
        }

        pub fn as_byte(self) -> u8 {
            self.0
        }

        pub fn fin(self) -> bool {
            self.0 & Self::FIN != 0
        }
        pub fn syn(self) -> bool {
            self.0 & Self::SYN != 0
        }
        pub fn rst(self) -> bool {
            self.0 & Self::RST != 0
        }
        pub fn psh(self) -> bool {
            self.0 & Self::PSH != 0
        }
        pub fn ack(self) -> bool {
            self.0 & Self::ACK != 0
        }
        pub fn urg(self) -> bool {
            self.0 & Self::URG != 0
        }
        pub fn ece(self) -> bool {
            self.0 & Self::ECE != 0
        }
        pub fn cwr(self) -> bool {
            self.0 & Self::CWR != 0
        }
    }

    impl fmt::Display for Flags {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            const NAMES: &[(u8, &str)] = &[
                (Flags::FIN, "FIN"),
                (Flags::SYN, "SYN"),
                (Flags::RST, "RST"),
                (Flags::PSH, "PSH"),
                (Flags::ACK, "ACK"),
                (Flags::URG, "URG"),
                (Flags::ECE, "ECE"),
                (Flags::CWR, "CWR"),
            ];

            let mut first = true;

            for &(bit, name) in NAMES {
                if self.0 & bit != 0 {
                    if !first {
                        f.write_str("|")?;
                    }

                    f.write_str(name)?;
                    first = false;
                }
            }

            if first { f.write_str("-") } else { Ok(()) }
        }
    }
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

mod frag {
    use std::{collections::BTreeMap, fmt, mem, num::NonZeroUsize};

    use lru::LruCache;

    use crate::{
        ip,
        transport::{self, AddrPair, tcp},
    };

    use super::SockAddr;

    struct Flow<A: ip::Addr> {
        endpoints: (SockAddr<A>, SockAddr<A>), // endpoints (a, b)
        streams: (HalfStream, HalfStream),     // streams: .0 => a->b, .1 => b->a
    }

    impl<A: ip::Addr> Flow<A> {
        fn new(src: SockAddr<A>, dst: SockAddr<A>) -> Self {
            Self {
                endpoints: (src, dst),
                streams: (HalfStream::Idle, HalfStream::Idle),
            }
        }

        fn direction(&self, src: &SockAddr<A>) -> Direction {
            if *src == self.endpoints.0 {
                return Direction::From;
            }
            if *src == self.endpoints.1 {
                return Direction::To;
            }

            // returning Result<Direction, ...> would be another option,
            // but we make caller responsible for ingest() call integrity instead
            unreachable!("segment not in this flow")
        }

        /// ingest tcp::Segment into one of the underlying
        fn ingest(&mut self, seg: &tcp::Segment<A>) -> FlowResult {
            let segment_info = SegmentInfo::from(seg);
            let direction = self.direction(&seg.addr.src);

            let half = match direction {
                Direction::From => &mut self.streams.0,
                Direction::To => &mut self.streams.1,
            };

            let out = half.ingest(segment_info);

            if matches!(out, IngestResult::Reset) {
                // abort both conversation streams upon any RST
                self.streams.0 = HalfStream::Closed(CloseReason::Rst);
                self.streams.1 = HalfStream::Closed(CloseReason::Rst);
            }

            match direction {
                Direction::From => FlowResult::Forward(out),
                Direction::To => FlowResult::Reverse(out),
            }
        }

        fn is_done(&self) -> bool {
            matches!(
                (&self.streams.0, &self.streams.1),
                (HalfStream::Closed(_), HalfStream::Closed(_))
            )
        }
    }

    #[derive(Clone, Copy, Debug)]
    pub enum Direction {
        From,
        To,
    }

    impl fmt::Display for Direction {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::From => f.write_str("forward"),
                Self::To => f.write_str("reverse"),
            }
        }
    }

    #[derive(Debug)]
    enum FlowResult {
        Forward(IngestResult),
        Reverse(IngestResult),
    }

    #[derive(Debug, PartialEq, Eq)]
    enum CloseReason {
        Fin,
        Rst,
    }

    struct SegmentInfo<'a> {
        seq: u32,
        payload: &'a [u8],
        flags: tcp::Flags,
    }

    impl<'a, A: ip::Addr> From<&'a tcp::Segment<A>> for SegmentInfo<'a> {
        fn from(value: &'a tcp::Segment<A>) -> Self {
            Self {
                seq: value.header.seq_number,
                flags: value.header.flags,
                payload: value.payload(),
            }
        }
    }

    enum HalfStream {
        Idle,
        Open(OpenHalfStream),
        Closed(CloseReason),
    }

    impl HalfStream {
        fn ingest(&mut self, seg: SegmentInfo<'_>) -> IngestResult {
            match mem::replace(self, Self::Idle) {
                Self::Idle => {
                    if seg.flags.rst() {
                        *self = Self::Closed(CloseReason::Rst);
                        return IngestResult::Reset;
                    }

                    // SYN only opens the half. Do not push the SYN segment into
                    // OpenHalfStream — from_syn already advanced past the ISN.
                    // Rare SYN+data/FIN is handled by re-entering on the Open arm.
                    if seg.flags.syn() {
                        *self = Self::Open(OpenHalfStream::from_syn(seg.seq));

                        if seg.payload.is_empty() && !seg.flags.fin() {
                            return IngestResult::Opened;
                        }

                        return self.ingest(SegmentInfo {
                            seq: seg.seq.wrapping_add(1),
                            payload: seg.payload,
                            flags: flags_without_syn(seg.flags),
                        });
                    }

                    if !seg.payload.is_empty() || seg.flags.fin() {
                        *self = Self::Open(OpenHalfStream::from_midstream(seg.seq));

                        return self.ingest(seg);
                    }

                    IngestResult::Ignore(IgnoreReason::Empty)
                }
                Self::Open(mut open) => {
                    let out = open.ingest(seg);
                    *self = Self::after_open_ingest(open, &out);

                    out
                }
                Self::Closed(reason) => {
                    *self = Self::Closed(reason);

                    IngestResult::AlreadyClosed
                }
            }
        }

        fn after_open_ingest(open: OpenHalfStream, out: &IngestResult) -> HalfStream {
            match out {
                IngestResult::Reset => Self::Closed(CloseReason::Rst),
                IngestResult::Ok {
                    fin_complete: true, ..
                } => Self::Closed(CloseReason::Fin),
                _ => Self::Open(open),
            }
        }
    }

    fn flags_without_syn(flags: tcp::Flags) -> tcp::Flags {
        tcp::Flags::from_byte(flags.as_byte() & !tcp::Flags::SYN)
    }

    struct OpenHalfStream {
        _isn: u32,                          // initial sequence number (ISN) from SYN
        next_seq: u32,                      // first undelivered byte
        ooo_buffer: BTreeMap<u32, Vec<u8>>, // sequence -> payload map (out of order buf)
        fin_seq: Option<u32>,               // set when FIN seen
    }

    #[derive(Debug)]
    enum IngestResult {
        /// Idle → Open via SYN (no payload delivered this call)
        Opened,
        AlreadyClosed, // only emitted by HalfStream if any event comes on closed
        Ok {
            delivered: Vec<u8>,
            fin_complete: bool, // next_seq passed fin_seq
        },
        Reset,                // RST -> HalfStream becomes Closed(Rst)
        Ignore(IgnoreReason), // no state change, discarded by OOO
    }

    #[derive(Debug, PartialEq, Eq)]
    enum IgnoreReason {
        Duplicate, // fully left of next_seq
        Empty,     // pure ACK / no seq progress
    }

    impl OpenHalfStream {
        fn from_syn(isn: u32) -> Self {
            Self {
                _isn: isn,
                next_seq: isn + 1, // SYN consumes 1 byte in seq space
                ooo_buffer: BTreeMap::default(),
                fin_seq: None,
            }
        }

        fn from_midstream(first_data_seq: u32) -> Self {
            // first_data_seq - "first byte we believe we should track"
            // because the real SYN was not received yet
            Self {
                _isn: first_data_seq, // anchor only, not a real SYN
                next_seq: first_data_seq,
                ooo_buffer: BTreeMap::default(),
                fin_seq: None,
            }
        }

        fn ingest(&mut self, seg: SegmentInfo) -> IngestResult {
            // early return for hard rejects, otherwise mutate self then always
            // drain ooo and try complete fin
            if seg.flags.rst() {
                // handle connection reset early
                return IngestResult::Reset;
            }

            if seg.flags.syn() {
                // unusual - retransmit SYN - ignore
                return IngestResult::Ignore(IgnoreReason::Duplicate);
            }

            let mut data_seq = seg.seq;
            let mut data = seg.payload;

            if before(data_seq, self.next_seq) {
                // trip already delivered data prefix
                let skipped_prefix = self.next_seq.wrapping_sub(data_seq) as usize;
                if skipped_prefix >= data.len() {
                    // the entire retransmitted payload was seen already
                    if !seg.flags.fin() {
                        return IngestResult::Ignore(IgnoreReason::Duplicate);
                    }

                    // FIN-only retransmit (or FIN with fully-duplicate payload)
                    data = &[];
                } else {
                    data = &data[skipped_prefix..];
                }

                // always move
                data_seq = self.next_seq;
            }

            if seg.flags.fin() {
                // remember FIN sequence (after data bytes)
                // ok to overwrite FIN on retransmissions (?)
                self.fin_seq = Some(data_seq.wrapping_add(data.len() as u32));
            }

            if data.is_empty() && self.fin_seq.is_none() {
                // pure ACK, no FIN, no data
                return IngestResult::Ignore(IgnoreReason::Empty);
            }

            // persist new payload (own it since reassembled stream outlives segments)
            if !data.is_empty() {
                self.ooo_buffer
                    .entry(data_seq)
                    .or_insert_with(|| data.to_owned()); // keep-first
            }

            // always try to deliver data + complete fin
            // drain must be called before try_complete_fin
            IngestResult::Ok {
                delivered: self.drain_ooo(),
                fin_complete: self.try_complete_fin(),
            }
        }

        /// Pulls every OOO chunk that starts exactly at next_seq.
        /// Returns owned bytes in order. Updates self.next_seq in the process.
        fn drain_ooo(&mut self) -> Vec<u8> {
            let mut delivered = Vec::new();

            while let Some(chunk) = self.ooo_buffer.remove(&self.next_seq) {
                // advance next_seq and push chunk to delivered
                self.next_seq = self.next_seq.wrapping_add(chunk.len() as u32);
                delivered.extend(chunk);
            }

            delivered
        }

        /// If all data before FIN is delivered, consume the FIN seq number.
        fn try_complete_fin(&mut self) -> bool {
            let Some(fin_seq) = self.fin_seq else {
                return false;
            };

            if self.next_seq == fin_seq {
                self.next_seq = fin_seq.wrapping_add(1);

                true
            } else {
                false
            }
        }
    }

    // check if segment a comes before segment b with possible wraparound
    fn before(a: u32, b: u32) -> bool {
        (a.wrapping_sub(b) as i32) < 0
    }

    #[derive(Eq, Hash, PartialEq, Clone, Copy)]
    struct FlowKey<A: ip::Addr> {
        a: SockAddr<A>, // min(src,dst)
        b: SockAddr<A>, // max(src,dst)
    }

    struct StreamReassembler<A: ip::Addr> {
        // same idea as IP LruCache in DatagramReassembler
        flows: LruCache<FlowKey<A>, Flow<A>>,
    }

    impl<A: ip::Addr> Default for StreamReassembler<A> {
        fn default() -> Self {
            Self {
                flows: LruCache::new(const { NonZeroUsize::new(1000).unwrap() }),
            }
        }
    }

    impl<A: ip::Addr> StreamReassembler<A> {
        fn derive_flow_key(pair: AddrPair<A>) -> FlowKey<A> {
            if pair.src <= pair.dst {
                FlowKey {
                    a: pair.src,
                    b: pair.dst,
                }
            } else {
                FlowKey {
                    a: pair.dst,
                    b: pair.src,
                }
            }
        }

        fn process(&mut self, seg: &tcp::Segment<A>) -> Vec<StreamEvent> {
            // first segment is used to decide on flow orientation (usually client sends SYN first)
            // but TCP is inherently full duplex, so this is just a heuristic
            let key = Self::derive_flow_key(seg.addr);
            let flow = self
                .flows
                .get_or_insert_mut_ref(&key, || Flow::new(seg.addr.src, seg.addr.dst));

            let result = flow.ingest(&seg);

            let mut events = map_flow_result(result);

            if flow.is_done() {
                // both have closed from this single packet
                self.flows.pop(&key);
                events.push(StreamEvent::Closed);
            }

            events
        }
    }

    fn map_flow_result(result: FlowResult) -> Vec<StreamEvent> {
        let (direction, ingest) = match result {
            FlowResult::Forward(i) => (Direction::From, i),
            FlowResult::Reverse(i) => (Direction::To, i),
        };

        map_ingest(direction, ingest)
    }

    /// Maps IngestResult into Vec of StreamEvents
    fn map_ingest(direction: Direction, ingest: IngestResult) -> Vec<StreamEvent> {
        match ingest {
            IngestResult::Opened => vec![StreamEvent::Opened(direction)],
            IngestResult::Reset => vec![StreamEvent::Reset],
            IngestResult::Ignore(_v) => vec![],
            IngestResult::AlreadyClosed => vec![],
            IngestResult::Ok {
                delivered,
                fin_complete,
            } => {
                let mut out = Vec::with_capacity(2); // at most 2 events

                if !delivered.is_empty() {
                    out.push(StreamEvent::Data {
                        direction,
                        bytes: delivered,
                    });
                }

                if fin_complete {
                    out.push(StreamEvent::HalfClosed { direction });
                }

                out
            }
        }
    }

    #[derive(Debug)]
    pub enum StreamEvent {
        Opened(Direction),
        Data {
            direction: Direction,
            bytes: Vec<u8>,
        },
        HalfClosed {
            direction: Direction,
        },
        Reset,
        Closed,
    }

    impl fmt::Display for StreamEvent {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            use crate::slices;

            write!(f, "TCP: stream: ")?;

            match self {
                Self::Opened(direction) => write!(f, "opened ({direction})"),
                Self::Reset => f.write_str("reset"),
                Self::Closed => f.write_str("closed"),
                Self::HalfClosed { direction } => {
                    write!(f, "half-closed ({direction})")
                }
                Self::Data { direction, bytes } => {
                    write!(f, "data ({direction}) len: {}, payload: ", bytes.len())?;
                    if f.alternate() {
                        write!(f, "{}", slices::Hex(bytes))
                    } else {
                        write!(f, "{}", slices::Utf8(bytes))
                    }
                }
            }
        }
    }

    /// Facade over StreamReassembler
    pub struct TcpStreamReassembler {
        v4: StreamReassembler<ip::v4::Addr>,
        v6: StreamReassembler<ip::v6::Addr>,
    }

    impl TcpStreamReassembler {
        pub fn process(&mut self, pkt: &transport::Packet) -> Vec<StreamEvent> {
            use crate::ip::markers::Family;
            use crate::transport::Segment;

            match pkt {
                Family::Ipv4(Segment::Tcp(seg)) => self.v4.process(seg),
                Family::Ipv6(Segment::Tcp(seg)) => self.v6.process(seg),
                _ => vec![],
            }
        }
    }

    impl Default for TcpStreamReassembler {
        fn default() -> Self {
            Self {
                v4: StreamReassembler::<ip::v4::Addr>::default(),
                v6: StreamReassembler::<ip::v6::Addr>::default(),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use crate::transport::AddrPair;

        use super::*;

        const ACK: u8 = tcp::Flags::ACK;
        const FIN: u8 = tcp::Flags::FIN;
        const PSH: u8 = tcp::Flags::PSH;
        const RST: u8 = tcp::Flags::RST;

        fn seg<'a>(seq: u32, payload: &'a [u8], f: u8) -> SegmentInfo<'a> {
            SegmentInfo {
                seq,
                payload,
                flags: tcp::Flags::from_byte(f),
            }
        }

        fn assert_ok(r: IngestResult, expect: &[u8], fin: bool) {
            match r {
                IngestResult::Ok {
                    delivered,
                    fin_complete,
                } => {
                    assert_eq!(delivered, expect);
                    assert_eq!(fin_complete, fin);
                }
                other => panic!("expected Ok, got {other:?}"),
            }
        }

        fn assert_ignore(r: IngestResult, reason: IgnoreReason) {
            match r {
                IngestResult::Ignore(got) => assert_eq!(got, reason),
                other => panic!("expected Ignore({reason:?}), got {other:?}"),
            }
        }

        #[test]
        fn in_order_delivers_after_syn() {
            let mut h = OpenHalfStream::from_syn(1000);
            assert_eq!(h.next_seq, 1001);

            assert_ok(h.ingest(seg(1001, b"GET", ACK | PSH)), b"GET", false);
            assert_eq!(h.next_seq, 1004);
            assert!(h.ooo_buffer.is_empty());
        }

        #[test]
        fn ooo_holds_until_gap_filled() {
            let mut h = OpenHalfStream::from_syn(1000);

            assert_ok(h.ingest(seg(1005, b"YY", ACK)), b"", false);
            assert_eq!(h.next_seq, 1001);
            assert_eq!(h.ooo_buffer.len(), 1);

            assert_ok(h.ingest(seg(1001, b"XXXX", ACK)), b"XXXXYY", false);
            assert_eq!(h.next_seq, 1007);
            assert!(h.ooo_buffer.is_empty());
        }

        #[test]
        fn full_duplicate_is_ignored() {
            let mut h = OpenHalfStream::from_syn(1000);

            assert_ok(h.ingest(seg(1001, b"AB", ACK)), b"AB", false);
            assert_eq!(h.next_seq, 1003);

            assert_ignore(h.ingest(seg(1001, b"AB", ACK)), IgnoreReason::Duplicate);
            assert_eq!(h.next_seq, 1003);
        }

        #[test]
        fn partial_overlap_delivers_new_suffix() {
            let mut h = OpenHalfStream::from_syn(1000);

            assert_ok(h.ingest(seg(1001, b"HELLO", ACK)), b"HELLO", false);
            assert_eq!(h.next_seq, 1006);

            assert_ok(h.ingest(seg(1003, b"LLO!", ACK)), b"!", false);
            assert_eq!(h.next_seq, 1007);
            assert!(h.ooo_buffer.is_empty());
        }

        #[test]
        fn keep_first_on_duplicate_ooo_key() {
            let mut h = OpenHalfStream::from_syn(1000);

            assert_ok(h.ingest(seg(1010, b"AAA", ACK)), b"", false);
            assert_ok(h.ingest(seg(1010, b"BBB", ACK)), b"", false);
            assert_eq!(
                h.ooo_buffer.get(&1010).map(Vec::as_slice),
                Some(&b"AAA"[..])
            );

            // 9 bytes: 1001..1010, then drain the kept OOO chunk
            assert_ok(
                h.ingest(seg(1001, b".........", ACK)),
                b".........AAA",
                false,
            );
            assert_eq!(h.next_seq, 1013);
            assert!(h.ooo_buffer.is_empty());
        }

        #[test]
        fn fin_with_data_completes() {
            let mut h = OpenHalfStream::from_syn(1000);

            assert_ok(h.ingest(seg(1001, b"bye", ACK | FIN)), b"bye", true);
            assert_eq!(h.next_seq, 1005); // 1001 + 3 data + 1 FIN
            assert!(h.ooo_buffer.is_empty());
        }

        #[test]
        fn fin_only_after_data_completes() {
            let mut h = OpenHalfStream::from_syn(1000);

            assert_ok(h.ingest(seg(1001, b"x", ACK)), b"x", false);
            assert_eq!(h.next_seq, 1002);

            assert_ok(h.ingest(seg(1002, b"", ACK | FIN)), b"", true);
            assert_eq!(h.next_seq, 1003);
        }

        #[test]
        fn fin_before_missing_data_waits() {
            let mut h = OpenHalfStream::from_syn(1000);

            assert_ok(h.ingest(seg(1005, b"", ACK | FIN)), b"", false);
            assert_eq!(h.next_seq, 1001);
            assert_eq!(h.fin_seq, Some(1005));

            assert_ok(h.ingest(seg(1001, b"XXXX", ACK)), b"XXXX", true);
            assert_eq!(h.next_seq, 1006);
            assert!(h.ooo_buffer.is_empty());
        }

        #[test]
        fn rst_returns_reset() {
            let mut h = OpenHalfStream::from_syn(1000);

            match h.ingest(seg(1001, b"", RST)) {
                IngestResult::Reset => {}
                other => panic!("expected Reset, got {other:?}"),
            }
        }

        #[test]
        fn midstream_open_delivers_from_first_seq() {
            let mut h = OpenHalfStream::from_midstream(500);

            assert_ok(h.ingest(seg(500, b"hi", ACK)), b"hi", false);
            assert_eq!(h.next_seq, 502);
        }

        #[test]
        fn sequence_wraparound() {
            // (u32::MAX - 1) + 2 bytes wraps to 0
            let mut h = OpenHalfStream::from_midstream(u32::MAX - 1);

            assert_ok(h.ingest(seg(u32::MAX - 1, b"ab", ACK)), b"ab", false);
            assert_eq!(h.next_seq, 0);

            assert_ok(h.ingest(seg(0, b"c", ACK)), b"c", false);
            assert_eq!(h.next_seq, 1);
        }

        #[test]
        fn pure_ack_is_ignored_as_empty() {
            let mut h = OpenHalfStream::from_syn(1000);

            assert_ignore(h.ingest(seg(1001, b"", ACK)), IgnoreReason::Empty);
            assert_eq!(h.next_seq, 1001);
        }

        // Flow and HalfStream tests
        type V4 = ip::v4::Addr;

        fn sockaddr(host: [u8; 4], port: u16) -> SockAddr<V4> {
            SockAddr {
                host: V4::from(host),
                port,
            }
        }

        fn client() -> SockAddr<V4> {
            sockaddr([10, 0, 0, 1], 50_000)
        }

        fn server() -> SockAddr<V4> {
            sockaddr([10, 0, 0, 2], 6379)
        }

        fn tcp_segment(
            src: SockAddr<V4>,
            dst: SockAddr<V4>,
            seq: u32,
            payload: &'_ [u8],
            flags: u8,
        ) -> tcp::Segment<V4> {
            tcp::Segment {
                header: tcp::Header {
                    src_port: src.port,
                    dst_port: dst.port,
                    seq_number: seq,
                    ack_number: 0,
                    data_offset_and_reserved: 0, // irrelevant
                    flags: tcp::Flags::from_byte(flags),
                    window: 0,
                    checksum: 0,
                    urgent_ptr: 0,
                },
                buf: payload.to_owned(),
                addr: AddrPair { src, dst },
                data_range: 0..payload.len(),
                _opts_range: 0..0,
            }
        }

        const SYN: u8 = tcp::Flags::SYN;

        fn assert_forward_ok(r: FlowResult, expect: &[u8], fin: bool) {
            match r {
                FlowResult::Forward(inner) => assert_ok(inner, expect, fin),
                other => panic!("expected Forward, got {other:?}"),
            }
        }

        fn assert_reverse_ok(r: FlowResult, expect: &[u8], fin: bool) {
            match r {
                FlowResult::Reverse(inner) => assert_ok(inner, expect, fin),
                other => panic!("expected Reverse, got {other:?}"),
            }
        }

        fn assert_forward_reset(r: FlowResult) {
            match r {
                FlowResult::Forward(IngestResult::Reset) => {}
                other => panic!("expected Forward(Reset), got {other:?}"),
            }
        }

        fn assert_reverse_already_closed(r: FlowResult) {
            match r {
                FlowResult::Reverse(IngestResult::AlreadyClosed) => {}
                other => panic!("expected Reverse(AlreadyClosed), got {other:?}"),
            }
        }

        fn assert_forward_opened(r: FlowResult) {
            match r {
                FlowResult::Forward(IngestResult::Opened) => {}
                other => panic!("expected Forward(Opened), got {other:?}"),
            }
        }

        fn assert_reverse_opened(r: FlowResult) {
            match r {
                FlowResult::Reverse(IngestResult::Opened) => {}
                other => panic!("expected Reverse(Opened), got {other:?}"),
            }
        }

        fn open_handshake(flow: &mut Flow<V4>) {
            assert_forward_opened(flow.ingest(&tcp_segment(client(), server(), 1000, b"", SYN)));
            assert_reverse_opened(flow.ingest(&tcp_segment(
                server(),
                client(),
                5000,
                b"",
                SYN | ACK,
            )));
            assert!(half_open(&flow.streams.0));
            assert!(half_open(&flow.streams.1));
        }

        fn half_closed_rst(h: &HalfStream) -> bool {
            matches!(h, HalfStream::Closed(CloseReason::Rst))
        }

        fn half_closed_fin(h: &HalfStream) -> bool {
            matches!(h, HalfStream::Closed(CloseReason::Fin))
        }

        fn half_open(h: &HalfStream) -> bool {
            matches!(h, HalfStream::Open(_))
        }

        fn half_idle(h: &HalfStream) -> bool {
            matches!(h, HalfStream::Idle)
        }

        #[test]
        fn forward_and_reverse_deliver_independently() {
            let mut flow = Flow::new(client(), server());

            assert_forward_opened(flow.ingest(&tcp_segment(client(), server(), 1000, b"", SYN)));
            assert!(half_open(&flow.streams.0));
            assert!(half_idle(&flow.streams.1));

            assert_reverse_opened(flow.ingest(&tcp_segment(
                server(),
                client(),
                5000,
                b"",
                SYN | ACK,
            )));
            assert!(half_open(&flow.streams.0));
            assert!(half_open(&flow.streams.1));

            assert_forward_ok(
                flow.ingest(&tcp_segment(client(), server(), 1001, b"PING", ACK | PSH)),
                b"PING",
                false,
            );
            assert_reverse_ok(
                flow.ingest(&tcp_segment(server(), client(), 5001, b"PONG", ACK | PSH)),
                b"PONG",
                false,
            );
            assert!(half_open(&flow.streams.0));
            assert!(half_open(&flow.streams.1));
        }

        #[test]
        fn fin_closes_only_sending_half() {
            let mut flow = Flow::new(client(), server());
            open_handshake(&mut flow);

            assert_forward_ok(
                flow.ingest(&tcp_segment(client(), server(), 1001, b"bye", ACK | FIN)),
                b"bye",
                true,
            );
            assert!(half_closed_fin(&flow.streams.0));
            assert!(half_open(&flow.streams.1));

            assert_reverse_ok(
                flow.ingest(&tcp_segment(server(), client(), 5001, b"ok", ACK | PSH)),
                b"ok",
                false,
            );
            assert!(half_closed_fin(&flow.streams.0));
            assert!(half_open(&flow.streams.1));
        }

        #[test]
        fn rst_closes_both_halves() {
            let mut flow = Flow::new(client(), server());
            open_handshake(&mut flow);
            flow.ingest(&tcp_segment(client(), server(), 1001, b"x", ACK));
            flow.ingest(&tcp_segment(server(), client(), 5001, b"y", ACK));

            assert_forward_reset(flow.ingest(&tcp_segment(client(), server(), 1002, b"", RST)));
            assert!(half_closed_rst(&flow.streams.0));
            assert!(half_closed_rst(&flow.streams.1));
        }

        #[test]
        fn rst_closes_idle_peer_half() {
            let mut flow = Flow::new(client(), server());

            assert_forward_opened(flow.ingest(&tcp_segment(client(), server(), 1000, b"", SYN)));
            assert!(half_open(&flow.streams.0));
            assert!(half_idle(&flow.streams.1));

            assert_forward_reset(flow.ingest(&tcp_segment(client(), server(), 1001, b"", RST)));
            assert!(half_closed_rst(&flow.streams.0));
            assert!(half_closed_rst(&flow.streams.1));
        }

        #[test]
        fn already_closed_after_rst() {
            let mut flow = Flow::new(client(), server());
            open_handshake(&mut flow);
            assert_forward_reset(flow.ingest(&tcp_segment(client(), server(), 1001, b"", RST)));

            assert_reverse_already_closed(flow.ingest(&tcp_segment(
                server(),
                client(),
                5001,
                b"late",
                ACK | PSH,
            )));
            assert!(half_closed_rst(&flow.streams.0));
            assert!(half_closed_rst(&flow.streams.1));
        }
    }
}
