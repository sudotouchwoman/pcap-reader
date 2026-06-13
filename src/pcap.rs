pub mod pcap {
    // see for the pcap header format: https://datatracker.ietf.org/doc/id/draft-gharris-opsawg-pcap-00.html
    use std::{io, time, vec};
    use thiserror::Error;

    #[derive(Error, Debug)]
    pub enum PcapHeaderError {
        #[error("bad magic number: {0:#08x}")]
        BadMagicNumber(u32),
        #[error("IO error: {0}")]
        Io(#[from] io::Error),
    }

    #[derive(Error, Debug)]
    pub enum PcapFrameError {
        #[error("IO error: {0}")]
        Io(#[from] io::Error),
    }

    #[derive(Error, Debug)]
    pub enum PcapError {
        #[error("invalid PCAP header: {0:?}")]
        Header(#[from] PcapHeaderError),
        #[error("invalid frame: {0:?}")]
        Frame(#[from] PcapFrameError),
    }

    #[derive(Debug, PartialEq)]
    enum Endianess {
        Little,
        Big,
    }

    #[derive(Debug, PartialEq)]
    enum TimeFormat {
        SecondsAndMicroseconds,
        SecondsAndNanoseconds,
    }

    impl Endianess {
        fn from_magic(magic_number: u32) -> Result<(Self, TimeFormat), PcapHeaderError> {
            const PCAP_HEADER_T1_BE: u32 = 0xA1_B2_C3_D4;
            const PCAP_HEADER_T2_BE: u32 = 0xA1_B2_3C_4D;

            const PCAP_HEADER_T1_LE: u32 = 0xD4_C3_B2_A1;
            const PCAP_HEADER_T2_LE: u32 = 0x4D_3C_B2_A1;

            match magic_number {
                PCAP_HEADER_T1_BE => Ok((Self::Big, TimeFormat::SecondsAndMicroseconds)),
                PCAP_HEADER_T2_BE => Ok((Self::Big, TimeFormat::SecondsAndNanoseconds)),
                PCAP_HEADER_T1_LE => Ok((Self::Little, TimeFormat::SecondsAndMicroseconds)),
                PCAP_HEADER_T2_LE => Ok((Self::Little, TimeFormat::SecondsAndNanoseconds)),
                v => Err(PcapHeaderError::BadMagicNumber(v)),
            }
        }

        fn read_u16(&self, v: &[u8]) -> u16 {
            let buf: [u8; 2] = v.try_into().unwrap_or_default();

            match self {
                Self::Big => u16::from_be_bytes(buf),
                Self::Little => u16::from_le_bytes(buf),
            }
        }

        fn read_u32(&self, v: &[u8]) -> u32 {
            let buf: [u8; 4] = v.try_into().unwrap_or_default();

            match self {
                Self::Big => u32::from_be_bytes(buf),
                Self::Little => u32::from_le_bytes(buf),
            }
        }
    }

    impl TimeFormat {
        fn parse(&self, seconds: u32, fraction: u32) -> time::SystemTime {
            time::UNIX_EPOCH
                + time::Duration::new(
                    seconds as u64,
                    match self {
                        Self::SecondsAndNanoseconds => fraction,
                        Self::SecondsAndMicroseconds => fraction * 1_000,
                    },
                )
        }
    }

    #[derive(Debug)]
    struct Version {
        major: u16,
        minor: u16,
    }

    #[derive(Debug)]
    pub struct PcapHeader {
        version: Version,
        endianess: Endianess,
        ts_format: TimeFormat,
        snapshot_len: u32,
        fcs_and_link_type: u32,
    }

    impl PcapHeader {
        fn parse_from<R: io::Read>(reader: &mut R) -> Result<Self, PcapHeaderError> {
            //                         1                   2                   3
            //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //  0 |                          Magic Number                         |
            //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //  4 |          Major Version        |         Minor Version         |
            //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //  8 |                           Reserved1                           |
            //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // 12 |                           Reserved2                           |
            //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // 16 |                            SnapLen                            |
            //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            // 20 | FCS |f|                   LinkType                            |
            //    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            const HEADER_SIZE: usize = 24;

            let mut header_bytes = [0u8; HEADER_SIZE];
            reader.read_exact(&mut header_bytes)?;

            let magic = header_bytes
                .first_chunk::<4>()
                .map_or(0, |&v| u32::from_be_bytes(v));

            let (endianess, ts_format) = Endianess::from_magic(magic)?;

            Ok(PcapHeader {
                version: Version {
                    major: endianess.read_u16(&header_bytes[4..6]),
                    minor: endianess.read_u16(&header_bytes[6..8]),
                },
                snapshot_len: endianess.read_u32(&header_bytes[16..20]),
                fcs_and_link_type: endianess.read_u32(&header_bytes[20..24]),
                endianess: endianess,
                ts_format: ts_format,
            })
        }
    }

    pub struct Frame {
        timestamp: time::SystemTime,
        captured_len: u32,
        original_len: u32,
        packet_data: Vec<u8>,
    }

    impl Frame {
        fn parse_from<R: io::Read>(
            reader: &mut R,
            endianess: &Endianess,
            time_format: &TimeFormat,
        ) -> Result<Option<Frame>, PcapFrameError> {
            //                         1                   2                   3
            //     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //   0 |                      Timestamp (Seconds)                      |
            //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //   4 |            Timestamp (Microseconds or nanoseconds)            |
            //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //   8 |                    Captured Packet Length                     |
            //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //  12 |                    Original Packet Length                     |
            //     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            //  16 /                                                               /
            //     /                          Packet Data                          /
            //     /                        variable length                        /
            //     /                                                               /
            //     +---------------------------------------------------------------+
            const FRAME_HEADER_SIZE: usize = 16;

            let mut frame_header = [0u8; FRAME_HEADER_SIZE];

            match reader.read_exact(&mut frame_header) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
                Err(v) => return Err(v.into()),
            }

            let captured_len = endianess.read_u32(&frame_header[8..12]);
            let mut packet_data = vec![0u8; captured_len as usize];

            reader.read_exact(&mut packet_data)?;

            Ok(Some(Frame {
                timestamp: time_format.parse(
                    endianess.read_u32(&frame_header[0..4]),
                    endianess.read_u32(&frame_header[4..8]),
                ),
                captured_len: captured_len,
                original_len: endianess.read_u32(&frame_header[12..16]),
                packet_data,
            }))
        }
    }

    pub struct PcapReader<R: io::Read> {
        reader: R,
        header: PcapHeader,
    }

    impl<R: io::Read> PcapReader<R> {
        pub fn new(mut reader: R) -> Result<Self, PcapError> {
            let header = PcapHeader::parse_from(&mut reader)?;

            Ok(Self { reader, header })
        }

        pub fn header(&self) -> &PcapHeader {
            &self.header
        }

        pub fn next_frame(&mut self) -> Result<Option<Frame>, PcapFrameError> {
            Frame::parse_from(
                &mut self.reader,
                &self.header.endianess,
                &self.header.ts_format,
            )
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn decode_endianess() {
            for (magic, expect) in [
                (
                    (0xA1_B2_C3_D4 as u32),
                    Some((Endianess::Big, TimeFormat::SecondsAndMicroseconds)),
                ),
                (
                    (0xA1_B2_3C_4D as u32),
                    Some((Endianess::Big, TimeFormat::SecondsAndNanoseconds)),
                ),
                ((0x100 as u32), None),
            ] {
                match expect {
                    Some(val) => assert_eq!(Endianess::from_magic(magic).unwrap(), val),
                    None => {
                        let _ = Endianess::from_magic(magic).unwrap_err();
                    }
                }
            }
        }

        #[test]
        fn decode_pcap_header() {
            // Standard PCAP magic (0xA1B2C3D4), version 2.4, little endian
            const PCAP_HEADER_BYTES: [u8; 24] = [
                0xD4, 0xC3, 0xB2, 0xA1, // Magic: 0xA1B2C3D4 in LE
                0x02, 0x00, // Major version: 2
                0x04, 0x00, // Minor version: 4
                0x00, 0x00, 0x00, 0x00, // Reserved1 (ignored)
                0x00, 0x00, 0x00, 0x00, // Reserved2 (ignored)
                0xFF, 0xFF, 0x00, 0x00, // SnapLen: 65535
                0x01, 0x00, 0x00, 0x00, // LinkType: 1 (Ethernet)
            ];

            let mut cursor = io::Cursor::new(PCAP_HEADER_BYTES);
            let header = PcapHeader::parse_from(&mut cursor).unwrap();

            assert_eq!(header.version.major, 2);
            assert_eq!(header.version.minor, 4);
            assert_eq!(header.endianess, Endianess::Little);
            assert_eq!(header.ts_format, TimeFormat::SecondsAndMicroseconds);
            assert_eq!(header.snapshot_len, 65535);
            assert_eq!(header.fcs_and_link_type, 1);
        }
    }
}
