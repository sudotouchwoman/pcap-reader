pub mod ethernet;
pub mod event;
pub mod ip;
pub mod pcap;

#[cfg(test)]
mod tests {
    use std::cmp::min;

    #[test]
    fn decode_binary_sequence() {
        const BYTES: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

        let be_decoded = u32::from_be_bytes(BYTES);
        let le_decoded = u32::from_le_bytes(BYTES);

        assert_eq!(be_decoded, 0x12_34_56_78);
        assert_eq!(le_decoded, 0x78_56_34_12);
    }

    #[test]
    fn decode_two_u16() {
        const BYTES: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

        const BYTES_FIRST_PART: [u8; 2] = [BYTES[0], BYTES[1]];
        const BYTES_SECOND_PART: [u8; 2] = [BYTES[2], BYTES[3]];

        // in general case, when input data range is unknown and we can perform runtime computations, would be like:
        let bytes_first_part: [u8; 2] = BYTES
            .get(0..2)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0, 0]);
        let bytes_second_part: [u8; 2] = BYTES
            .get(2..4)
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0, 0]);

        const FIRST_PART: u16 = 0x_12_34;
        const SECOND_PART: u16 = 0x_56_78;

        assert_eq!(FIRST_PART, u16::from_be_bytes(bytes_first_part));
        assert_eq!(FIRST_PART, u16::from_be_bytes(BYTES_FIRST_PART));

        assert_eq!(SECOND_PART, u16::from_be_bytes(bytes_second_part));
        assert_eq!(SECOND_PART, u16::from_be_bytes(BYTES_SECOND_PART));
    }

    #[test]
    fn decode_length_prefixed_blob() {
        const LENGTH_PREFIX_SIZE: usize = 2;

        let blob: [u8; _] = [0, 5, b'b', b'y', b't', b'e', b'z'];

        // the two ways of handling Result<T, E> and Option<T> for error handling
        // personally, I would prefer the latter one since we avoid obsolete creation of a temporary
        // array and clearly and directly output zero, which is basically what [0, 0] means
        let length_prefix_no_map = u16::from_be_bytes(
            blob.get(..LENGTH_PREFIX_SIZE)
                .and_then(|s| s.try_into().ok())
                .unwrap_or_else(|| [0, 0]),
        );

        let length_prefix_with_map = blob
            .get(..LENGTH_PREFIX_SIZE)
            .and_then(|s| s.try_into().ok())
            .map(u16::from_be_bytes)
            .unwrap_or_else(|| 0);

        assert_eq!(length_prefix_no_map, length_prefix_with_map);
        assert_eq!(usize::from(length_prefix_with_map), blob.len() - 2);

        // this is how one slices and returns a default value
        let payload = blob
            .get(LENGTH_PREFIX_SIZE..LENGTH_PREFIX_SIZE + usize::from(length_prefix_with_map))
            .unwrap_or(&[]);

        // this is how one converts byte slice to a utf8 string
        let payload_str = std::str::from_utf8(payload).unwrap_or("");

        assert_eq!(payload_str, "bytez");
    }

    #[test]
    fn decode_pcap_header() {
        // the plan:
        // 1. read the entire header (24 octets, i.e. bytes / u8) into a buffer
        // 2. parse it into components, test that magic number is correct, deduce endianess
        // 3. construct a struct from the components
    }
}
