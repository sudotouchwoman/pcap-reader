use std::{
    env,
    fmt::{self, Debug},
    fs, process,
};

use thiserror::Error;
use users::{get_current_uid, get_user_by_uid};

use ros_flake::{event, pcap};

fn greet(name: &str) -> String {
    format!("Greetings, {}", name)
}

fn main() {
    let user: String = get_user_by_uid(get_current_uid())
        .map(|user| user.name().to_string_lossy().into_owned())
        .unwrap_or_else(|| "anon".to_string());

    println!("{}", greet(user.as_str()));

    let args: Vec<String> = env::args().collect();

    let config = parse_args(&args).unwrap_or_else(display_and_exit);

    println!("parsed: {config:?}");

    let f = fs::File::open(config.pcap_filename).unwrap_or_else(display_and_exit);
    let mut pcap_reader = pcap::PcapReader::new(f).unwrap_or_else(display_and_exit);

    let mut decoder = event::Decoder::new();

    println!("parsed header: {:?}", pcap_reader.header());

    let mut frame_count = 0 as usize;

    loop {
        match pcap_reader.next_frame() {
            Ok(Some(frame)) => {
                // process frame
                println!("{frame_count}:{frame}:");
                frame_count += 1;

                for event in decoder.push_frame(&frame.packet_data) {
                    println!("{event}")
                }
            }
            Ok(None) => break,
            Err(e) => display_and_exit(e),
        }
    }
}

fn display_and_exit<T: fmt::Display, V>(err: T) -> V {
    println!("while parsing arguments: {err}");
    process::exit(1);
}

#[derive(Error, Debug)]
enum ConfigError {
    #[error("not enough arguments: expected at least {expected}, got {actual}")]
    NotEnoughArgs { expected: usize, actual: usize },
}

#[derive(Debug)]
struct Config {
    pcap_filename: String,
}

fn parse_args(args: &[String]) -> Result<Config, ConfigError> {
    let args_len = args.len();
    if args_len < 2 {
        return Err(ConfigError::NotEnoughArgs {
            expected: 2,
            actual: args_len,
        });
    }

    Ok(Config {
        pcap_filename: args[1].clone(),
    })
}
