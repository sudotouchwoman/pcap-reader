use std::{
    env,
    fmt::{self, Debug},
    fs, process,
};

use thiserror::Error;
use users::{get_current_uid, get_user_by_uid};

mod ethernet;
mod pcap;
mod tcpip;

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

    let mut reasm = tcpip::NetworkReassembler::default();

    println!("parsed header: {:?}", pcap_reader.header());

    let mut frame_count = 0 as usize;

    loop {
        match pcap_reader.next_frame() {
            Ok(Some(frame)) => {
                // process frame
                print!("{frame_count}:{frame}: ");
                frame_count += 1;

                if let Ok(lf) = ethernet::LinkFrame::parse(&frame.packet_data) {
                    print!("{} - ", lf);

                    use tcpip::ReassemblyResult::{Incomplete, NopIp, Ready, Rejected};

                    match tcpip::NetworkPacket::parse(lf.ether_type, lf.payload) {
                        Ok(pkt) => match reasm.process(&pkt) {
                            Ready(d) => println!("ready: {d}"),
                            Incomplete => println!("fragment buffered"),
                            Rejected(e) => println!("reject fragment: {}", e),
                            NopIp => println!("non-ip: {}", pkt),
                        },
                        Err(e) => {
                            println!("while parsing network packet: {}", e);
                        }
                    }
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
