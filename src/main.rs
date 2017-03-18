
extern crate clap;

use clap::{App, Arg};
use std::io;
use std::io::BufRead;
use std::io::BufReader;
use std::fs::File;

fn main() {

    // Parse arguments and provide help.
    let matches = App::new("rxor")
        .version("1.0.0")
        .about("XORs input against a provided key")
        .author("Gavyn Riebau")
        .arg(Arg::with_name("key")
             .help("The key against which input will be XOR'd. This should be larger than the given input data or will need to be repeated to encode the input data.")
             .long("key")
             .short("k")
             .required(true)
             .value_name("KEY"))
        .arg(Arg::with_name("file")
             .help("The file from which input data will be read, if omitted input will be read from stdin")
             .long("input")
             .short("i")
             .required(false)
             .value_name("FILE"))
     .get_matches();

    let key = matches.value_of("key").unwrap();
    let stdin = io::stdin();

    // If the "file" argument was supplied input will be read from the file, otherwise
    // input is read from stdin.
    let input : Box<std::io::BufRead> = if matches.is_present("file") {
        Box::new(BufReader::new(File::open(matches.value_of("file").unwrap()).unwrap()))
    } else {
        Box::new(stdin.lock())
    };

    // TODO: Read chunks of input rather than lines (otherwise newline chars won't be encoded).
    //
    // Iterate each chunk of input and XOR it against the key.
    for line in input.lines() {
        let data = line.unwrap();
        let data_bytes = data.into_bytes();
        let key_bytes = key.as_bytes();

        let k = key_bytes[0];

        let mut encoded_bytes: Vec<u8> = Vec::new();

        for b in data_bytes {
            let e = b ^ k;
            encoded_bytes.push(e);
        }

        let encoded = String::from_utf8(encoded_bytes);

        println!("{}", encoded.unwrap());
    }
}
