
extern crate clap;

use clap::{App, Arg};
use std::io;
use std::fs::File;
use std::io::Write;

fn main() {

    // Parse arguments and provide help.
    let matches = App::new("xor")
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
    let key_bytes = key.as_bytes();
    let key_len = key_bytes.len();
    let stdin = io::stdin();
    let mut key_idx = 0;
    let mut warning_shown = false;

    // If the "file" argument was supplied input will be read from the file, otherwise
    // input is read from stdin.
    let mut input : Box<std::io::Read> = if matches.is_present("file") {
        Box::new(File::open(matches.value_of("file").unwrap()).unwrap())
    } else {
        Box::new(stdin.lock())
    };

    // Iterate each chunk of input data and XOR it against the provided key.
    loop {
        let mut data = [0; 1024];
        let num_read = input.read(&mut data[..]).unwrap();

        if num_read == 0 {
            break;
        }

        let data_bytes = &data[0 .. num_read - 1];
        let mut encoded_bytes: Vec<u8> = Vec::new();

        for b in data_bytes {
            let k = key_bytes[key_idx];
            let e = b ^ k;

            encoded_bytes.push(e);

            key_idx += 1;

            if key_idx >= key_len {
                key_idx = key_idx % key_len;

                if !warning_shown {
                    warning_shown = true;
                    let _ = writeln!(&mut std::io::stderr(), "Key wasn't long enough and had to be re-used to fully encode data, use a longer key to be secure.");
                }
            }
        }

        let encoded = String::from_utf8(encoded_bytes);

        println!("{}", encoded.unwrap());
    }
}
