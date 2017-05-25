
extern crate clap;
extern crate xor_utils;

use clap::{App, Arg, ArgMatches};
use std::io;
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::{Write, Read};
use xor_utils::Xor;

const ERR_ENCODED_DATA_NOT_UTF8 : &'static str = r#"ERROR: Encoded data isn't printable.

The encoded data couldn't be encoded to valid utf8 and so couldn't be printed to the screen.
Use the "-o" option to write the output directly to a file instead."#;

fn main() {

    // Parse arguments and provide help.
    let matches = App::new("xor")
        .version("1.2.2")
        .about("XORs input against a provided key")
        .author("Gavyn Riebau")
        .arg(Arg::with_name("key")
             .help("The file containing the key data, or a provided string, against which input will be XOR'd. This should be larger than the given input data or will need to be repeated to encode the input data.")
             .long("key")
             .short("k")
             .required(true)
             .value_name("KEY"))
        .arg(Arg::with_name("input")
             .help("The file from which input data will be read, if omitted input will be read from stdin")
             .long("input")
             .short("i")
             .required(false)
             .value_name("FILE"))
        .arg(Arg::with_name("output")
             .help("The file to which encoded data will be written, if omitted output will be written to stdout.\nIt's recommended to write output to a file for cases where the encoded data contains non-unicode characters.")
             .long("output")
             .short("o")
             .required(false)
             .value_name("FILE"))
        .arg(Arg::with_name("verbose")
             .help("Increases the level of feedback given")
             .long("verbose")
             .short("v")
             .required(false))
         .get_matches();

    let key_bytes = get_key_bytes(&matches);
    let stdin = io::stdin();

    // If the "file" argument was supplied input will be read from the file, otherwise
    // input is read from stdin.
    let mut input : Box<Read> = if matches.is_present("input") {
        Box::new(File::open(matches.value_of("input").unwrap()).unwrap())
    } else {
        Box::new(stdin.lock())
    };

    let encoded_bytes = input.by_ref().xor(key_bytes);

    write_encoded_bytes(&matches, encoded_bytes);
}

fn get_key_bytes<'a>(matches: &'a ArgMatches<'a>) -> Vec<u8> {
    let mut key_bytes : Vec<u8> = Vec::new();

    let key = matches.value_of("key").unwrap();
    if Path::new(key).exists() {
        // Key is a file, read the contents of the file.
        File::open(key).unwrap().read_to_end(&mut key_bytes).unwrap();
    } else {
        // Key is a string, use the string bytes
        key_bytes = key.to_string().into_bytes();
    }

    key_bytes
}

fn write_encoded_bytes<'a>(matches : &'a ArgMatches<'a>, encoded_bytes : Vec<u8>) {
    if matches.is_present("output") {
        let mut output = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(matches.value_of("output").unwrap())
            .unwrap();
        let _ = output.write_all(encoded_bytes.as_slice());
        output.flush().unwrap();
    } else {
        match String::from_utf8(encoded_bytes) {
            Ok(encoded) => println!("{}", encoded),
            Err(e) => println!("{}\n\nDetails: {}", ERR_ENCODED_DATA_NOT_UTF8, e)
        }
    }
}
