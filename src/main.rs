
extern crate clap;
extern crate xor_utils;

use clap::{App, Arg, ArgMatches};
use std::io;
use std::fs;
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
        .version("1.3.0")
        .about("XORs input against a provided key")
        .author("Gavyn Riebau")
        .arg(Arg::with_name("key")
             .help("The file containing the key data, or a provided string, against which input will be XOR'd. This should be larger than the given input data or will need to be repeated to encode the input data.")
             .long("key")
             .short("k")
             .required(true)
             .value_name("KEY"))
        .arg(Arg::with_name("input")
             .help("The file / directory from which input data will be read, if omitted input will be read from stdin.\nIf a directory is specified, all files inside the directory will be encryted.")
             .long("input")
             .short("i")
             .required(false)
             .value_name("FILE"))
        .arg(Arg::with_name("recursive")
             .help("Recursively encrypt files and subfolders starting at the given directory")
             .long("recursive")
             .short("r")
             .conflicts_with("output")
             .value_name("DIRECTORY"))
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

    if matches.is_present("recursive") {
        // Recursively encrypt files and folders in the specified directory.
        let starting_dir_name = matches.value_of("recursive").unwrap();
        let starting_dir = Path::new(starting_dir_name);

        if !starting_dir.is_dir() {
            panic!("Supplied value for option 'recursive' was not a directory.")
        }

        recursively_encrypt(starting_dir);
    } else {
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
}

fn recursively_encrypt(p : &Path) {
    if p.is_dir() {
        println!("Path was a directory");
        match fs::read_dir(p) {
            Ok(entries) => {
                for entry in entries {
                    if let Ok(entry) = entry {
                        if let Ok(file_type) = entry.file_type() {
                            println!("{:?} - {:?}", entry.path(), file_type);
                            if file_type.is_dir() {
                                let p = &entry.path();
                                let path = Path::new(p);
                                recursively_encrypt(path);
                            }
                        }
                    }
                }
            },
            Err(e) => {
                let mut stderr = io::stderr();
                let _ = stderr.write_fmt(format_args!("Failed to read directory: {}", e));
            }
        }
    } else if p.is_file() {
        println!("Path was a file");
    } else {
        println!("Path was something else");
    }
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
