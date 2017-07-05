
mod stdout_writer;

extern crate clap;
extern crate xor_utils;
extern crate hex;
extern crate base64;

#[macro_use] extern crate log;
extern crate env_logger;

use log::LogLevel;
use clap::{App, Arg, ArgMatches};
use std::io;
use std::io::{Cursor};
use std::fs;
use std::path::Path;
use std::fs::{File, OpenOptions, DirEntry};
use std::io::{Write, Read};
use xor_utils::Xor;
use xor_utils::*;
use hex::{ToHex};


fn main() {
    env_logger::init().unwrap();

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

    if matches.is_present("recursive") {
        // Recursively encrypt files and folders in the specified directory.
        let starting_dir_name = matches.value_of("recursive").unwrap();
        let starting_dir = Path::new(starting_dir_name);

        encrypt_path(starting_dir, &key_bytes);
    } else {
        // If the "file" argument was supplied input will be read from the file, otherwise
        // input is read from stdin.
        let input : Box<Read> = if matches.is_present("input") {
            Box::new(File::open(matches.value_of("input").unwrap()).unwrap())
        } else {
            Box::new(io::stdin())
        };

        // If "output" argument was supplied output will be written to a file, otherwise
        // it's written to stdout.
        let output : Box<Write> = if matches.is_present("output") {
            Box::new(OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(matches.value_of("output").unwrap())
                .unwrap())
        } else {
            Box::new(stdout_writer::StdoutWriter{})
        };

        encrypt_reader(input, &key_bytes, output);
    }
}

fn encrypt_reader(mut input : Box<Read>, key : &Vec<u8>, mut output : Box<Write>) {
    let encoded_bytes = input.by_ref().xor(&key);
    let _ = output.write_all(encoded_bytes.as_slice());
    output.flush().unwrap();
}

fn encrypt_path(p : &Path, key : &Vec<u8>) {
    for item in fs::read_dir(p).unwrap() {
        let entry = item.unwrap();
        xor_entry(&entry, key);
    }
}

fn xor_entry(entry : &DirEntry, key : &Vec<u8>) {
    if let Ok(entry_type) = entry.file_type() {
        if entry_type.is_dir() {
            xor_dir(entry, key);
        } else if entry_type.is_file() {
            xor_file(entry, key);
        } else if entry_type.is_symlink() {
            xor_symlink(entry, key);
        }
    }
}

fn xor_file(entry : &DirEntry, key : &Vec<u8>) {
    info!("Encrypting file {:?}", entry);

    if let Ok(mut file) = File::open(entry.path()) {
        let mut reader = &mut file as &mut Read;
        let cypher_text = reader.xor(&key);

        let mut writer = OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(entry.path())
            .unwrap();

        writer.write_all(cypher_text.as_slice()).unwrap();
    }
}

fn xor_symlink(entry : &DirEntry, key : &Vec<u8>) {
    info!("Encrypting symlink {:?}", entry);
}

fn xor_dir(entry : &DirEntry, key : &Vec<u8>) {
    info!("Encrypting dir {:?}", entry);

    match fs::read_dir(entry.path()) {
        Ok(entries) => {
            for child in entries {
                if let Ok(child) = child {
                    xor_entry(&child, key);
                }
            }
        },
        Err(e) => {
            let mut stderr = io::stderr();
            let _ = stderr.write_fmt(format_args!("Failed to read directory: {}", e));
        }
    }

    // Encrypt the directory entry itself.
    let file_name = entry.file_name();

    if let Some(original_name) = file_name.to_str() {

        let mut encrypted = Vec::with_capacity(original_name.len());
        for (d, k) in original_name.as_bytes().iter().zip(key) {
            encrypted.push(d ^ k);
        }

        let hex_name = to_hex(encrypted);
        let encrypted_name = base64::encode(hex_name.as_slice());


        let full_path_buf = entry.path();
        let full_path = full_path_buf.as_path();
        let parent_path = full_path.parent().unwrap();

        let src_file_path_buf = parent_path.join(original_name);
        let dst_file_path_buf = parent_path.join(encrypted_name);
        let src_file_path = src_file_path_buf.as_path();
        let dst_file_path = dst_file_path_buf.as_path();


        // TODO: REMOVE
        //println!("full {:?} parent {:?}", full_path, parent);
        println!("Mv {:?} to {:?}", src_file_path, dst_file_path);




        fs::rename(src_file_path, dst_file_path).unwrap();
    }
}

fn to_hex(bytes : Vec<u8>) -> Vec<u8> {
    static CHARS: &'static [u8] = b"0123456789abcdef";

    let mut v = Vec::with_capacity(bytes.len() * 2);
    for &byte in bytes.iter() {
        v.push(CHARS[(byte >> 4) as usize]);
        v.push(CHARS[(byte & 0xf) as usize]);
    }

    v
}

fn get_key_bytes<'a>(matches: &'a ArgMatches<'a>) -> Vec<u8> {
    let mut key_bytes : Vec<u8> = Vec::new();

    let key = matches.value_of("key").unwrap();

    // If the key is a file, read the contents of the file.
    // Otherwise if key is a string, use the string bytes.
    if Path::new(key).exists() {
        File::open(key).unwrap().read_to_end(&mut key_bytes).unwrap();
    } else {
        key_bytes = key.to_string().into_bytes();
    }

    key_bytes
}

