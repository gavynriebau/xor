
mod stdout_writer;

extern crate clap;
extern crate xor_utils;
extern crate hex;
extern crate base64;

#[macro_use] extern crate log;
extern crate env_logger;

use clap::{App, Arg, ArgMatches};
use std::io;
use std::fs;
use std::path::Path;
use std::fs::{File, OpenOptions, DirEntry};
use std::io::{Write, Read};
use xor_utils::Xor;

/// The mode is used in conjunction with the "recursive" option and determines how file names
/// will be processed when renaming files.
/// When in "encrypt" mode, file names are XOR'd then hexified.
/// When in "decrypt" mode, file names are unhexified then XOR'd.
enum Mode {
    Encrypt,
    Decrypt
}

static ABOUT: &str = "
XOR encrypt files or directories using a supplied key.

In it's simplest form, reads input from stdin, encrypts it against a key and writes the result to stdout.
The \"key\" option can be either a path to a file or a string of characters.

When the \"recursive\" option is used, files under a given directory are recursively encrypted.
Files are renamed by XORing the original name against the provided key, then hexifying the result.
To decrypt you must use the \"mode\" option with the value \"d\", files are then renamed by unhexifying then XORing.
";

fn main() {
    env_logger::init().unwrap();

    // Parse arguments and provide help.
    let matches = App::new("xor")
        .version("1.4.0")
        .about(ABOUT)
        .author("Gavyn Riebau")
        .arg(Arg::with_name("key")
             .help("The file containing the key data, or a provided string, against which input will be XOR'd.\nThis should be larger than the given input data or will need to be repeated to encode the input data.")
             .long("key")
             .short("k")
             .required(true)
             .value_name("KEY"))
        /*
        .arg(Arg::with_name("force")
             .help("Don't show warning prompt if the key size is too small and key bytes will have to be re-used.\nRe-using key bytes makes the encryption vulnerable to being decrypted.")
             .long("force")
             .short("f"))
             */
        .arg(Arg::with_name("decrypt")
             .help("Decrypt directory names rather than encrypting them.\nApplies when using the \"recursive\" option to encrypt a directory.\nWhen set, directory names are decrypted by unhexifying then XORing.\nWhen not set, directory names are encrypted by XORing then hexifying.")
             .long("decrypt")
             .short("d"))
        .arg(Arg::with_name("input")
             .help("The file from which input data will be read, if omitted, and the \"recursive\" option isn't used, input will be read from stdin.")
             .long("input")
             .short("i")
             .required(false)
             .value_name("FILE"))
        .arg(Arg::with_name("recursive")
             .help("Recursively encrypt / decrypt files and subfolders starting at the given directory.\nFiles and directory names will be encrypted / decrypted according to the \"mode\" argument.\nNames are xor encrypted then converted to a hex string.")
             .long("recursive")
             .short("r")
             .value_name("DIRECTORY")
             .conflicts_with("input")
             .conflicts_with("output"))
        .arg(Arg::with_name("output")
             .help("The file to which encoded data will be written, if omitted output will be written to stdout.\nIt's recommended to write output to a file for cases where the encoded data contains non-unicode characters which would otherwise not be printed to the console.")
             .long("output")
             .short("o")
             .required(false)
             .value_name("FILE"))
         .get_matches();

    // Parse the mode of operation, defaulting to encrypt mode.
    let mode = if matches.is_present("decrypt") {
        Mode::Decrypt
    } else {
        Mode::Encrypt
    };

    // Read all the key bytes into memory.
    let key_bytes = get_key_bytes(&matches);

    if matches.is_present("recursive") {
        trace!("Recursively encrypting files and folders.");

        let starting_dir_name = matches.value_of("recursive").unwrap();
        let starting_dir = Path::new(starting_dir_name);

        encrypt_path(starting_dir, &key_bytes, &mode);
    } else {

        let input : Box<Read> = if matches.is_present("input") {
            trace!("Reading input from a file.");
            Box::new(File::open(matches.value_of("input").unwrap()).unwrap())
        } else {
            trace!("Reading input from stdin.");
            Box::new(io::stdin())
        };

        let output : Box<Write> = if matches.is_present("output") {
            trace!("Writting output to a file.");
            Box::new(OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(matches.value_of("output").unwrap())
                .unwrap())
        } else {
            trace!("Writting output to stdout.");
            Box::new(stdout_writer::StdoutWriter{})
        };

        encrypt_reader(input, &key_bytes, output);
    }
}

/// XOR's all the bytes from reader against the provided key then writes the result to the output
/// writer.
fn encrypt_reader(mut input : Box<Read>, key : &Vec<u8>, mut output : Box<Write>) {
    let encoded_bytes = input.by_ref().xor(&key);
    let _ = output.write_all(encoded_bytes.as_slice());
    output.flush().unwrap();
}

fn encrypt_path(p : &Path, key : &Vec<u8>, mode : &Mode) {
    for item in fs::read_dir(p).unwrap() {
        match item {
            Ok(entry) => xor_entry(&entry, key, mode),
            Err(err) => info!("Failed to read entry because: {}", err)
        }
    }
}

fn xor_entry(entry : &DirEntry, key : &Vec<u8>, mode : &Mode) {
    match entry.file_type() {
        Ok(entry_type) => {
            if entry_type.is_dir() {
                xor_dir(entry, key, mode);
            } else if entry_type.is_file() {
                xor_file(entry, key, mode);
            } else if entry_type.is_symlink() {
                xor_symlink(entry, key, mode);
            }
        },
        Err(err) => info!("Failed to get filetype for DirEntry {:?} because: {}", entry, err)
    }
}

fn xor_file(entry : &DirEntry, key : &Vec<u8>, mode : &Mode) {
    debug!("Encrypting file {:?}", entry);

    match File::open(entry.path()) {
        Ok(mut file) => {
            let mut reader = &mut file as &mut Read;
            let cypher_text = reader.xor(&key);

            let output = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(entry.path());

            match output {
                Ok(mut writer) => {
                    match writer.write_all(cypher_text.as_slice()) {
                        Ok(_) => {},
                        Err(err) => info!("Failed to write encrypted bytes to file because: {}", err)
                    }
                },
                Err(err) => info!("Failed to open file with truncate option for DirEntry {:?} because: {}", entry, err)
            }
        },
        Err(err) => info!("Failed to open file for DirEntry {:?} because: {}", entry, err)
    }

    rename_entry(entry, key, mode);
}

fn xor_symlink(entry : &DirEntry, key : &Vec<u8>, mode : &Mode) {
    debug!("Encrypting symlink {:?}", entry);

    rename_entry(entry, key, mode);
}

fn xor_dir(entry : &DirEntry, key : &Vec<u8>, mode : &Mode) {
    debug!("Encrypting dir {:?}", entry);

    match fs::read_dir(entry.path()) {
        Ok(entries) => {
            for child in entries {
                if let Ok(child) = child {
                    xor_entry(&child, key, mode);
                }
            }
        },
        Err(e) => {
            let mut stderr = io::stderr();
            let _ = stderr.write_fmt(format_args!("Failed to read directory: {}", e));
        }
    }

    rename_entry(entry, key, mode);
}

/// Renames a directory entry.
/// When "mode" is Mode::Encrypt, the name of the entry is XOR'd then hexlified.
/// When "mode" is Mode::Decrypt, the name of the entry is unhexlified then XOR'd.
fn rename_entry(entry : &DirEntry, key : &Vec<u8>, mode : &Mode) {
    let file_name = entry.file_name();

    if let Some(original_name) = file_name.to_str() {
        debug!("original_name: {}", original_name);

        let key_repeated = repeat_key(key, original_name.len());

        // If in Encrypt mode use the filename as is.
        // If in Decrypt mode unhexify the filename before getting it's bytes.
        let input_bytes = match *mode {
            Mode::Encrypt => original_name.to_string().into_bytes(),
            Mode::Decrypt => from_hex_string(String::from(original_name))
        };

        // Xor encrypt the name.
        let mut encrypted = Vec::with_capacity(input_bytes.len());
        for (d, k) in input_bytes.iter().zip(key_repeated) {
            encrypted.push(d ^ k);
        }

        // If in Encrypt mode hexify the filename.
        // If in Decrypt mode just use the filename as is.
        let replaced_name = match *mode {
            Mode::Encrypt => to_hex_string(encrypted),
            Mode::Decrypt => String::from_utf8(encrypted).unwrap()
        };
        debug!("replaced_name: {}", replaced_name);

        let full_path_buf = entry.path();
        let full_path = full_path_buf.as_path();
        let parent_path = full_path.parent().unwrap();

        let src_file_path_buf = parent_path.join(original_name);
        let dst_file_path_buf = parent_path.join(replaced_name);

        let src_file_path = src_file_path_buf.as_path();
        let dst_file_path = dst_file_path_buf.as_path();

        debug!("Moving {:?} to {:?}", src_file_path, dst_file_path);

        match fs::rename(src_file_path, dst_file_path) {
            Ok(_) => {},
            Err(e) => info!("Failed to rename file because: {}", e)
        }
    }
}

/// Create a vector of bytes equal in length to the name of the file.
/// If the key is too small it'll be repeated to make up the required length.
fn repeat_key(key : &Vec<u8>, required_len : usize) -> Vec<u8> {
    let mut key_repeated = Vec::with_capacity(required_len);

    while key_repeated.len() < required_len {
        for &b in key {
            key_repeated.push(b);

            if key_repeated.len() == required_len {
                break;
            }
        }
    }

    key_repeated
}

fn to_hex_string(bytes: Vec<u8>) -> String {
    let strings: Vec<String> = bytes
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect();

    strings.join("")
}

fn from_hex_string(hex : String) -> Vec<u8> {
    hex::FromHex::from_hex(hex).unwrap()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn to_hex_string_works() {
        let input_string = String::from("hello");
        let input_bytes = input_string.into_bytes();

        let hex_string = to_hex_string(input_bytes);
        assert_eq!(hex_string, "68656C6C6F");
    }

    #[test]
    fn from_hex_string_works() {
        let input_string = String::from("68656C6C6F");
        let ascii_bytes = from_hex_string(input_string);
        let expected_bytes = vec![104, 101, 108, 108, 111];

        assert_eq!(expected_bytes, ascii_bytes);
    }

}

