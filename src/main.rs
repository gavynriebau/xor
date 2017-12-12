
mod stdout_writer;

extern crate clap;
extern crate xor_utils;
extern crate hex;
extern crate base64;
extern crate number_prefix;
extern crate filesystem;

#[macro_use] extern crate log;
extern crate env_logger;

use clap::{App, Arg, ArgMatches};
use std::io;
use std::fs;
use std::path::Path;
use std::io::{Write, Read, Cursor};
use number_prefix::{binary_prefix, Standalone, Prefixed};
use filesystem::{FileSystem, DirEntry};

/// The mode is used in conjunction with the "recursive" option and determines how file names
/// will be processed when renaming files.
/// When in "encrypt" mode, file names are XOR'd then hexified.
/// When in "decrypt" mode, file names are unhexified then XOR'd.
#[derive(PartialEq, Eq)]
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
To decrypt you must use the \"decrypt\" flag, files are then renamed by unhexifying then XORing.
";

fn main() {
    env_logger::init().unwrap();

    // Parse arguments and provide help.
    let matches = App::new("xor")
        .version("1.4.5")
        .about(ABOUT)
        .author("Gavyn Riebau")
        .arg(Arg::with_name("key")
             .help("The file containing the key data, or a provided string, against which input will be XOR'd.\nThis should be larger than the given input data or will need to be repeated to encode the input data.")
             .long("key")
             .short("k")
             .required(true)
             .value_name("KEY"))
        .arg(Arg::with_name("force")
             .help("Don't show warning prompt if the key size is too small and key bytes will have to be re-used.\nRe-using key bytes makes the encryption vulnerable to being decrypted.")
             .long("force")
             .short("f"))
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
        // trace!("Recursively encrypting files and folders.");

        // let starting_dir_name = matches.value_of("recursive").unwrap();
        // let starting_dir = Path::new(starting_dir_name);

        // if mode == Mode::Decrypt || matches.is_present("force") || check_sizes(starting_dir, &key_bytes) {
        //     encrypt_path(starting_dir, &key_bytes, &mode);
        // }
    } else {

        // let mut output : Box<Write> = if matches.is_present("output") {
        //     trace!("Writting output to a file.");

        //     // let x = filesystem.path();

        //     // Box::new(OpenOptions::new()
        //     //     .write(true)
        //     //     .create(true)
        //     //     .truncate(true)
        //     //     .open(matches.value_of("output").unwrap())
        //     //     .unwrap())
        // } else {
        //     trace!("Writting output to stdout.");
        //     Box::new(stdout_writer::StdoutWriter{})
        // };

        if matches.is_present("input") {
            // trace!("Reading input from a file.");
            // let mut file_reader= File::open(matches.value_of("input").unwrap()).unwrap();
            // encrypt_reader(&mut file_reader, &key_bytes, output.deref_mut());
        } else {
            // trace!("Reading input from stdin.");
            // let mut stdin_reader = io::stdin();
            // encrypt_reader(&mut stdin_reader, &key_bytes, output.deref_mut());
        };
    }
}

/// XOR's all the bytes from reader against the provided key then writes the result to the output
/// writer.
fn encrypt_reader(input : &mut Read, key : &Vec<u8>, output : &mut Write) {
    let mut buffer = [0; 512];
    loop {
        match input.read(&mut buffer) {
            Ok(n) => {
                info!("Read {} bytes", n);
                if n == 0 {
                    break;
                }
                let key_repeated = repeat_key(key, n);
                let encoded_bytes : Vec<u8> = buffer.iter().zip(key_repeated).map(|(d, k)| d ^ k).collect();
                let _ = output.write_all(encoded_bytes.as_slice());
                output.flush().unwrap();
            },
            Err(e) => {
                error!("Failed to read because: {}", e);
                break;
            }
        }
    }
}

//fn encrypt_path(p : &VPath, key : &Vec<u8>, mode : &Mode) {
    // for item in fs::read_dir(p).unwrap() {
    //     match item {
    //         Ok(entry) => xor_entry(&entry, key, mode),
    //         Err(err) => info!("Failed to read entry because: {}", err)
    //     }
    // }
//}

//fn xor_entry(entry : &VPath, key : &Vec<u8>, mode : &Mode) {
    // match entry.file_type() {
    //     Ok(entry_type) => {
    //         if entry_type.is_dir() {
    //             xor_dir(entry, key, mode);
    //         } else if entry_type.is_file() {
    //             xor_file(entry, key, mode);
    //         } else if entry_type.is_symlink() {
    //             xor_symlink(entry, key, mode);
    //         }
    //     },
    //     Err(err) => info!("Failed to get filetype for DirEntry {:?} because: {}", entry, err)
    // }
//}

fn xor_file<T : FileSystem>(fs : &T, file_path : &Path, key : &Vec<u8>, mode : &Mode) {
    debug!("Encrypting file {:?}", file_path);

    // match file_path.metadata() {
    //     Ok(metadata) => {
    //         let mut buffer : Cursor<Vec<u8>> = Cursor::new(Vec::with_capacity(metadata.len() as usize));

    //         encrypt_reader(&mut file, &key, &mut buffer);

    //         let output_options = OpenOptions::new()
    //             .create(true)
    //             .write(true)
    //             .truncate(true);

    //         match file_path.open_with_options(output_options) {
    //             Ok(mut writer) => {
    //                 let _ = writer.write_all(buffer.get_mut());
    //                 //let cloned_buffer = raw_buffer.clone();
    //                 //std::fs::rename(temp_file_path, entry.path()).unwrap();
    //             },
    //             Err(err) => info!("Failed to open file with truncate option for DirEntry {:?} because: {}", entry.path(), err)
    //         }
    //     },
    //     Err(err) => info!("Failed to read metadata of file at path {:?} because: {}", file_path, err)
    // }

   rename_entry(fs, file_path, key, mode);
}

// fn xor_symlink(entry : &DirEntry, key : &Vec<u8>, mode : &Mode) {
//     debug!("Encrypting symlink {:?}", entry);

//     rename_entry(entry, key, mode);
// }

// fn xor_dir(entry : &DirEntry, key : &Vec<u8>, mode : &Mode) {
//     debug!("Encrypting dir {:?}", entry);

//     match fs::read_dir(entry.path()) {
//         Ok(entries) => {
//             for child in entries {
//                 if let Ok(child) = child {
//                     xor_entry(&child, key, mode);
//                 }
//             }
//         },
//         Err(e) => {
//             let mut stderr = io::stderr();
//             let _ = stderr.write_fmt(format_args!("Failed to read directory: {}", e));
//         }
//     }

//     rename_entry(entry, key, mode);
// }

/// Renames a directory entry.
/// When "mode" is Mode::Encrypt, the name of the entry is XOR'd then hexlified.
/// When "mode" is Mode::Decrypt, the name of the entry is unhexlified then XOR'd.
fn rename_entry<T : FileSystem>(fs : &T, entry : &Path, key : &Vec<u8>, mode : &Mode) {

    if let Some(original_name_osstr) = entry.file_name() {
        let original_name = String::from(original_name_osstr.to_str().unwrap());
        debug!("original_name: {}", original_name);

        let key_repeated = repeat_key(key, original_name.len());

        // If in Encrypt mode use the filename as is.
        // If in Decrypt mode unhexify the filename before getting it's bytes.
        let input_bytes = match *mode {
            Mode::Encrypt => original_name.clone().into_bytes(),
            Mode::Decrypt => from_hex_string(&original_name)
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

        let parent_path = entry.parent().unwrap();
        let src_file_path = parent_path.join(&original_name);
        let dst_file_path = parent_path.join(&replaced_name);

        debug!("Moving {:?} to {:?}", src_file_path, dst_file_path);

        fs.rename(src_file_path, dst_file_path).unwrap();
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

fn from_hex_string(hex : &String) -> Vec<u8> {
    hex::FromHex::from_hex(hex).unwrap()
}

fn get_key_bytes<'a>(matches: &'a ArgMatches<'a>) -> Vec<u8> {
    let mut key_bytes : Vec<u8> = Vec::new();

    // let key = matches.value_of("key").unwrap();

    // // If the key is a file, read the contents of the file.
    // // Otherwise if key is a string, use the string bytes.
    // if Path::new(key).exists() {
    //     File::open(key).unwrap().read_to_end(&mut key_bytes).unwrap();
    // } else {
    //     key_bytes = key.to_string().into_bytes();
    // }

    key_bytes
}

/// Recursively searches the supplied path and finds the size of the largest file.
//fn get_largest_file_size(path : &VPath) -> u64 {
    // let mut size : u64 = 0;

    // match path.metadata() {
    //     Ok(metadata) => {
            
    //         // Check if the current file is the largest.
    //         if path.is_file() {
    //             size = metadata.len();
    //         } else if path.is_dir() {
    //             // Check if any of the child files are the largest.
    //             match path.read_dir() {
    //                 Ok(entries) => {
    //                     for entry in entries {
    //                         let entry_size = get_largest_file_size(entry.path().as_path());

    //                         if entry_size > size {
    //                             size = entry_size;
    //                         }
    //                     }
    //                 },
    //                 Err(err) => info!("Failed to read directory {:?} because: {}", path, err)
    //             }
    //         }
    //     },
    //     Err => info!("Failed to get metadata for path {:?} because: {}", path, err)
    // }

    // size
    //0
//}

/// Recursively searches the supplied path and finds the length of the longest file/directory name.
//fn get_longest_name(path : &VPath) -> usize {
    // let mut size : usize = 0;

    // // Check if the current entry name is the longest.
    // if let Some(name) = path.file_name() {
    //     let length = name.len();

    //     if length > size {
    //         size = length;
    //     }

    //     if path.is_dir() {
    //         // Check if any of the child directory / file names are the longest.
    //         for entry_result in fs::read_dir(path).unwrap() {
    //             if let Ok(entry) = entry_result {
    //                 let entry_size = get_longest_name(entry.path().as_path());

    //                 if entry_size > size {
    //                     size = entry_size;
    //                 }
    //             }
    //         }
    //     }
    // }

    // size

    //0
//}

// fn check_sizes(starting_directory : &Path, key_bytes : &Vec<u8>) -> bool {
//     let mut should_continue : bool = true;

//     let key_size = key_bytes.len();
//     let largest_file_size = get_largest_file_size(starting_directory);
//     let longest_name = get_longest_name(starting_directory);

//     if largest_file_size > key_size as u64 || longest_name > key_size {
//         print_keysize_warning(key_size, largest_file_size, longest_name);
//         let answer = show_prompt();
//         should_continue = answer == 'y';
//     }

//     should_continue
// }

fn show_prompt() -> char {
    let mut answer : char = '_';

    while answer != 'y' && answer != 'n' {
        print!("Do you want to continue? ('y'/'n')?: ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_) => {
                answer = input.remove(0);
            },
            Err(_) => answer = 'n'
        }
    }

    answer
}

fn print_keysize_warning(key_size : usize, largest_file_size : u64, longest_name : usize) {
    println!("
================================================================================
WARNING: The supplied key is too small to safely encrypt your files.
================================================================================

You are trying to use a key that is smaller than the largest file or smaller
than the longest directory name.
If you choose to proceed it's possible your files could be decrypted by
someone else.

It's recommended that you use a key that is larger.

Sizes:");

    match binary_prefix(key_size as f64) {
        Standalone(n)       => println!("{:>7} {:5} - Keysize (too small)", n, "Bytes"),
        Prefixed(prefix, n) => println!("{:>4.3} {}B   - Keysize (too small)", n, prefix)
    }
    match binary_prefix(largest_file_size as f64) {
        Standalone(n)       => println!("{:>7} {:5} - Largest file", n, "Bytes"),
        Prefixed(prefix, n) => println!("{:>7.3} {}B   - Largest file", n, prefix)
    }
    match binary_prefix(longest_name as f64) {
        Standalone(n)       => println!("{:>7} {:5} - Longest file or directory name", n, "Bytes"),
        Prefixed(prefix, n) => println!("{:>4.3} {}B   - Longest file or directory name", n, prefix)
    }

    println!("\n================================================================================");
}

#[cfg(test)]
mod tests {
    use super::*;
    use filesystem::*;

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
        let ascii_bytes = from_hex_string(&input_string);
        let expected_bytes = vec![104, 101, 108, 108, 111];

        assert_eq!(expected_bytes, ascii_bytes);
    }

    #[test]
    fn encrypt_reader_works() {
        let input = "hello";
        let expected = "Q\\UUV";

        let mut reader = Cursor::new(input.as_bytes());
        let key_bytes = vec![57;1];
        let mut writer : Cursor<Vec<u8>> = Cursor::new(Vec::new());

        encrypt_reader(&mut reader, &key_bytes, &mut writer);

        let cipher_text = String::from_utf8(writer.into_inner()).unwrap();

        assert_eq!(expected, cipher_text);
    }

    // Gets a list of files in the current directory of the given FileSystem type
    fn get_root_files<T : FileSystem>(fs : &T) -> Vec<String> {
        let mut filenames = Vec::new();

        let root = fs.current_dir().unwrap();
        let entries = fs.read_dir(root).unwrap();
        for entry in entries {
            if let Ok(dir) = entry {
                filenames.push(String::from(dir.path().into_os_string().to_str().unwrap()));
            }
        }

        filenames
    }

    #[test]
    fn xor_file_works() {
        // Arrange.

        // Setup the input file
        let fs = FakeFileSystem::new();
        let root = fs.current_dir().unwrap();
        let input_path = root.join("input.txt");
        let input_data = "hello world".as_bytes();
        fs.create_file(&input_path, input_data).unwrap();

        let key = vec![71];
        let mode = Mode::Encrypt;

        // Act.
        xor_file(&fs, &input_path, &key, &mode);

        // Assert.
        let mut filenames = get_root_files(&fs);

        // Filename is XOR'd against the key then encoded to hex
        assert_eq!(filenames, vec!["/2E2937323369333F33"]);
    }

}

