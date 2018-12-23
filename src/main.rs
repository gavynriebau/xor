
mod stdout_writer;

extern crate clap;
extern crate xor_utils;
extern crate hex;
extern crate base64;
extern crate number_prefix;
extern crate rsfs;

#[macro_use] extern crate log;
extern crate env_logger;

//use std::fs;
use std::fmt::Debug;
use clap::{App, Arg, ArgMatches};
use std::str::FromStr;
use std::io::{self};
use std::io::{Write, Read, Seek, SeekFrom};
use std::path::Path;
use number_prefix::{binary_prefix, Standalone, Prefixed};
use rsfs::*;
use std::ops::DerefMut;


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


    // Open handle to the file system.
    let fs = rsfs::disk::FS;

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

        if mode == Mode::Decrypt || matches.is_present("force") || check_sizes(&fs, starting_dir, &key_bytes) {
            encrypt_path(&fs, starting_dir, &key_bytes, &mode);
        }
    } else {

        let mut output : Box<Write> = if matches.is_present("output") {
            trace!("Writting output to a file.");

            Box::new(fs.new_openopts()
                     .write(true)
                     .create(true)
                     .truncate(true)
                     .open(matches.value_of("output").unwrap())
                     .unwrap())

        } else {
            trace!("Writting output to stdout.");
            Box::new(stdout_writer::StdoutWriter{})
        };

        let mut in_reader : Box<Read> = if matches.is_present("input") {
            trace!("Reading input from a file.");
            let in_file_name = matches.value_of("input").unwrap();
            Box::new(fs.open_file(in_file_name).unwrap())
        } else {
            trace!("Reading input from stdin.");
            Box::new(io::stdin())
        };

        encrypt_reader(&mut in_reader, &key_bytes, output.deref_mut());
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

fn encrypt_path<T: GenFS>(fs: &T, p : &Path, key : &Vec<u8>, mode : &Mode) {
    for item in fs.read_dir(p).unwrap() {
        match item {
            Ok(entry) => xor_entry(fs, &entry, key, mode),
            Err(err) => info!("Failed to read entry because: {}", err)
        }
    }
}

fn xor_entry<T: rsfs::DirEntry, U: GenFS>(fs: &U, entry : &T, key : &Vec<u8>, mode : &Mode) {
    match entry.file_type() {
        Ok(entry_type) => {
            if entry_type.is_dir() {
                xor_dir(fs, &entry.path(), key, mode);
            } else if entry_type.is_file() {
                xor_file(fs, &entry.path(), key, mode);
            } else if entry_type.is_symlink() {
                xor_symlink(fs, &entry.path(), key, mode);
            }
        },
        Err(err) => info!("Failed to get filetype for DirEntry {:?} because: {}", entry, err)
    }
}

fn xor_file<T, P>(fs: &T, path : &P, key : &Vec<u8>, mode : &Mode)
    where T: GenFS, P: AsRef<Path> + Debug {

        debug!("Encrypting file {:?}", path);

        let mut in_file = fs.open_file(path).unwrap();
        let mut file_bytes : Vec<u8> = Vec::new();

        //in_file.seek(SeekFrom::Start(0)).unwrap();

        let num_read = in_file.read_to_end(&mut file_bytes).unwrap();

        // TODO: REMOVE
        println!("in_file: {:?}", in_file);
        println!("path: {}", path.as_ref().to_str().unwrap());
        println!("num_read: {}", num_read);
        //println!("file_bytes: {:?}", file_bytes);

        let key_repeated = repeat_key(key, file_bytes.len() as usize);

        let encrypted_bytes : Vec<u8> = file_bytes.iter()
            .zip(key_repeated)
            .map(|(d, k)| d ^ k)
            .collect();

        let mut out_file = fs.new_openopts()
            .write(true)
            .truncate(true)
            .open(path)
            .unwrap();


        // TODO: REMOVE
        println!("Encrypted bytes are: {:?}", encrypted_bytes);


        out_file.write_all(&encrypted_bytes).unwrap();

        rename_entry(fs, path, key, mode);
    }

fn xor_symlink<T, P>(fs: &T, entry : &P, key : &Vec<u8>, mode : &Mode)
    where T: GenFS, P: AsRef<Path> + Debug {
        debug!("Encrypting symlink {:?}", entry);
        rename_entry(fs, entry, key, mode);
    }

fn xor_dir<T, P>(fs: &T, path : &P, key : &Vec<u8>, mode : &Mode)
    where T: GenFS, P: AsRef<Path> + Debug {

        debug!("Encrypting dir {:?}", path);

        for child in fs.read_dir(&path).unwrap() {
            let child_path = child.unwrap();
            let metadata = child_path.metadata().unwrap();

            if metadata.is_dir() {
                xor_dir(fs, &child_path.path(), key, mode);
            }
            else if metadata.is_file() {
                xor_file(fs, &child_path.path(), key, mode);
            }
            else if metadata.is_dir() {
                rename_entry(fs, &child_path.path(), key, mode);
            }
        }

        rename_entry(fs, path, key, mode);
    }

/// //Renames a directory entry.
/// //When "mode" is Mode::Encrypt, the name of the entry is XOR'd then hexlified.
/// When "mode" is Mode::Decrypt, the name of the entry is unhexlified then XOR'd.
fn rename_entry<T, P>(fs: &T, path : P, key : &Vec<u8>, mode : &Mode)
    where T: GenFS, P: AsRef<Path> + Debug {

        if let Some(original_name) = path.as_ref().file_name() {
            debug!("original_name: {:?}", original_name);

            let key_repeated = repeat_key(key, original_name.len());

            // If in Encrypt mode use the filename as is.
            // If in Decrypt mode unhexify the filename before getting it's bytes.
            let input_bytes = match *mode {
                Mode::Encrypt => String::from_str(original_name.to_str().unwrap()).unwrap().into_bytes(),
                Mode::Decrypt => from_hex_string(&String::from_str(original_name.to_str().unwrap()).unwrap())
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

            let parent_path = path.as_ref().parent().unwrap();
            let src_file_path = parent_path.join(&original_name);
            let dst_file_path = parent_path.join(&replaced_name);

            debug!("Moving {:?} to {:?}", src_file_path, dst_file_path);

            match fs.rename(&src_file_path, &dst_file_path) {
                Ok(_) => trace!("Renamed path '{:?}' to '{:?}'", &src_file_path, &dst_file_path),
                Err(e) => error!("Failed to rename '{:?}' to '{:?}' because: {}", &src_file_path, &dst_file_path, e)
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
fn get_largest_file_size(path : &Path) -> u64 {
    let mut size : u64 = 0;

    match path.metadata() {
        Ok(metadata) => {

            // Check if the current file is the largest.
            if path.is_file() {
                size = metadata.len();
            } else if path.is_dir() {
                // Check if any of the child files are the largest.
                match path.read_dir() {
                    Ok(entries) => {
                        for entry in entries {
                            let entry_size = get_largest_file_size(entry.unwrap().path().as_path());

                            if entry_size > size {
                                size = entry_size;
                            }
                        }
                    },
                    Err(err) => info!("Failed to read directory {:?} because: {}", path, err)
                }
            }
        },
        Err(err) => info!("Failed to get metadata for path {:?} because: {}", path, err)
    }

    size
}

/// Recursively searches the supplied path and finds the length of the longest file/directory name.
fn get_longest_name<T: GenFS>(fs: &T, path : &Path) -> usize {
    let mut size : usize = 0;

    // Check if the current entry name is the longest.
    if let Some(name) = path.file_name() {
        let length = name.len();

        if length > size {
            size = length;
        }

        if path.is_dir() {
            // Check if any of the child directory / file names are the longest.
            for entry_result in fs.read_dir(path).unwrap() {
                if let Ok(entry) = entry_result {
                    let entry_size = get_longest_name(fs, entry.path().as_path());

                    if entry_size > size {
                        size = entry_size;
                    }
                }
            }
        }
    }

    size
}

fn check_sizes<T: GenFS>(fs: &T, starting_directory : &Path, key_bytes : &Vec<u8>) -> bool {
    let mut should_continue : bool = true;

    let key_size = key_bytes.len();
    let largest_file_size = get_largest_file_size(starting_directory);
    let longest_name = get_longest_name(fs, starting_directory);

    if largest_file_size > key_size as u64 || longest_name > key_size {
        print_keysize_warning(key_size, largest_file_size, longest_name);
        let answer = show_prompt();
        should_continue = answer == 'y';
    }

    should_continue
}

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
    use rsfs::mem::{FS, Permissions};
    use rsfs::unix_ext::PermissionsExt;
    use std::io::{Cursor, Error};

    fn read_file_contents<T: GenFS, P: AsRef<Path>>(fs: &T, path: P) -> Vec<u8> {
        let mut x = fs.open_file(path).unwrap();
        let mut data : Vec<u8> = Vec::new();
        
        let _num_read = x.read_to_end(&mut data).unwrap();

        data
    }

    fn debug_path<T: GenFS, P: AsRef<Path>>(fs: &T, p: &P) {
        for entry in fs.read_dir(p).unwrap() {
            match entry {
                Ok(e) => {
                    let is_dir = e.metadata().unwrap().is_dir();
                    let key = if is_dir {
                        "D"
                    } else {
                        "F"
                    };

                    println!("{} - {:?}", key, e.path());

                    if is_dir {
                        debug_path(fs, &e.path());
                    }
                },
                Err(_) => {}
            }
        }
    }

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

    #[test]
    fn xor_file_encrypt_mode_works() {
        // Arrange.

        // Setup the input file
        let fs = FS::new();
        let input_data = "hello world".as_bytes();
        let input_path = Path::new("/input.txt");
        let key = vec![71];
        let mode = Mode::Encrypt;
        let mut input_file = fs.create_file(&input_path).unwrap();
        input_file.write(input_data).unwrap();

        // Act.
        xor_file(&fs, &input_path, &key, &mode);

        // Assert.
        let filenames : Vec<String> = fs.read_dir("/")
            .unwrap()
            .map(|x| x.unwrap())
            .map(|x| x.path().into_os_string())
            .map(|x| x.into_string().unwrap())
            .collect();

        let mut encrypted_file = fs.open_file("/2E2937323369333F33").unwrap();
        let mut encrypted_bytes : Vec<u8> = Vec::new();
        encrypted_file.read_to_end(&mut encrypted_bytes).unwrap();

        // Filename is XOR'd against the key then encoded to hex
        assert_eq!(filenames, vec!["/2E2937323369333F33"]);
        assert_eq!(encrypted_bytes, vec![0x2f_u8, 0x22_u8, 0x2b_u8, 0x2b_u8, 0x28_u8, 0x67_u8, 0x30_u8, 0x28_u8, 0x35_u8, 0x2b_u8, 0x23_u8]);
    }

    #[test]
    fn xor_file_decrypt_mode_works() {
        // Arrange.

        // Setup the input file
        let fs = FS::new();
        let input_path = Path::new("/2E2937323369333F33");
        let input_data = [0x2f_u8, 0x22_u8, 0x2b_u8, 0x2b_u8, 0x28_u8, 0x67_u8, 0x30_u8, 0x28_u8, 0x35_u8, 0x2b_u8, 0x23_u8];
        let mut input_file = fs.create_file(&input_path).unwrap();
        input_file.write(&input_data).unwrap();

        let key = vec![71];
        //let mode = Mode::Decrypt;

        // Act.
        xor_file(&fs, &input_path, &key, &Mode::Decrypt);

        // Assert.
        let mut output_file = fs.open_file("/input.txt").unwrap();
        let mut encrypted_bytes : Vec<u8> = Vec::new();
        output_file.read_to_end(&mut encrypted_bytes).unwrap();

        // Filename is XOR'd against the key then encoded to hex
        assert_eq!(encrypted_bytes, "hello world".as_bytes());
    }

    #[test]
    fn xor_directory_encrypt_mode_works() {

        // Arrange.

        // Use a single letter key 'G'
        let key = vec![71];

        // Make a filesystem as follows:
        //
        // parent_dir
        //    |
        //    +-- child_dir
        //    |     |
        //    |     +-- file_a
        //    |     |
        //    |     +-- file_b
        //    |     
        //    +-- file_c
        //

        let fs = FS::new();
        let file_a_contents_starting : [u8; 5] = [1_u8, 2_u8, 3_u8, 4_u8, 5_u8];
        let file_b_contents_starting : [u8; 5] = [6_u8, 7_u8, 8_u8, 9_u8, 10_u8];
        let file_c_contents_starting : [u8; 5] = [11_u8, 12_u8, 13_u8, 14_u8, 15_u8];
        let file_a_contents_expected : [u8; 5] = [70_u8, 69_u8, 68_u8, 67_u8, 66_u8];
        let file_b_contents_expected : [u8; 5] = [65_u8, 64_u8, 79_u8, 78_u8, 77_u8];
        let file_c_contents_expected : [u8; 5] = [76_u8, 75_u8, 74_u8, 73_u8, 72_u8];

        // Create the files
        fs.new_dirbuilder()
            .recursive(true)
            .create("/parent_dir/child_dir")
            .unwrap();

        let mut file_a = fs.create_file("/parent_dir/child_dir/file_a").unwrap();
        let mut file_b = fs.create_file("/parent_dir/child_dir/file_b").unwrap();
        let mut file_c = fs.create_file("/parent_dir/file_c").unwrap();

        // Write contents to files
        file_a.write_all(&file_a_contents_starting).unwrap();
        file_b.write_all(&file_b_contents_starting).unwrap();
        file_c.write_all(&file_c_contents_starting).unwrap();

        xor_dir(&fs, &"parent_dir", &key, &Mode::Encrypt);

        assert!(fs.metadata("/37263522293318232E35").unwrap().is_dir());                                  // parent_dir -> 37263522293318232E35
        assert!(fs.metadata("/37263522293318232E35/242F2E2B2318232E35").unwrap().is_dir());               // parent_dir/child_dir -> 37263522293318232E35/242F2E2B2318232E35
        assert!(fs.metadata("/37263522293318232E35/242F2E2B2318232E35/212E2B221826").unwrap().is_file()); // parent_dir/child_dir/file_a -> 37263522293318232E35/242F2E2B2318232E35/212E2B221826
        assert!(fs.metadata("/37263522293318232E35/242F2E2B2318232E35/212E2B221825").unwrap().is_file()); // parent_dir/child_dir/file_b -> 37263522293318232E35/242F2E2B2318232E35/212E2B221825
        assert!(fs.metadata("/37263522293318232E35/212E2B221824").unwrap().is_file());                    // parent_dir/file_c -> 37263522293318232E35/212E2B221824

        // Assert contents are XOR'd
        let file_a_contents_actual : Vec<u8> = read_file_contents(&fs, "/37263522293318232E35/242F2E2B2318232E35/212E2B221826");
        let file_b_contents_actual : Vec<u8> = read_file_contents(&fs, "/37263522293318232E35/242F2E2B2318232E35/212E2B221825");
        let file_c_contents_actual : Vec<u8> = read_file_contents(&fs, "/37263522293318232E35/212E2B221824");

        assert_eq!(file_a_contents_actual, file_a_contents_expected);
        assert_eq!(file_b_contents_actual, file_b_contents_expected);
        assert_eq!(file_c_contents_actual, file_c_contents_expected);
    }

}

