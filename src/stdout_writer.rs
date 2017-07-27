
use std::io;
use std::io::{Write};

const ERR_ENCODED_DATA_NOT_UTF8 : &'static str = r#"ERROR: Encoded data isn't printable.

The encoded data couldn't be encoded to valid utf8 and so couldn't be printed to the screen.
Use the "-o" option to write the output directly to a file instead."#;


pub struct StdoutWriter;

impl Write for StdoutWriter {
    fn write(&mut self, buf: &[u8]) -> Result<usize, io::Error> {
        match String::from_utf8(Vec::from(buf)) {
            Ok(encoded) => {
                let mut out = io::stdout();
                out.write_all(encoded.as_bytes()).unwrap();
                let _ = out.flush();
            },
            Err(e) => println!("{}\n\nDetails: {}", ERR_ENCODED_DATA_NOT_UTF8, e)
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> Result<(), io::Error> {
        Ok(())
    }
}
