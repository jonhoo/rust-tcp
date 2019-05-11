use std::io::prelude::*;
use std::{io, thread};

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;
    eprintln!("created interface");
    let mut l1 = i.bind(8000)?;
    let jh = thread::spawn(move || {
        while let Ok(mut stream) = l1.accept() {
            eprintln!("got connection!");
            loop {
                let mut buf = [0; 512];
                let n = stream.read(&mut buf[..]).unwrap();
                eprintln!("read {}b of data", n);
                if n == 0 {
                    eprintln!("no more data!");
                    break;
                } else {
                    println!("{}", std::str::from_utf8(&buf[..n]).unwrap());
                }
            }
        }
    });
    jh.join().unwrap();
    Ok(())
}
