use std::{io, thread};

fn main() -> io::Result<()> {
    let mut i = trust::Interface::new()?;
    eprintln!("created interface");
    let mut l1 = i.bind(7000)?;
    let jh = thread::spawn(move || {
        while let Ok(_stream) = l1.accept() {
            eprintln!("got connection!");
        }
    });
    jh.join().unwrap();
    Ok(())
}
