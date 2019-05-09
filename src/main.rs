use futures::{
    future,
    Future
};
use tokio::{
    io::AsyncWrite,
    net::TcpStream
};

use std::{
    net::SocketAddr,
    boxed::Box
};

fn req() -> Box<Future<Item = (), Error = ()> + Send> {
    for _ in 0..1000 {
        let addr = "0.0.0.0:1337".parse::<SocketAddr>().unwrap();
        let stream = TcpStream::connect(&addr);

        let req_fut = stream
            .map(|mut stream| {
                let body = format!(
                    "{}\r\n{}\r\n{}\r\n{}\r\n\r\n",
                    "GET / HTTP/1.1",
                    "Host: localhost",
                    r#"User-Agent: ¯\_(ツ)_/¯"#,
                    "Accept: */*"
                );
                stream.poll_write(&body.as_bytes()).unwrap();
            })
            .map_err(|e| {
                println!("[ERROR]: {}", e);
            });

        tokio::spawn(req_fut);
    }
    
    Box::new(future::ok(()))
}

fn main() -> Result<(), Box<std::error::Error>> {
    tokio::run(
        futures::lazy(|| {
            req()
        }
    ));

    Ok(())
}
