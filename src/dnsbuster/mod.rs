use futures::{future, Future, Stream};
use hyper::rt;
use serde::{Deserialize, Serialize};

use std::{sync::mpsc::Sender, net::ToSocketAddrs};

#[derive(Debug, Clone)]
pub struct Config {
    pub n_threads: usize
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SingleDnsScanResult {
    pub domain: String,
    pub status: bool
}

fn make_request_future(
    tx: Sender<SingleDnsScanResult>,
    domain: String
) -> impl Future<Item = (), Error = ()> {
    let mut result = SingleDnsScanResult {
        domain,
        status: false
    };

    future::lazy(move || {
        match result.domain.to_socket_addrs() {
            Ok(v) => {
                result.status = true;
                tx.send(result).unwrap();
                Ok(v);
            }
            Err(e) => {
                println!("err {}", e);
                tx.send(result).unwrap();
                Err(e);
            }
        };
    })
}

pub fn run(tx: Sender<SingleDnsScanResult>, domains: Vec<String>, config: Config) {
    let stream = futures::stream::iter_ok(domains)
        .map(move |url| make_request_future(tx.clone(), url))
        .buffer_unordered(config.n_threads)
        .for_each(Ok)
        .map_err(|err| eprintln!("Err {:?}", err));

    rt::run(stream);
}
