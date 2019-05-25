use futures::{future, Future, Stream};
use hyper::rt;

use std::{net::ToSocketAddrs, sync::mpsc::Sender};

pub mod result_processor;
pub mod utils;

use result_processor::SingleDnsScanResult;

#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub n_threads: usize,
}

fn make_request_future(
    tx: Sender<SingleDnsScanResult>,
    domain: String,
) -> impl Future<Item = (), Error = ()> {
    future::lazy(move || {
        match domain.to_socket_addrs() {
            Ok(v) => {
                debug!("{:?}", v);
                let mut addrs: Vec<std::net::SocketAddr> = Vec::new();
                for addr in v {
                    addrs.push(addr);
                }

                let result = SingleDnsScanResult {
                    domain,
                    status: true,
                    extra: Some(addrs),
                };
                tx.send(result).unwrap();
            }
            Err(_e) => {
                let result = SingleDnsScanResult {
                    domain,
                    status: false,
                    extra: None,
                };

                tx.send(result).unwrap();
            }
        };

        Ok(())
    })
}

pub fn run(tx: Sender<SingleDnsScanResult>, domains: Vec<String>, config: DnsConfig) {
    let stream = futures::stream::iter_ok(domains)
        .map(move |url| make_request_future(tx.clone(), url))
        .buffer_unordered(config.n_threads)
        .for_each(Ok)
        .map_err(|err| eprintln!("Err {:?}", err));

    rt::run(stream);
}
