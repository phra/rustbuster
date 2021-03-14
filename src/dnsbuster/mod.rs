use futures::{future, Future, Stream};
use hyper::rt;
use std::{net::ToSocketAddrs, sync::mpsc::Sender};
use std::sync::mpsc::channel;
use std::{time::SystemTime};
use indicatif::{ProgressBar, ProgressStyle};

pub mod result_processor;
pub mod utils;
use result_processor::{SingleDnsScanResult, DnsScanResult};
use utils::{build_domains, save_dns_results};

#[derive(Debug, Clone)]
pub struct DnsBuster {
    pub n_threads: usize,
    pub wordlist_path: String,
    pub domain: String,
    pub no_progress_bar: bool,
    pub output: String,
}

impl DnsBuster {

    fn make_request_future(
        &self,
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
    
    pub fn run(self) {
        let mut current_numbers_of_request = 0;
        let start_time = SystemTime::now();
        let output = self.output.clone();
        let no_progress_bar = self.no_progress_bar;
        let n_threads = self.n_threads;
        let domains = build_domains(&self.wordlist_path, &self.domain);
        let total_numbers_of_request = domains.len();
        let (tx, rx) = channel::<SingleDnsScanResult>();
        let mut result_processor = DnsScanResult::new();

        let bar = if self.no_progress_bar {
            ProgressBar::hidden()
        } else {
            ProgressBar::new(total_numbers_of_request as u64)
        };
        bar.set_draw_delta(25);
        bar.set_style(ProgressStyle::default_bar()
            .template("{spinner} [{elapsed_precise}] {bar:40.red/white} {pos:>7}/{len:7} ETA: {eta_precise} req/s: {msg}")
            .progress_chars("#>-"));

        let stream = futures::stream::iter_ok(domains)
            .map(move |url| self.make_request_future(tx.clone(), url))
            .buffer_unordered(n_threads)
            .for_each(Ok)
            .map_err(|err| eprintln!("Err {:?}", err));
    
        rt::run(stream);

        while current_numbers_of_request != total_numbers_of_request {
            current_numbers_of_request = current_numbers_of_request + 1;
            bar.inc(1);

            let seconds_from_start = start_time.elapsed().unwrap().as_millis() / 1000;
            if seconds_from_start != 0 {
                bar.set_message(
                    &(current_numbers_of_request as u64 / seconds_from_start as u64)
                        .to_string(),
                );
            } else {
                bar.set_message("warming up...")
            }

            let msg = match rx.recv() {
                Ok(msg) => msg,
                Err(_err) => {
                    error!("{:?}", _err);
                    break;
                }
            };

            result_processor.maybe_add_result(msg.clone());
            match msg.status {
                true => {
                    if no_progress_bar {
                        println!("OK\t{}", &msg.domain[..msg.domain.len() - 3]);
                    } else {
                        bar.println(format!("OK\t{}", &msg.domain[..msg.domain.len() - 3]));
                    }

                    match msg.extra {
                        Some(v) => {
                            for addr in v {
                                let string_repr = addr.ip().to_string();
                                match addr.is_ipv4() {
                                    true => {
                                        if no_progress_bar {
                                            println!("\t\tIPv4: {}", string_repr);
                                        } else {
                                            bar.println(format!("\t\tIPv4: {}", string_repr));
                                        }
                                    }
                                    false => {
                                        if no_progress_bar {
                                            println!("\t\tIPv6: {}", string_repr);
                                        } else {
                                            bar.println(format!("\t\tIPv6: {}", string_repr));
                                        }
                                    }
                                }
                            }
                        }
                        None => (),
                    }
                }
                false => (),
            }
        }

        bar.finish();
        println!("{}", crate::banner::ending_time());

        if !output.is_empty() {
            save_dns_results(&output, &result_processor.results);
        }
    }
}
