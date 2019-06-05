use futures::Stream;
use hyper::{
    client::HttpConnector,
    rt::{self, Future},
    Body, Client, Method, Request, StatusCode,
};
use hyper_tls::{self, HttpsConnector};
use native_tls;
use std::sync::mpsc::Sender;
use itertools::Itertools;
use std::sync::mpsc::channel;


pub mod result_processor;
mod utils;

use utils::{split_http_headers};

use result_processor::{FuzzResultProcessorConfig, FuzzScanProcessor, SingleFuzzScanResult};

use std::{fs, fs::File, io::Write, path::Path, str, time::SystemTime};

use indicatif::{ProgressBar, ProgressStyle};

#[derive(Debug, Clone)]
pub struct FuzzBuster {
    pub n_threads: usize,
    pub ignore_certificate: bool,
    pub http_method: String,
    pub http_body: String,
    pub user_agent: String,
    pub http_headers: Vec<(String, String)>,
    pub wordlist_paths: Vec<String>,
    pub url: String,
    pub include_status_codes: Vec<String>,
    pub ignore_status_codes: Vec<String>,
    pub no_progress_bar: bool,
    pub exit_on_connection_errors: bool,
    pub output: String,
}

pub struct FuzzRequest {
    pub uri: hyper::Uri,
    pub http_method: String,
    pub http_headers: Vec<(String, String)>,
    pub http_body: String,
    pub user_agent: String,
}

impl FuzzBuster {

    pub fn run(self) {
        let (tx, rx) = channel::<SingleFuzzScanResult>();
        let mut tls_connector_builder = native_tls::TlsConnector::builder();
        tls_connector_builder.danger_accept_invalid_certs(self.ignore_certificate);
        let tls_connector = tls_connector_builder
            .build()
            .expect("TLS initialization failed");
        let mut http_connector = HttpConnector::new(self.n_threads);
        http_connector.enforce_http(false);
        let https_connector = HttpsConnector::from((http_connector, tls_connector));
        let client = Client::builder().build(https_connector);
        let n_threads = self.n_threads;
        let rp_config = FuzzResultProcessorConfig {
            include: self.include_status_codes.clone(),
            ignore: self.ignore_status_codes.clone(),
        };
        let requests = self.build_requests();
        let mut current_numbers_of_request = 0;
        let total_numbers_of_request = requests.len();
        let start_time = SystemTime::now();
        let mut result_processor = FuzzScanProcessor::new(rp_config);
        let bar = if self.no_progress_bar {
            ProgressBar::hidden()
        } else {
            ProgressBar::new(requests.len() as u64)
        };
        bar.set_draw_delta(100);
        bar.set_style(ProgressStyle::default_bar()
            .template("{spinner} [{elapsed_precise}] {bar:40.red/white} {pos:>7}/{len:7} ETA: {eta_precise} req/s: {msg}")
            .progress_chars("#>-"));

        let stream = futures::stream::iter_ok(requests)
            .map(move |request| FuzzBuster::make_request_future(tx.clone(), &client, &request))
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

            match &msg.error {
                Some(e) => {
                    error!("{:?}", e);
                    if current_numbers_of_request == 1 || self.exit_on_connection_errors {
                        warn!("Check connectivity to the target");
                        break;
                    }
                }
                None => (),
            }

            let was_added = result_processor.maybe_add_result(msg.clone());
            if was_added {
                let mut extra = msg.extra.unwrap_or("".to_owned());

                if !extra.is_empty() {
                    extra = format!("\n\t\t\t\t\t\t=> {}", extra)
                }

                let n_tabs = match msg.status.len() / 8 {
                    3 => 1,
                    2 => 2,
                    1 => 3,
                    0 => 4,
                    _ => 0,
                };

                if self.no_progress_bar {
                    println!(
                        "{}\t{}{}{}{}",
                        msg.method,
                        msg.status,
                        "\t".repeat(n_tabs),
                        msg.url,
                        extra
                    );
                } else {
                    bar.println(format!(
                        "{}\t{}{}{}{}",
                        msg.method,
                        msg.status,
                        "\t".repeat(n_tabs),
                        msg.url,
                        extra
                    ));
                }
            }
        }

        bar.finish();
        println!("{}", crate::banner::ending_time());

        if !self.output.is_empty() {
            result_processor.save_fuzz_results(&self.output);
        }
    }

    fn make_request_future(
        tx: Sender<SingleFuzzScanResult>,
        client: &Client<HttpsConnector<HttpConnector>>,
        request: &FuzzRequest,
    ) -> impl Future<Item = (), Error = ()> {
        let tx_err = tx.clone();
        let mut target = SingleFuzzScanResult {
            url: request.uri.to_string(),
            method: Method::GET.to_string(),
            status: StatusCode::default().to_string(),
            error: None,
            extra: None,
        };
        let mut target_err = target.clone();
        let mut request_builder = Request::builder();

        for header_tuple in &request.http_headers {
            request_builder.header(header_tuple.0.as_str(), header_tuple.1.as_str());
        }

        let request = request_builder
            .header("User-Agent", &request.user_agent[..])
            .method(&request.http_method[..])
            .uri(&request.uri)
            .body(Body::from(request.http_body.clone()))
            .expect("Request builder");

        client
            .request(request)
            .and_then(move |res| {
                let status = res.status();
                target.status = status.to_string();
                if status.is_redirection() {
                    target.extra = Some(
                        res.headers()
                            .get("Location")
                            .unwrap()
                            .to_str()
                            .unwrap()
                            .to_owned(),
                    );
                }

                tx.send(target).unwrap();
                Ok(())
            })
            .or_else(move |e| {
                target_err.error = Some(e.to_string());
                tx_err.send(target_err).unwrap_or_else(|_| ());
                Ok(())
            })
    }

    fn is_url_case(&self) -> bool {
        self.url.contains("FUZZ")
    }

    fn is_header_case(&self) -> bool {
        let sum = self.http_headers.iter().map(|(header, value)| -> usize {
            if header.contains("FUZZ") || value.contains("FUZZ") {
                return 1
            } else {
                return 0
            }
        }).sum::<usize>();

        sum > 0
    }

    fn is_body_case(&self) -> bool {
        self.http_body.contains("FUZZ")
    }

    fn build_requests(&self) -> Vec<FuzzRequest> {
        debug!("building requests");
        let mut requests: Vec<FuzzRequest> = Vec::new();
        let wordlists_iter = self.wordlist_paths.iter()
            .map(|wordlist| {
                fs::read_to_string(wordlist).expect("Something went wrong reading the wordlist file")
                    .lines()
                    .filter(|word| !word.starts_with('#') && !word.starts_with(' '))
                    .map(|x| x.to_owned())
                    .collect::<Vec<String>>()
            })
            .multi_cartesian_product();

        let case = if self.is_url_case() {
            "url"
        } else if self.is_header_case() {
            "header"
        } else if self.is_body_case() {
            "body"
        } else { error!("No injection points"); "ERROR" };

        match case {
            "url" | "body" => {
                for words in wordlists_iter {
                    let mut url = self.url.clone();
                    let mut http_body = self.http_body.clone();
                    let mut words_iter = words.iter();

                    while url.contains("FUZZ") {
                        match words_iter.next() {
                            None => break,
                            Some(word) => {
                                url = url.replacen("FUZZ", word, 1);
                            },
                        }
                    }

                    while http_body.contains("FUZZ") {
                        match words_iter.next() {
                            None => break,
                            Some(word) => {
                                http_body = http_body.replacen("FUZZ", word, 1);
                            },
                        }
                    }

                    for word in words {
                        http_body = http_body.replacen("FUZZ", &word, 1);
                    }

                    match url.parse::<hyper::Uri>() {
                        Ok(uri) => {
                            requests.push(FuzzRequest {
                                http_body,
                                uri,
                                user_agent: self.user_agent.clone(),
                                http_method: self.http_method.clone(),
                                http_headers: self.http_headers.clone(),
                            });
                        }
                        Err(e) => {
                            trace!("URI: {}", e);
                        }
                    }
                }
            },
            "header" => (),
            _ => (),
        }

        requests
    }
}