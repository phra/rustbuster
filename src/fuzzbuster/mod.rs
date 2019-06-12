use futures::Stream;
use hyper::{
    client::HttpConnector,
    rt::{self, Future},
    Body, Client, Method, Request, StatusCode,
};
use hyper_tls::{self, HttpsConnector};
use itertools::Itertools;
use native_tls;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::thread;

pub mod result_processor;
mod spec;
pub mod utils;

use result_processor::{FuzzScanProcessor, FuzzScanProcessorConfig, SingleFuzzScanResult};

use std::{fs, time::SystemTime};

use indicatif::{ProgressBar, ProgressStyle};

use regex::Regex;

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
    pub include_body: Vec<String>,
    pub ignore_body: Vec<String>,
    pub no_progress_bar: bool,
    pub exit_on_connection_errors: bool,
    pub output: String,
    pub csrf_url: Option<String>,
    pub csrf_regex: Option<String>,
    pub csrf_headers: Option<Vec<(String, String)>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FuzzRequest {
    pub uri: hyper::Uri,
    pub http_method: String,
    pub http_headers: Vec<(String, String)>,
    pub http_body: String,
    pub user_agent: String,
    pub payload: Vec<String>,
    pub csrf_uri: Option<hyper::Uri>,
    pub csrf_regex: Option<String>,
    pub csrf_headers: Option<Vec<(String, String)>>,
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
        let rp_config = FuzzScanProcessorConfig {
            include: self.include_status_codes.clone(),
            ignore: self.ignore_status_codes.clone(),
            include_body: self.include_body.clone(),
            ignore_body: self.ignore_body.clone(),
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
            .map(move |request| {
                FuzzBuster::make_request_future(tx.clone(), client.clone(), request)
            })
            .buffer_unordered(n_threads)
            .for_each(Ok)
            .map_err(|err| eprintln!("Err {:?}", err));

        let _ = thread::spawn(move || rt::run(stream));

        while current_numbers_of_request != total_numbers_of_request {
            current_numbers_of_request = current_numbers_of_request + 1;
            bar.inc(1);
            let seconds_from_start = start_time.elapsed().unwrap().as_millis() / 1000;
            if seconds_from_start != 0 {
                bar.set_message(
                    &(current_numbers_of_request as u64 / seconds_from_start as u64).to_string(),
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
                        "{}\t{}{}{} ({:?}){}",
                        msg.method,
                        msg.status,
                        "\t".repeat(n_tabs),
                        msg.url,
                        msg.payload,
                        extra,
                    );
                } else {
                    bar.println(format!(
                        "{}\t{}{}{}\n\t\t\t\t\t\t=> PAYLOAD: {:?}{}",
                        msg.method,
                        msg.status,
                        "\t".repeat(n_tabs),
                        msg.url,
                        msg.payload,
                        extra,
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
        client: Client<HttpsConnector<HttpConnector>>,
        request: FuzzRequest,
    ) -> impl Future<Item = (), Error = ()> {
        let tx_err = tx.clone();
        let tx_err2 = tx.clone();
        let mut target = SingleFuzzScanResult {
            url: request.uri.to_string(),
            method: Method::GET.to_string(),
            status: StatusCode::default().to_string(),
            payload: request.payload.clone(),
            body: request.http_body.clone(),
            error: None,
            extra: None,
        };
        let mut target_err = target.clone();
        let mut target_err2 = target.clone();
        let mut request_builder = Request::builder();

        for header_tuple in &request.http_headers {
            request_builder.header(header_tuple.0.as_str(), header_tuple.1.as_str());
        }

        let csrf_fut = match &request.csrf_uri {
            None => futures::future::Either::A(futures::future::ok::<
                (Option<String>, FuzzRequest),
                _,
            >((None, request))),
            Some(uri) => {
                let mut csrf_request_builder = Request::builder();

                match &request.csrf_headers {
                    None => (),
                    Some(v) => {
                        for header_tuple in v.iter() {
                            csrf_request_builder
                                .header(header_tuple.0.as_str(), header_tuple.1.as_str());
                        }
                    }
                }

                let hyper_request = csrf_request_builder
                    .header("User-Agent", &request.user_agent[..])
                    .method(hyper::Method::GET)
                    .uri(uri)
                    .body(Body::from(""))
                    .expect("Request builder");
                let csrf_regex = request.csrf_regex.clone();
                let csrf_regex = &csrf_regex.expect("Missing regex");
                match Regex::new(&csrf_regex) {
                    Ok(re) => futures::future::Either::B(
                        client
                            .request(hyper_request)
                            .and_then(|res| res.into_body().concat2())
                            .join3(futures::future::ok(re), futures::future::ok(request))
                            .and_then(|(body, re, request)| {
                                let vec = body.iter().cloned().collect();
                                let body = String::from_utf8(vec).unwrap();
                                match re.captures_iter(&body).take(1).next() {
                                    Some(v) => Ok((Some(v[1].to_owned()), request)),
                                    None => {
                                        warn!("no match for csrf regex");
                                        Ok((None, request))
                                    }
                                }
                            }),
                    ),
                    Err(e) => {
                        error!("Invalid regex: {}", e);
                        std::process::exit(-1);
                    }
                }
            }
        };

        csrf_fut
            .and_then(move |(csrf, request)| {
                let request = match csrf {
                    Some(v) => {
                        trace!("csrf: {}", v);
                        FuzzBuster::replace_csrf(request, v)
                    }
                    _ => request,
                };

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

                        futures::future::ok(target).join(res.into_body().concat2())
                    })
                    .and_then(move |(target, body)| {
                        let mut target = target;
                        let vec = body.iter().cloned().collect();
                        let body = String::from_utf8(vec).unwrap();
                        target.body = body;
                        tx.send(target.clone()).unwrap();
                        Ok(())
                    })
                    .or_else(move |e| {
                        target_err.error = Some(e.to_string());
                        tx_err.send(target_err).unwrap_or_else(|_| ());
                        Ok(())
                    })
            })
            .or_else(move |e| {
                target_err2.error = Some(e.to_string());
                tx_err2.send(target_err2).unwrap_or_else(|_| ());
                Ok(())
            })
    }

    pub fn build_requests(&self) -> Vec<FuzzRequest> {
        debug!("building requests");
        let mut requests: Vec<FuzzRequest> = Vec::new();
        let wordlists_iter = self
            .wordlist_paths
            .iter()
            .map(|wordlist| {
                fs::read_to_string(wordlist)
                    .expect("Something went wrong reading the wordlist file")
                    .lines()
                    .filter(|word| !word.starts_with('#') && !word.starts_with(' '))
                    .map(|x| x.to_owned())
                    .collect::<Vec<String>>()
            })
            .multi_cartesian_product();

        for words in wordlists_iter {
            let mut url = self.url.clone();
            let mut http_body = self.http_body.clone();
            let mut http_headers = self.http_headers.clone();
            let payload = words.clone();

            for word in words {
                if url.contains("FUZZ") {
                    url = url.replacen("FUZZ", &word, 1);
                }

                for (header, value) in http_headers.iter_mut() {
                    if header.contains("FUZZ") {
                        *header = header.replacen("FUZZ", &word, 1);
                        break;
                    } else if value.contains("FUZZ") {
                        *value = value.replacen("FUZZ", &word, 1);
                        break;
                    }
                }

                if http_body.contains("FUZZ") {
                    http_body = http_body.replacen("FUZZ", &word, 1);
                }
            }

            match url.parse::<hyper::Uri>() {
                Ok(uri) => match &self.csrf_url {
                    Some(csrf_url) => match csrf_url.parse::<hyper::Uri>() {
                        Ok(csrf_uri) => {
                            requests.push(FuzzRequest {
                                http_body,
                                uri,
                                http_headers,
                                payload,
                                user_agent: self.user_agent.clone(),
                                http_method: self.http_method.clone(),
                                csrf_uri: Some(csrf_uri),
                                csrf_regex: self.csrf_regex.to_owned(),
                                csrf_headers: self.csrf_headers.clone(),
                            });
                        }
                        Err(e) => {
                            debug!("CSRF URI: {}", e);
                        }
                    },
                    None => {
                        requests.push(FuzzRequest {
                            http_body,
                            uri,
                            http_headers,
                            payload,
                            user_agent: self.user_agent.clone(),
                            http_method: self.http_method.clone(),
                            csrf_uri: None,
                            csrf_regex: None,
                            csrf_headers: None,
                        });
                    }
                },
                Err(e) => {
                    debug!("URI: {}", e);
                }
            }
        }

        requests
    }

    pub fn replace_csrf(request: FuzzRequest, csrf: String) -> FuzzRequest {
        let mut p = request;
        p.uri = p
            .uri
            .to_string()
            .replace("CSRFCSRF", &csrf)
            .parse::<hyper::Uri>()
            .expect("replace csrf in uri");
        for (header, value) in p.http_headers.iter_mut() {
            *header = header.replace("CSRFCSRF", &csrf);
            *value = value.replace("CSRFCSRF", &csrf);
        }

        p.http_body = p.http_body.replace("CSRFCSRF", &csrf);
        p
    }
}
