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

use result_processor::{TildeScanProcessor, SingleTildeScanResult, FSObject};

use std::{fs, time::SystemTime};

use indicatif::{ProgressBar, ProgressStyle};

use regex::Regex;

#[derive(Debug, Clone)]
pub struct TildeBuster {
    pub n_threads: usize,
    pub ignore_certificate: bool,
    pub http_method: String,
    pub http_body: String,
    pub user_agent: String,
    pub http_headers: Vec<(String, String)>,
    pub url: String,
    pub no_progress_bar: bool,
    pub exit_on_connection_errors: bool,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct TildeRequest {
    pub url: String,
    pub http_method: String,
    pub http_headers: Vec<(String, String)>,
    pub http_body: String,
    pub user_agent: String,
    pub filename: String,
    pub extension: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum IISVersion {
    Unknown,
    IIS1,
    IIS2,
    IIS3,
    IIS4,
    IIS5,
    IIS6,
    IIS7,
    IIS75,
    IIS8,
    IIS85,
    IIS10,
}

impl TildeBuster {
    pub fn run(self) {
        let (tx, rx) = channel::<SingleTildeScanResult>();
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
        let mut current_numbers_of_request = 0;
        let chars = "abcdefghijklmnopqrstuvwxyz1234567890-_".split("").map(|c| c.to_owned()).collect::<Vec<String>>();
        let total_numbers_of_request = chars.len();
        let start_time = SystemTime::now();
        let mut result_processor = TildeScanProcessor::new();
        let output = self.output.clone();
        let no_progress_bar = self.no_progress_bar;
        let exit_on_connection_errors = self.exit_on_connection_errors;
        let bar = if self.no_progress_bar {
            ProgressBar::hidden()
        } else {
            ProgressBar::new(total_numbers_of_request as u64)
        };
        bar.set_draw_delta(100);
        bar.set_style(ProgressStyle::default_bar()
            .template("{spinner} [{elapsed_precise}] {bar:40.red/white} {pos:>7}/{len:7} ETA: {eta_precise} req/s: {msg}")
            .progress_chars("#>-"));

        let fut = self.check_iis_version(&client)
            .and_then(move |version| {
                futures::future::ok(version.clone()).join(self.check_if_vulnerable(&client, version))
                    .and_then(move |(version, is_vulnerable)| {
                        debug!("iis version: {:?}", version);
                        debug!("is vulnerable: {:?}", is_vulnerable);

                        let stream = futures::stream::iter_ok(chars)
                            .map(move |c| {
                                let request = TildeRequest {
                                    url: self.url.clone(),
                                    http_method: self.http_method.clone(),
                                    http_headers: self.http_headers.clone(),
                                    http_body: self.http_body.clone(),
                                    user_agent: self.user_agent.clone(),
                                    filename: c,
                                    extension: "".to_owned(),
                                };

                                TildeBuster::_brute_filename(tx.clone(), client.clone(), request)
                            })
                        .buffer_unordered(n_threads)
                        .for_each(Ok)
                        .map_err(|err| eprintln!("Err {:?}", err));

                        rt::spawn(stream);
                        Ok(())
                    })
            })
            .or_else(|e| {
                error!("{}", e);
                Ok(())
            });

        let _ = thread::spawn(move || rt::run(fut));

        loop {
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
                    if current_numbers_of_request == 1 || exit_on_connection_errors {
                        warn!("Check connectivity to the target");
                        break;
                    }
                }
                None => (),
            }

            result_processor.maybe_add_result(msg.clone());

            match msg.kind {
                FSObject::File => {
                    if no_progress_bar {
                        println!(
                            "File\t{}.{}",
                            msg.filename,
                            msg.extension,
                        );
                    } else {
                        bar.println(format!(
                            "File\t{}.{}",
                            msg.filename,
                            msg.extension,
                        ));
                    }
                },
                FSObject::Directory => {
                    if no_progress_bar {
                        println!(
                            "Directory\t{}",
                            msg.filename,
                        );
                    } else {
                        bar.println(format!(
                            "Directory\t{}",
                            msg.filename,
                        ));
                    }
                },
            }
        }

        bar.finish();
        println!("{}", crate::banner::ending_time());

        if !output.is_empty() {
            result_processor.save_tilde_results(&output);
        }
    }

    fn _brute_filename(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = (), Error = ()> {
        let tx1 = tx.clone();
        let tx2 = tx.clone();
        if request.filename.len() == 6 {
            rt::spawn(TildeBuster::_has_extension(tx.clone(), client.clone(), request.clone())
                .and_then(move |has_extension| {
                    if !has_extension {
                        // DIRECTORY FOUND
                    } else {
                        rt::spawn(TildeBuster::_brute_extension(tx1, client, request));
                    }

                    futures::future::ok(())
                })
                .or_else(|e| {
                    error!("{}", e);
                    Ok(())
                }));
        } else {
            rt::spawn(TildeBuster::_filename_exists(tx.clone(), client, request)
                .and_then(move |exists| {
                    if exists {
                        rt::spawn(TildeBuster::_brute_filename(tx2, client, request));
                    }

                    futures::future::ok(())
                })
                .or_else(|e| {
                    error!("{}", e);
                    Ok(())
                }));
        }

        futures::future::ok(())
    }

    fn _filename_exists(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = bool, Error = hyper::Error> {
        futures::future::ok(true)
    }

    fn _extension_exists(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = bool, Error = hyper::Error> {
        futures::future::ok(true)
    }

    fn _has_extension(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = bool, Error = hyper::Error> {
        futures::future::ok(true)
    }

    fn _brute_extension(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = (), Error = ()> {
        if request.extension.len() == 3 {
            // FILE FOUND
        }

        futures::future::ok(())
    }

    pub fn check_iis_version(&self, client: &Client<HttpsConnector<HttpConnector>>) -> impl Future<Item = IISVersion, Error = hyper::Error> {
        let request = Request::builder()
            .header("User-Agent", &self.user_agent[..])
            .method(&self.http_method[..])
            .uri(self.url.parse::<hyper::Uri>().unwrap())
            .body(Body::from(self.http_body.clone()))
            .expect("Request builder");

        client
            .request(request)
            .and_then(move |res| {
                let version = res.headers().get("Server").unwrap().to_str().unwrap();
                Ok(TildeBuster::map_iis_version(version))
            })
    }

    pub fn map_iis_version(header: &str) -> IISVersion {
        match header {
            "Microsoft-IIS/1" => IISVersion::IIS1,
            "Microsoft-IIS/2" => IISVersion::IIS2,
            "Microsoft-IIS/3" => IISVersion::IIS3,
            "Microsoft-IIS/4" => IISVersion::IIS4,
            "Microsoft-IIS/5" => IISVersion::IIS5,
            "Microsoft-IIS/6" => IISVersion::IIS6,
            "Microsoft-IIS/7" => IISVersion::IIS7,
            "Microsoft-IIS/7.5" => IISVersion::IIS75,
            "Microsoft-IIS/8" => IISVersion::IIS8,
            "Microsoft-IIS/8.5" => IISVersion::IIS85,
            "Microsoft-IIS/10" => IISVersion::IIS10,
            _ => IISVersion::Unknown,
        }
    }

    pub fn check_if_vulnerable(&self, client: &Client<HttpsConnector<HttpConnector>>, version: IISVersion) -> impl Future<Item = bool, Error = hyper::Error> {
        let magic_suffix = "*~1*/.aspx";
        let vuln_url = format!("{}{}", self.url, magic_suffix);
        let request = Request::builder()
            .header("User-Agent", &self.user_agent[..])
            .method(&self.http_method[..])
            .uri(vuln_url.parse::<hyper::Uri>().unwrap())
            .body(Body::from(self.http_body.clone()))
            .expect("Request builder");

        client
            .request(request)
            .and_then(|res| {
                match res.status() {
                    hyper::StatusCode::NOT_FOUND => Ok(true),
                    hyper::StatusCode::BAD_REQUEST => Ok(false),
                    _ => {
                        warn!("Got invalid HTTP status code when checking if vulnerable: {}", res.status());
                        Ok(false)
                    }
                }
            })
    }
}
