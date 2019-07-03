use futures::Stream;
use hyper::{
    client::HttpConnector,
    rt::{self, Future},
    Body, Client, Request,
};
use hyper_tls::{self, HttpsConnector};
use native_tls;
use std::boxed::Box;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;

use futures::sync::mpsc;

pub mod result_processor;

use result_processor::{FSObject, SingleTildeScanResult, TildeRequest, TildeScanProcessor};

use std::time::SystemTime;

use indicatif::{ProgressBar, ProgressStyle};

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
    pub extension: Option<String>,
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
    pub fn run(mut self) {
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
        let mut current_numbers_of_request = 0;
        let chars = "abcdefghijklmnopqrstuvwxyz1234567890-_"
            .split("")
            .filter(|c| !c.is_empty())
            .map(|c| c.to_owned())
            .collect::<Vec<String>>();
        let chars_duplicate = "234567890"
            .split("")
            .filter(|c| !c.is_empty())
            .map(|c| c.to_owned())
            .collect::<Vec<String>>();
        let start_time = SystemTime::now();
        let mut result_processor = TildeScanProcessor::new();
        let output = self.output.clone();
        let no_progress_bar = self.no_progress_bar;
        let exit_on_connection_errors = self.exit_on_connection_errors;
        let bar = if self.no_progress_bar {
            ProgressBar::hidden()
        } else {
            ProgressBar::new_spinner()
        };
        let tx1 = tx.clone();
        let client1 = client.clone();
        let chars1 = chars.clone();
        bar.set_style(
            ProgressStyle::default_spinner().template("{spinner} [{elapsed_precise}] {msg}"),
        );

        if !self.url.ends_with("/") {
            self.url = format!("{}/", self.url);
        }

        let base_request = TildeRequest {
            url: self.url.clone(),
            http_method: self.http_method.clone(),
            http_headers: self.http_headers.clone(),
            http_body: self.http_body.clone(),
            user_agent: self.user_agent.clone(),
            filename: "".to_owned(),
            extension: "".to_owned(),
            redirect_extension: self.extension.clone(),
            duplicate_index: "1".to_owned(),
        };

        let (tx_futures, rx_futures) = mpsc::unbounded::<
            Box<dyn Future<Item = (), Error = ()> + Send + 'static>,
        >();
        let stream_of_futures = rx_futures
            .map(|fut| {
                rt::spawn(fut);
                Ok(())
            })
            .buffer_unordered(self.n_threads)
            .for_each(Ok)
            .map_err(|err| eprintln!("Err {:?}", err));
        
        std::thread::spawn(|| rt::run(stream_of_futures));

        tx_futures.unbounded_send(Box::new(TildeBuster::_run_checks(tx1.clone(), client1.clone(), base_request))).unwrap();

        let mut spawned_futures = 1;

        while spawned_futures > 0 {
            debug!("spawned_futures: {}", spawned_futures);
            current_numbers_of_request = current_numbers_of_request + 1;
            bar.inc(1);
            spawned_futures = spawned_futures - 1;
            let seconds_from_start =
                start_time.elapsed().unwrap().as_millis() / 1000;
            if seconds_from_start != 0 {
                bar.set_message(&format!(
                    "{} requests done | req/s: {}",
                    current_numbers_of_request,
                    current_numbers_of_request as u64
                        / seconds_from_start as u64,
                ));
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
                    if current_numbers_of_request == 1
                        || exit_on_connection_errors
                    {
                        warn!("Check connectivity to the target");
                        break;
                    }
                }
                None => match msg.kind {
                    FSObject::NotVulnerable => {
                        error!("The target doesn't seem to be vulnerable");
                        warn!(
                            "Try setting HTTP method to OPTIONS or add an extension like aspx"
                        );
                    }
                    FSObject::Vulnerable => {
                        for c in chars.iter() {
                            let request = TildeRequest {
                                url: self.url.clone(),
                                http_method: self.http_method.clone(),
                                http_headers: self.http_headers.clone(),
                                http_body: self.http_body.clone(),
                                user_agent: self.user_agent.clone(),
                                filename: c.to_owned(),
                                extension: "".to_owned(),
                                redirect_extension: self.extension.clone(),
                                duplicate_index: "1".to_owned(),
                            };

                            tx_futures.unbounded_send(Box::new(TildeBuster::_brute_filename(tx1.clone(), client1.clone(), request))).unwrap();
                            spawned_futures = spawned_futures + 1;
                        }
                    }
                    FSObject::NotExisting => {
                        trace!("{:?}", msg);
                    }
                    FSObject::DuplicateFile => {
                        if no_progress_bar {
                            println!(
                                "File\t\t{}~{}.{}",
                                msg.request.filename,
                                msg.request.duplicate_index,
                                msg.request.extension,
                            );
                        } else {
                            bar.println(format!(
                                "File\t\t{}~{}.{}",
                                msg.request.filename,
                                msg.request.duplicate_index,
                                msg.request.extension,
                            ));
                        }

                        result_processor.maybe_add_result(msg);
                    }
                    FSObject::DuplicateDirectory => {
                        if no_progress_bar {
                            println!(
                                "Directory\t{}~{}",
                                msg.request.filename,
                                msg.request.duplicate_index,
                            );
                        } else {
                            bar.println(format!(
                                "Directory\t{}~{}",
                                msg.request.filename,
                                msg.request.duplicate_index,
                            ));
                        }

                        result_processor.maybe_add_result(msg);
                    }
                    FSObject::File => {
                        if no_progress_bar {
                            println!(
                                "File\t\t{}~{}.{}",
                                msg.request.filename,
                                msg.request.duplicate_index,
                                msg.request.extension,
                            );
                        } else {
                            bar.println(format!(
                                "File\t\t{}~{}.{}",
                                msg.request.filename,
                                msg.request.duplicate_index,
                                msg.request.extension,
                            ));
                        }

                        for c in chars_duplicate.iter() {
                            let mut request = msg.request.clone();
                            request.duplicate_index = c.clone();
                            tx_futures
                                .unbounded_send(Box::new(
                                    TildeBuster::_brute_duplicate(
                                        tx1.clone(),
                                        client1.clone(),
                                        request,
                                    ),
                                ))
                                .unwrap();
                            spawned_futures = spawned_futures + 1;
                        }

                        result_processor.maybe_add_result(msg);
                    }
                    FSObject::Directory => {
                        if no_progress_bar {
                            println!(
                                "Directory\t{}~{}",
                                msg.request.filename,
                                msg.request.duplicate_index
                            );
                        } else {
                            bar.println(format!(
                                "Directory\t{}~{}",
                                msg.request.filename,
                                msg.request.duplicate_index
                            ));
                        }

                        for c in chars_duplicate.iter() {
                            let mut request = msg.request.clone();
                            request.duplicate_index = c.clone();
                            tx_futures
                                .unbounded_send(Box::new(
                                    TildeBuster::_brute_duplicate(
                                        tx1.clone(),
                                        client1.clone(),
                                        request,
                                    ),
                                ))
                                .unwrap();
                            spawned_futures = spawned_futures + 1;
                        }

                        result_processor.maybe_add_result(msg);
                    }
                    FSObject::BruteExtension => {
                        for c in chars1.iter() {
                            let mut request = msg.request.clone();
                            request.extension =
                                format!("{}{}", request.extension, c);
                            tx_futures
                                .unbounded_send(Box::new(
                                    TildeBuster::_brute_extension(
                                        tx1.clone(),
                                        client1.clone(),
                                        request,
                                    ),
                                ))
                                .unwrap();
                            spawned_futures = spawned_futures + 1;
                        }
                    }
                    FSObject::BruteFilename => {
                        for c in chars1.iter() {
                            let mut request = msg.request.clone();
                            request.filename =
                                format!("{}{}", request.filename, c);
                            tx_futures
                                .unbounded_send(Box::new(
                                    TildeBuster::_brute_filename(
                                        tx1.clone(),
                                        client1.clone(),
                                        request,
                                    ),
                                ))
                                .unwrap();
                            spawned_futures = spawned_futures + 1;
                        }
                    }
                    FSObject::CheckIfDirectory => {
                        tx_futures
                            .unbounded_send(Box::new(
                                TildeBuster::_check_if_directory(
                                    tx1.clone(),
                                    client1.clone(),
                                    msg.request,
                                ),
                            ))
                            .unwrap();
                        spawned_futures = spawned_futures + 1;
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

    fn _brute_extension(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = (), Error = ()> {
        let magic_suffix = match &request.redirect_extension {
            Some(v) => format!("/.{}", v),
            None => "".to_owned(),
        };

        let vuln_url = format!(
            "{}{}~1.{}{}{}",
            request.url,
            request.filename,
            request.extension,
            "%3f".repeat(3 - request.extension.len()),
            magic_suffix,
        );
        let hyper_request = Request::builder()
            .header("User-Agent", &request.user_agent[..])
            .method(&request.http_method[..])
            .uri(&vuln_url.parse::<hyper::Uri>().unwrap())
            .body(Body::from(request.http_body.clone()))
            .expect("Request builder");

        client
            .request(hyper_request)
            .and_then(move |res| {
                match (res.status(), request.extension.len()) {
                    (hyper::StatusCode::NOT_FOUND, 3) => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::File,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    }
                    (hyper::StatusCode::NOT_FOUND, _) => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::BruteExtension,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    }
                    (hyper::StatusCode::BAD_REQUEST, _) | _ => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::NotExisting,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    } // _ => {
                      //     warn!(
                      //         "Got invalid HTTP status code when bruteforcing the extension: {}",
                      //         res.status()
                      //     );
                      // }
                }

                Ok(())
            })
            .or_else(|e| {
                warn!("Got HTTP error when bruteforcing the extension: {}", e);
                Ok(())
            })
    }

    fn _brute_filename(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = (), Error = ()> {
        let magic_suffix = match &request.redirect_extension {
            Some(v) => format!("*~1*/.{}", v),
            None => "*~1*".to_owned(),
        };

        let magic_suffix_short = match &request.redirect_extension {
            Some(v) => format!("~1*/.{}", v),
            None => "~1*".to_owned(),
        };

        let vuln_url = format!("{}{}{}", request.url, request.filename, magic_suffix);
        let vuln_url_short = format!("{}{}{}", request.url, request.filename, magic_suffix_short);

        let hyper_request = Request::builder()
            .header("User-Agent", &request.user_agent[..])
            .method(&request.http_method[..])
            .uri(&vuln_url.parse::<hyper::Uri>().unwrap())
            .body(Body::from(request.http_body.clone()))
            .expect("Request builder");

        let hyper_request_short = Request::builder()
            .header("User-Agent", &request.user_agent[..])
            .method(&request.http_method[..])
            .uri(&vuln_url_short.parse::<hyper::Uri>().unwrap())
            .body(Body::from(request.http_body.clone()))
            .expect("Request builder");

        let req = client.request(hyper_request);
        let req_short = client.request(hyper_request_short);

        req.join(req_short)
            .and_then(move |(res, res_short)| {
                match (res.status(), res_short.status()) {
                    (_, hyper::StatusCode::NOT_FOUND) => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::CheckIfDirectory,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    }
                    (hyper::StatusCode::NOT_FOUND, _) => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::BruteFilename,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    }
                    (hyper::StatusCode::BAD_REQUEST, _) | _ => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::NotExisting,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    } // _ => {
                      //     warn!(
                      //         "Got invalid HTTP status code when bruteforcing the filename: {}",
                      //         res.status()
                      //     );
                      // }
                }

                Ok(())
            })
            .or_else(|e| {
                warn!("Got HTTP error when bruteforcing the filename: {}", e);
                Ok(())
            })
    }

    fn _check_if_directory(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = (), Error = ()> {
        let magic_suffix = match &request.redirect_extension {
            Some(v) => format!("*~1/.{}", v),
            None => "*~1".to_owned(),
        };
        let vuln_url = format!("{}{}{}", request.url, request.filename, magic_suffix);
        let hyper_request = Request::builder()
            .header("User-Agent", &request.user_agent[..])
            .method(&request.http_method[..])
            .uri(vuln_url.parse::<hyper::Uri>().unwrap())
            .body(Body::from(request.http_body.clone()))
            .expect("Request builder");

        client
            .request(hyper_request)
            .and_then(move |res| {
                match res.status() {
                    hyper::StatusCode::NOT_FOUND => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::Directory,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    }
                    hyper::StatusCode::BAD_REQUEST | _ => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::BruteExtension,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    } // _ => {
                      //     warn!(
                      //         "Got invalid HTTP status code when checking if directory: {}",
                      //         res.status()
                      //     );
                      // }
                }

                Ok(())
            })
            .or_else(|e| {
                warn!("Got HTTP error when checking if directory: {}", e);
                Ok(())
            })
    }

    pub fn check_iis_version(
        client: &Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = IISVersion, Error = hyper::Error> {
        let hyper_request = Request::builder()
            .header("User-Agent", &request.user_agent[..])
            .method(&request.http_method[..])
            .uri(request.url.parse::<hyper::Uri>().unwrap())
            .body(Body::from(request.http_body.clone()))
            .expect("Request builder");

        client
            .request(hyper_request)
            .and_then(move |res| Ok(TildeBuster::map_iis_version(res.headers())))
    }

    pub fn map_iis_version(headers: &hyper::HeaderMap) -> IISVersion {
        match headers.get("Server") {
            None => IISVersion::Unknown,
            Some(v) => match v.to_str().unwrap() {
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
            },
        }
    }

    pub fn check_if_vulnerable(
        client: &Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
        _version: IISVersion,
    ) -> impl Future<Item = bool, Error = hyper::Error> {
        let magic_suffix = match &request.redirect_extension {
            Some(v) => format!("*~1*/.{}", v),
            None => "*~1*".to_owned(),
        };
        let not_existing_suffix = match &request.redirect_extension {
            Some(v) => format!("AAAAB*~1/.{}", v),
            None => "AAAAB*~1".to_owned(),
        };
        let vuln_url = format!("{}{}", request.url, magic_suffix);
        let not_existing_url = format!("{}{}", request.url, not_existing_suffix);
        let hyper_request = Request::builder()
            .header("User-Agent", &request.user_agent[..])
            .method(&request.http_method[..])
            .uri(vuln_url.parse::<hyper::Uri>().unwrap())
            .body(Body::from(request.http_body.clone()))
            .expect("Request builder");

        let not_existing_hyper_request = Request::builder()
            .header("User-Agent", &request.user_agent[..])
            .method(&request.http_method[..])
            .uri(not_existing_url.parse::<hyper::Uri>().unwrap())
            .body(Body::from(request.http_body.clone()))
            .expect("Request builder");

        let fut1 = client
            .request(hyper_request)
            .and_then(|res| match res.status() {
                hyper::StatusCode::NOT_FOUND => Ok(true),
                hyper::StatusCode::BAD_REQUEST => Ok(false),
                _ => {
                    warn!(
                        "Got invalid HTTP status code when checking if vulnerable: {}",
                        res.status()
                    );
                    Ok(false)
                }
            });

        let fut2 = client
            .request(not_existing_hyper_request)
            .and_then(|res| match res.status() {
                hyper::StatusCode::NOT_FOUND => Ok(true),
                hyper::StatusCode::BAD_REQUEST => Ok(false),
                _ => {
                    warn!(
                        "Got invalid HTTP status code when checking if vulnerable: {}",
                        res.status()
                    );
                    Ok(false)
                }
            });

        fut1.join(fut2).and_then(|res| match res {
            (true, false) => Ok(true),
            _ => Ok(false),
        })
    }

    pub fn _run_checks(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = (), Error = ()> {
        TildeBuster::check_iis_version(&client, request.clone())
            .and_then(move |version| {
                futures::future::ok(version.clone())
                    .join(TildeBuster::check_if_vulnerable(&client.clone(), request.clone(), version))
                    .and_then(move |(version, is_vulnerable)| {
                        info!("iis version: {:?}", version);
                        info!("is vulnerable: {:?}", is_vulnerable);
                        let res = match is_vulnerable {
                            true => SingleTildeScanResult {
                                kind: FSObject::Vulnerable,
                                error: None,
                                request: request,
                            },
                            false => SingleTildeScanResult {
                                kind: FSObject::NotVulnerable,
                                error: None,
                                request: request,
                            },
                        };

                        tx.send(res).unwrap();
                        Ok(())
                    })
            })
            .or_else(|e| {
                warn!("Got HTTP error when running checks: {}", e);
                Ok(())
            })
    }

    pub fn _brute_duplicate(
        tx: Sender<SingleTildeScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        request: TildeRequest,
    ) -> impl Future<Item = (), Error = ()> {
        let vuln_url = match (&request.extension.len(), &request.redirect_extension) {
            (0, Some(v)) => format!(
                "{}{}~{}/.{}",
                request.url, request.filename, request.duplicate_index, v,
            ),
            (0, None) => format!(
                "{}{}~{}",
                request.url, request.filename, request.duplicate_index,
            ),
            (_, Some(v)) => format!(
                "{}{}~{}.{}/.{}",
                request.url, request.filename, request.duplicate_index, request.extension, v,
            ),
            (_, None) => format!(
                "{}{}~{}.{}",
                request.url, request.filename, request.duplicate_index, request.extension,
            ),
        };

        let hyper_request = Request::builder()
            .header("User-Agent", &request.user_agent[..])
            .method(&request.http_method[..])
            .uri(&vuln_url.parse::<hyper::Uri>().unwrap())
            .body(Body::from(request.http_body.clone()))
            .expect("Request builder");

        client
            .request(hyper_request)
            .and_then(move |res| {
                match (res.status(), request.extension.len()) {
                    (hyper::StatusCode::NOT_FOUND, 3) => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::DuplicateFile,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    }
                    (hyper::StatusCode::NOT_FOUND, _) => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::DuplicateDirectory,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    }
                    (hyper::StatusCode::BAD_REQUEST, _) | _ => {
                        let res = SingleTildeScanResult {
                            kind: FSObject::NotExisting,
                            error: None,
                            request: request,
                        };
                        tx.send(res).unwrap();
                    } // _ => {
                      //     warn!(
                      //         "Got invalid HTTP status code when bruteforcing duplicates: {}",
                      //         res.status()
                      //     );
                      // }
                }

                Ok(())
            })
            .or_else(|e| {
                warn!("Got HTTP error when bruteforcing duplicates: {}", e);
                Ok(())
            })
    }
}
