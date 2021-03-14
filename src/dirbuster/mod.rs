use futures::Stream;
use hyper::{
    client::HttpConnector,
    rt::{self, Future},
    Body, Client, Method, Request, StatusCode, Uri,
};
use hyper_tls::{self, HttpsConnector};
use native_tls;
use std::sync::mpsc::channel;
use std::sync::mpsc::Sender;
use std::{time::SystemTime};
use indicatif::{ProgressBar, ProgressStyle};

pub mod result_processor;
pub mod utils;

use result_processor::{SingleDirScanResult, ResultProcessorConfig, ScanResult};
use utils::{save_dir_results, build_urls};

#[derive(Debug, Clone)]
pub struct DirBuster {
    pub n_threads: usize,
    pub ignore_certificate: bool,
    pub http_method: String,
    pub http_body: String,
    pub user_agent: String,
    pub http_headers: Vec<(String, String)>,
    pub url: String,
    pub wordlist_path: String,
    pub extensions: Vec<String>,
    pub append_slash: bool,
    pub include_status_codes: Vec<String>,
    pub ignore_status_codes: Vec<String>,
    pub no_progress_bar: bool,
    pub exit_on_connection_errors: bool,
    pub output: String,
}

impl DirBuster {
    pub fn run(self) {
        let mut current_numbers_of_request = 0;
        let start_time = SystemTime::now();
        let output = self.output.clone();
        let no_progress_bar = self.no_progress_bar;
        let exit_on_connection_errors = self.exit_on_connection_errors;
        let n_threads = self.n_threads;
        let urls = build_urls(
            &self.wordlist_path,
            &self.url,
            &self.extensions,
            self.append_slash,
        );
        let total_numbers_of_request = urls.len();
        let (tx, rx) = channel::<SingleDirScanResult>();
        let mut tls_connector_builder = native_tls::TlsConnector::builder();
        tls_connector_builder.danger_accept_invalid_certs(self.ignore_certificate);
        let tls_connector = tls_connector_builder
            .build()
            .expect("TLS initialization failed");
        let mut http_connector = HttpConnector::new(self.n_threads);
        http_connector.enforce_http(false);
        let https_connector = HttpsConnector::from((http_connector, tls_connector));
        let client = Client::builder().build(https_connector);
        let rp_config = ResultProcessorConfig {
            include: self.include_status_codes.clone(),
            ignore: self.ignore_status_codes.clone(),
        };
        let mut result_processor = ScanResult::new(rp_config);
        let bar = if self.no_progress_bar {
            ProgressBar::hidden()
        } else {
            ProgressBar::new(total_numbers_of_request as u64)
        };
        bar.set_draw_delta(100);
        bar.set_style(ProgressStyle::default_bar()
            .template("{spinner} [{elapsed_precise}] {bar:40.red/white} {pos:>7}/{len:7} ETA: {eta_precise} req/s: {msg}")
            .progress_chars("#>-"));

        let stream = futures::stream::iter_ok(urls)
            .map(move |request| {
                self.make_request_future(tx.clone(), client.clone(), request)
            })
            .buffer_unordered(n_threads)
            .for_each(Ok)
            .map_err(|err| eprintln!("Err {:?}", err));

        let _ = std::thread::spawn(move || rt::run(stream));

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
                    error!("{} - {:?}", msg.url, e);
                    if current_numbers_of_request == 1 || exit_on_connection_errors
                    {
                        warn!("Check connectivity to the target");
                        break;
                    }

                    continue;
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

                if no_progress_bar {
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
        
        if !output.is_empty() {
            save_dir_results(&output, &result_processor.results);
        }
    }
    
    fn make_request_future(
        &self,
        tx: Sender<SingleDirScanResult>,
        client: Client<HttpsConnector<HttpConnector>>,
        url: Uri,
    ) -> impl Future<Item = (), Error = ()> {
        let tx_err = tx.clone();
        let mut target = SingleDirScanResult {
            url: url.to_string(),
            method: Method::GET.to_string(),
            status: StatusCode::default().to_string(),
            error: None,
            extra: None,
        };
        let mut target_err = target.clone();
        let mut request_builder = Request::builder();
        
        for header_tuple in &self.http_headers {
            request_builder.header(header_tuple.0.as_str(), header_tuple.1.as_str());
        }
        
        let request = request_builder
        .header("User-Agent", &self.user_agent[..])
        .method(&self.http_method[..])
        .uri(&url)
        .header("Host", url.host().unwrap())
        .body(Body::from(self.http_body.clone()))
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
}
