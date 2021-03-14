use futures::Stream;
use hyper::{
    client::HttpConnector,
    rt::{self, Future},
    Body, Client, Request, StatusCode, Uri,
};
use hyper_tls::{self, HttpsConnector};
use native_tls;

use std::sync::{mpsc::Sender, Arc, Mutex};
use std::sync::mpsc::channel;
use indicatif::{ProgressBar, ProgressStyle};

pub mod result_processor;
pub mod utils;

use utils::{build_vhosts, save_vhost_results};
use std::{fs, time::SystemTime};

use result_processor::{SingleVhostScanResult, VhostScanResult};

#[derive(Debug, Clone)]
pub struct VhostBuster {
    pub n_threads: usize,
    pub ignore_certificate: bool,
    pub ignore_strings: Vec<String>,
    pub user_agent: String,
    pub http_method: String,
    pub original_url: String,
    pub wordlist_path: String,
    pub domain: String,
    pub no_progress_bar: bool,
    pub exit_on_connection_errors: bool,
    pub output: String,
}

impl VhostBuster {

    fn make_request_future(
        &self,
        tx: Sender<SingleVhostScanResult>,
        client: &Client<HttpsConnector<HttpConnector>>,
        url: Uri,
    ) -> impl Future<Item = (), Error = ()> {
        let tx_err = tx.clone();
        let target = Arc::new(Mutex::new(SingleVhostScanResult {
            vhost: url.to_string(),
            status: StatusCode::default().to_string(),
            error: None,
            method: self.http_method.clone(),
            ignored: false,
        }));
        let target_res = target.clone();
        let mut target_err = (*target.lock().unwrap()).clone();
        let mut request_builder = Request::builder();
        let ignore_strings = self.ignore_strings.clone();
        let request = request_builder
            .header("User-Agent", &self.user_agent[..])
            .method(&self.http_method[..])
            .uri(&self.original_url)
            .header("Host", url.host().unwrap())
            .body(Body::from(""))
            .expect("Request builder");
    
        client
            .request(request)
            .and_then(move |res| {
                target.lock().unwrap().status = res.status().to_string();
                res.into_body().concat2()
            })
            .and_then(move |body| {
                let vec = body.iter().cloned().collect();
                let body = String::from_utf8(vec).unwrap();
                target_res.lock().unwrap().ignored = false;
                for s in ignore_strings {
                    if body.contains(&s) {
                        target_res.lock().unwrap().ignored = true;
                        break;
                    }
                }
    
                let target = Arc::try_unwrap(target_res).unwrap().into_inner().unwrap();
                tx.send(target).unwrap();
                Ok(())
            })
            .or_else(move |e| {
                target_err.error = Some(e.to_string());
                tx_err.send(target_err).unwrap_or_else(|_| ());
                Ok(())
            })
    }
    
    pub fn run(self) {
        let mut current_numbers_of_request = 0;
        let start_time = SystemTime::now();
        let output = self.output.clone();
        let no_progress_bar = self.no_progress_bar;
        let exit_on_connection_errors = self.exit_on_connection_errors;
        let n_threads = self.n_threads;
        let (tx, rx) = channel::<SingleVhostScanResult>();
        let mut tls_connector_builder = native_tls::TlsConnector::builder();
        tls_connector_builder.danger_accept_invalid_certs(self.ignore_certificate);
        let tls_connector = tls_connector_builder
            .build()
            .expect("TLS initialization failed");
        let mut http_connector = HttpConnector::new(self.n_threads);
        http_connector.enforce_http(false);
        let https_connector = HttpsConnector::from((http_connector, tls_connector));
        let client = Client::builder().build(https_connector);
    
        let vhosts = build_vhosts(&self.wordlist_path, &self.domain);
        let total_numbers_of_request = vhosts.len();

        let mut result_processor = VhostScanResult::new();
        let bar = if self.no_progress_bar {
            ProgressBar::hidden()
        } else {
            ProgressBar::new(total_numbers_of_request as u64)
        };
        bar.set_draw_delta(100);
        bar.set_style(ProgressStyle::default_bar()
            .template("{spinner} [{elapsed_precise}] {bar:40.red/white} {pos:>7}/{len:7} ETA: {eta_precise} req/s: {msg}")
            .progress_chars("#>-"));
        let stream = futures::stream::iter_ok(vhosts)
            .map(move |url| self.make_request_future(tx.clone(), &client, url))
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
                    error!("{} - {:?}", msg.vhost, e);
                    if current_numbers_of_request == 1 || exit_on_connection_errors
                    {
                        warn!("Check connectivity to the target");
                        break;
                    }

                    continue;
                }
                None => (),
            }

            let n_tabs = match msg.status.len() / 8 {
                3 => 1,
                2 => 2,
                1 => 3,
                0 => 4,
                _ => 0,
            };

            if !msg.ignored {
                result_processor.maybe_add_result(msg.clone());
                if no_progress_bar {
                    println!(
                        "{}\t{}{}{}",
                        msg.method,
                        msg.status,
                        "\t".repeat(n_tabs),
                        msg.vhost
                    );
                } else {
                    bar.println(format!(
                        "{}\t{}{}{}",
                        msg.method,
                        msg.status,
                        "\t".repeat(n_tabs),
                        msg.vhost
                    ));
                }
            }
        }

        bar.finish();
        println!("{}", crate::banner::ending_time());

        if !output.is_empty() {
            save_vhost_results(&output, &result_processor.results);
        }
    }
}
