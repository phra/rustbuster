use futures::Stream;
use hyper::{
    client::HttpConnector,
    rt::{self, Future},
    Body, Client, Request, StatusCode, Uri,
};
use hyper_tls::{self, HttpsConnector};
use native_tls;
use std::sync::mpsc::Sender;

pub mod result_processor;
pub mod utils;

use result_processor::SingleVhostScanResult;

#[derive(Debug, Clone)]
pub struct VhostConfig {
    pub n_threads: usize,
    pub ignore_certificate: bool,
    pub ignore_strings: Vec<String>,
    pub user_agent: String,
    pub http_method: String,
    pub original_url: String,
}

fn make_request_future(
    tx: Sender<SingleVhostScanResult>,
    client: &Client<HttpsConnector<HttpConnector>>,
    url: Uri,
    config: &VhostConfig,
) -> impl Future<Item = (), Error = ()> {
    let tx_err = tx.clone();
    let mut target = SingleVhostScanResult {
        vhost: url.to_string(),
        status: StatusCode::default().to_string(),
        error: None,
        method: config.http_method.clone(),
        ignored: false,
    };
    let mut target_err = target.clone();
    let mut request_builder = Request::builder();
    let ignore_strings = config.ignore_strings.clone();
    let request = request_builder.header("User-Agent", &config.user_agent[..])
        .method(&config.http_method[..])
        .uri(&config.original_url)
        .header("Host", url.host().unwrap())
        .body(Body::from(""))
        .expect("Request builder");

    client
        .request(request)
        .and_then(|res| {
            res.into_body().concat2()
        })
        .and_then(move |_body| {
            let vec = _body.iter().cloned().collect();
            let body = String::from_utf8(vec).unwrap();
            target.ignored = false;
            for s in ignore_strings {
                if body.contains(&s) {
                    target.ignored = true;
                    break;
                }
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

pub fn run(tx: Sender<SingleVhostScanResult>, urls: Vec<hyper::Uri>, config: VhostConfig) {
    let mut tls_connector_builder = native_tls::TlsConnector::builder();
    tls_connector_builder.danger_accept_invalid_certs(config.ignore_certificate);
    let tls_connector = tls_connector_builder
        .build()
        .expect("TLS initialization failed");
    let mut http_connector = HttpConnector::new(config.n_threads);
    http_connector.enforce_http(false);
    let https_connector = HttpsConnector::from((http_connector, tls_connector));
    let client = Client::builder().build(https_connector);
    let n_threads = config.n_threads;
    debug!("{:?}", urls);

    let stream = futures::stream::iter_ok(urls)
        .map(move |url| make_request_future(tx.clone(), &client, url, &config))
        .buffer_unordered(n_threads)
        .for_each(Ok)
        .map_err(|err| eprintln!("Err {:?}", err));

    rt::run(stream);
}
