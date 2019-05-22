use futures::Stream;
use hyper::{
    client::HttpConnector,
    rt::{self, Future},
    Body, Client, Method, Request, StatusCode, Uri,
};
use hyper_tls::{self, HttpsConnector};
use native_tls;
use std::sync::mpsc::Sender;

pub mod result_processor;
pub mod utils;

use result_processor::SingleDirScanResult;
use utils::*;

#[derive(Debug, Clone)]
pub struct DirConfig {
    pub n_threads: usize,
    pub ignore_certificate: bool,
    pub http_method: String,
    pub http_body: String,
    pub user_agent: String,
    pub http_headers: Vec<(String, String)>,
}

fn make_request_future(
    tx: Sender<SingleDirScanResult>,
    client: &Client<HttpsConnector<HttpConnector>>,
    url: Uri,
    config: &DirConfig,
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

    for header_tuple in &config.http_headers {
        request_builder.header(header_tuple.0.as_str(), header_tuple.1.as_str());
    }

    let request = request_builder.header("User-Agent", &config.user_agent[..])
        .method(&config.http_method[..])
        .uri(url)
        .body(Body::from(config.http_body.clone()))
        .expect("Request builder");

    client
        .request(request)
        .and_then(move |res| {
            let status = res.status();
            target.status = status.to_string();
            if status.is_redirection() {
                target.extra = Some(res.headers().get("Location").unwrap().to_str().unwrap().to_owned());
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

pub fn run(tx: Sender<SingleDirScanResult>, urls: Vec<hyper::Uri>, config: DirConfig) {
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

    let stream = futures::stream::iter_ok(urls)
        .map(move |url| make_request_future(tx.clone(), &client, url, &config))
        .buffer_unordered(n_threads)
        .for_each(Ok)
        .map_err(|err| eprintln!("Err {:?}", err));

    rt::run(stream);
}
