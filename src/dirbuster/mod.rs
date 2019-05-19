use futures::Stream;
use hyper::{
    client::HttpConnector,
    rt::{self, Future},
    Client, Method, StatusCode, Uri,
};
use hyper_tls::{self, HttpsConnector};
use native_tls;
use std::sync::mpsc::Sender;

pub mod utils;
pub mod result_processor;

use result_processor::SingleScanResult;
use utils::*;

fn _fetch_url(
    tx: Sender<SingleScanResult>,
    client: &Client<HttpsConnector<HttpConnector>>,
    url: Uri,
) -> impl Future<Item = (), Error = ()> {
    let tx_err = tx.clone();
    let mut target = SingleScanResult {
        url: url.to_string(),
        method: Method::GET.to_string(),
        status: StatusCode::default().to_string(),
        error: None,
    };
    let mut target_err = target.clone();

    client
        .get(url)
        .and_then(move |res| {
            target.status = res.status().to_string();

            tx.send(target).unwrap();

            Ok(())
        })
        .or_else(move |e| {
            target_err.error = Some(e.to_string());
            tx_err.send(target_err).unwrap_or_else(|_| ());
            Ok(())
        })
}

pub fn run(tx: Sender<SingleScanResult>, urls: Vec<hyper::Uri>, config: &Config) {
    let mut tls_connector_builder = native_tls::TlsConnector::builder();
    tls_connector_builder.danger_accept_invalid_certs(config.ignore_certificate);
    let tls_connector = tls_connector_builder
        .build()
        .expect("TLS initialization failed");
    let mut http_connector = HttpConnector::new(config.n_threads);
    http_connector.enforce_http(false);
    let https_connector = HttpsConnector::from((http_connector, tls_connector));
    let client = Client::builder().build(https_connector);

    let stream = futures::stream::iter_ok(urls)
        .map(move |url| _fetch_url(tx.clone(), &client, url))
        .buffer_unordered(config.n_threads)
        .for_each(Ok)
        .map_err(|err| eprintln!("Err {:?}", err));

    rt::run(stream);
}
