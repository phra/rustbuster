use futures::Stream;
use hyper::{
    rt::{self, Future},
    Client, Method, StatusCode, Uri,
    client::HttpConnector
};
use hyper_tls::{
    self,
    HttpsConnector
};
use native_tls;
use std::sync::mpsc::Sender;

#[derive(Debug, Clone)]
pub struct Target {
    url: Uri,
    method: Method,
    status: StatusCode,
    pub error: Option<String>,
}

fn _fetch_url(
    tx: Sender<Target>,
    client: &Client<HttpsConnector<HttpConnector>>,
    url: Uri,
) -> impl Future<Item = (), Error = ()> {
    let tx_err = tx.clone();
    let mut target = Target {
        url: url.clone(),
        method: Method::GET,
        status: StatusCode::default(),
        error: None,
    };
    let mut target_err = target.clone();

    client
        .get(url)
        .and_then(move |res| {
            target.status = res.status();

            tx.send(target).unwrap();

            Ok(())
        })
        .or_else(move |e| {
            target_err.error = Some(e.to_string());
            tx_err.send(target_err).unwrap();
            Ok(())
        })
}

pub fn _run(tx: Sender<Target>, urls: Vec<hyper::Uri>, n_threads: usize) {
    let mut tls_connector_builder = native_tls::TlsConnector::builder();
    tls_connector_builder.danger_accept_invalid_certs(true);
    let tls_connector = tls_connector_builder.build().unwrap();
    let http_connector = HttpConnector::new(n_threads);
    let https_connector = HttpsConnector::from((http_connector, tls_connector));
    let https = HttpsConnector::new(n_threads);
    let client = Client::builder().build(https);

    let stream = futures::stream::iter_ok(urls)
        .map(move |url| _fetch_url(tx.clone(), &client, url))
        .buffer_unordered(n_threads)
        .for_each(Ok)
        .map_err(|err| eprintln!("Err {:?}", err));

    rt::run(stream);
}
