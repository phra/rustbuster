use hyper::{
    Client,
    Uri,
    Method,
    StatusCode,
    rt::{self, Future},
    error::Error
};
use futures::Stream;

use std::sync::mpsc::Sender;

#[derive(Debug)]
pub struct Target {
    url: Uri,
    method: Method,
    status: StatusCode
}

type FetcherMessage = Result<Target, Error>;

fn _fetch_url(
    tx: Sender<FetcherMessage>,
    client: &hyper::Client<hyper::client::HttpConnector>,
    url: Uri,
) -> impl Future<Item = (), Error = ()> {
    let in_url = url.clone();
    let tx_err = tx.clone();
    client
        // Fetch the url...
        .get(url)
        // And then, if we get a response back...
        .and_then(move |res| {
            let res = Target {
                url: in_url,
                method: Method::GET,
                status: res.status()
            };

            tx.send(Ok(res)).unwrap();

            Ok(())
        })
        // If there was an error, let the user know...
        .map_err(move |e| tx_err.send(Err(e)).unwrap())
}

pub fn _run(tx: Sender<FetcherMessage>, urls: Vec<hyper::Uri>) {
    let client = Client::new();

    let stream = futures::stream::iter_ok(urls)
        .map(move |url| _fetch_url(tx.clone(), &client, url))
        .buffer_unordered(1)
        .for_each(Ok)
        .map_err(|_| eprintln!("Err"));

    rt::run(stream);
}
