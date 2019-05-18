use hyper::{
    Client, StatusCode,
    rt::{self, Future}
};
use futures::Stream;
use std::sync::mpsc::Sender;

#[derive(Debug)]
pub enum FetcherMessage {
    Response(String),
    Log(String)
}

fn _fetch_url(
    tx: Sender<FetcherMessage>,
    client: &hyper::Client<hyper::client::HttpConnector>,
    url: hyper::Uri,
) -> impl Future<Item = (), Error = ()> {
    client
        // Fetch the url...
        .get(url)
        // And then, if we get a response back...
        .and_then(move |res| {
            if res.status() == StatusCode::OK {
                println!("Response: {}", res.status());
                println!("Headers: {:#?}", res.headers());

                tx.send(
                    FetcherMessage::Log(String::from("Status != 200"))
                ).unwrap();
            }

            tx.send(
                FetcherMessage::Response(String::from("Response received!"))
            ).unwrap();

            Ok(())
        })
        // If there was an error, let the user know...
        .map_err(|err| {
            eprintln!("Error {}", err);
        })
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
