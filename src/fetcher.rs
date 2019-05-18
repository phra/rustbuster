use hyper::rt::{self, lazy, Future};
use hyper::{Client, StatusCode};
use futures::Stream;

fn _fetch_url(
    client: &hyper::Client<hyper::client::HttpConnector>,
    url: hyper::Uri,
) -> impl Future<Item = (), Error = ()> {
    client
        // Fetch the url...
        .get(url)
        // And then, if we get a response back...
        .and_then(|res| {
            if res.status() == StatusCode::OK {
                println!("Response: {}", res.status());
                println!("Headers: {:#?}", res.headers());
            }

            Ok(())
        })
        // If there was an error, let the user know...
        .map_err(|err| {
            eprintln!("Error {}", err);
        })
}

pub fn _run(urls: Vec<hyper::Uri>) {
    let client = Client::new();

    let stream = futures::stream::iter_ok(urls)
        .map(move |url| _fetch_url(&client, url))
        .buffer_unordered(1)
        .for_each(|_| Ok(()))
        .map_err(|_| eprintln!("Err"));

    rt::run(stream);
}
