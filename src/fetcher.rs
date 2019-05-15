use hyper::rt::{self, lazy, Future};
use hyper::{Client, StatusCode};

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
    rt::run(lazy(|| {
        let client = Client::new();

        for url in urls {
            rt::spawn(_fetch_url(&client, url));
        }

        Ok(())
    }));
}
