extern crate hyper;

use std::io::{self, Write};
use hyper::Client;
use hyper::rt::{self, Future, Stream};

pub mod fetcher {
    pub fn fetch_url(url: hyper::Uri) -> impl Future<Item=(), Error=()> {
        let client = Client::new();

        client
            // Fetch the url...
            .get(url)
            // And then, if we get a response back...
            .and_then(|res| {
                println!("Response: {}", res.status());
                println!("Headers: {:#?}", res.headers());

                // The body is a stream, and for_each returns a new Future
                // when the stream is finished, and calls the closure on
                // each chunk of the body...
                res.into_body().for_each(|chunk| {
                    io::stdout().write_all(&chunk)
                        .map_err(|e| panic!("example expects stdout is open, error={}", e))
                })
            })
            // If all good, just tell the user...
            .map(|_| {
                println!("\n\nDone.");
            })
            // If there was an error, let the user know...
            .map_err(|err| {
                eprintln!("Error {}", err);
            })
    }

    pub fn run(url: hyper::Uri) {
        rt::run(fetch_url(url));
        // Run the runtime with the future trying to fetch and print this URL.
        //
        // Note that in more complicated use cases, the runtime should probably
        // run on its own, and futures should just be spawned into it.
    }
}
