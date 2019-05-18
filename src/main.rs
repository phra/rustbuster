#[macro_use] extern crate log;

use clap::{App, Arg};

use std::{
    fs, str, thread,
    sync::mpsc::channel
};

use crate::fetcher::FetcherMessage;

mod fetcher;

fn main() {
    pretty_env_logger::init();
    let matches = App::new("rustbuster")
        .version("0.1")
        .author("phra <greensoncio@gmail.com>, ps1dr3x <michele@federici.tech>")
        .about("DirBuster for rust")
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .arg(
            Arg::with_name("url")
                .help("Sets the target URL")
                .short("u")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("wordlist")
                .help("Sets the wordlist")
                .short("w")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("extensions")
                .help("Sets the extensions")
                .short("e")
                .default_value("")
                .use_delimiter(true),
        )
        .arg(
            Arg::with_name("mode")
                .help("Sets the mode of operation (dir, dns, fuzz)")
                .short("m")
                .takes_value(true)
                .default_value("dir"),
        )
        .get_matches();

    let url = matches.value_of("url").unwrap();
    let wordlist_path = matches.value_of("wordlist").unwrap();
    let mode = matches.value_of("mode").unwrap();
    let extensions = matches
        .values_of("extensions")
        .unwrap()
        .filter(|e| e.len() != 0)
        .collect::<Vec<&str>>();

    // HTTPS requires picking a TLS implementation, so give a better
    // warning if the user tries to request an 'https' URL.
    match url.parse::<hyper::Uri>() {
        Ok(v) => {
            if v.scheme_part().map(|s| s.as_ref()) != Some("http") {
                println!("This example only works with 'http' URLs.");
                return;
            }
        }
        Err(e) => {
            error!("URI: {}", e);
            return;
        }
    }

    debug!("Using url: {:?}", url);
    debug!("Using wordlist: {:?}", wordlist_path);
    debug!("Using mode: {:?}", mode);
    debug!("Using extensions: {:?}", extensions);

    // Vary the output based on how many times the user used the "verbose" flag
    // (i.e. 'myprog -v -v -v' or 'myprog -vvv' vs 'myprog -v'
    match matches.occurrences_of("verbose") {
        0 => info!("No verbose info"),
        1 => info!("Some verbose info"),
        2 => info!("Tons of verbose info"),
        3 | _ => info!("Don't be crazy"),
    }

    match mode {
        "dir" => {
            debug!("using mode: dir");
            let urls = load_wordlist_and_build_urls(wordlist_path, url, extensions);
            debug!("urls: {:#?}", urls);

            let (tx, rx) = channel();

            thread::spawn(move || {
                fetcher::_run(tx, urls);
            });

            loop {
                let msg = match rx.recv() {
                    Ok(msg) => msg,
                    Err(_err) => continue
                };

                match msg {
                    FetcherMessage::Response(res) => {
                        println!("{:?}", res);
                    }
                    FetcherMessage::Log(log) => {
                        println!("{:?}", log);
                    }
                }
            }
        }
        _ => (),
    }
}

fn load_wordlist_and_build_urls(
    wordlist_path: &str,
    url: &str,
    extensions: Vec<&str>,
) -> Vec<hyper::Uri> {
    debug!("loading wordlist");
    let contents =
        fs::read_to_string(wordlist_path).expect("Something went wrong reading the file");

    let splitted_lines = contents.lines();
    build_urls(splitted_lines, url, extensions)
}

fn build_urls(splitted_lines: str::Lines, url: &str, extensions: Vec<&str>) -> Vec<hyper::Uri> {
    debug!("building urls");
    let mut urls: Vec<hyper::Uri> = Vec::new();
    let urls_iter = splitted_lines
        .filter(|word| !word.starts_with('#') && !word.starts_with(' '))
        .map(|word| format!("{}{}", url, word));

    for url in urls_iter {
        match url.parse::<hyper::Uri>() {
            Ok(v) => {
                urls.push(v);
            }
            Err(e) => {
                error!("URI: {}", e);
            }
        }

        for extension in extensions.iter() {
            match format!("{}.{}", url, extension).parse::<hyper::Uri>() {
                Ok(v) => {
                    urls.push(v);
                }
                Err(e) => {
                    error!("URI: {}", e);
                }
            }
        }
    }

    urls
}
