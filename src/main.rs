#[macro_use]
extern crate log;

use clap::{App, Arg};

use std::{fs, str, sync::mpsc::channel, thread};

mod dirbuster;

use dirbuster::{utils::{Target, Config}};

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
        .arg(
            Arg::with_name("threads")
                .alias("workers")
                .help("Sets the amount of concurrent requests")
                .short("t")
                .default_value("10")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ignore-certificate")
                .alias("no-check-certificate")
                .help("Disables TLS certificate validation")
                .short("k"),
        )
        .arg(
            Arg::with_name("exit-on-error")
                .help("Exits on connection errors")
                .short("K"),
        )
        .get_matches();

    let url = matches.value_of("url").unwrap();
    let wordlist_path = matches.value_of("wordlist").unwrap();
    let mode = matches.value_of("mode").unwrap();
    let ignore_certificate = matches.is_present("ignore-certificate");
    let exit_on_connection_errors = matches.is_present("exit-on-error");
    let n_threads = matches
        .value_of("threads")
        .unwrap()
        .parse::<usize>()
        .expect("threads is a number");
    let extensions = matches
        .values_of("extensions")
        .unwrap()
        .filter(|e| e.len() != 0)
        .collect::<Vec<&str>>();

    debug!("Using mode: {:?}", mode);
    debug!("Using url: {:?}", url);
    debug!("Using wordlist: {:?}", wordlist_path);
    debug!("Using mode: {:?}", mode);
    debug!("Using extensions: {:?}", extensions);
    debug!("Using concurrent requests: {:?}", n_threads);
    debug!("Using certificate validation: {:?}", !ignore_certificate);
    debug!(
        "Using exit on connection errors: {:?}",
        exit_on_connection_errors
    );

    // Vary the output based on how many times the user used the "verbose" flag
    // (i.e. 'myprog -v -v -v' or 'myprog -vvv' vs 'myprog -v'
    match matches.occurrences_of("verbose") {
        0 => trace!("No verbose info"),
        1 => trace!("Some verbose info"),
        2 => trace!("Tons of verbose info"),
        3 | _ => trace!("Don't be crazy"),
    }

    match mode {
        "dir" => {
            let urls = load_wordlist_and_build_urls(wordlist_path, url, extensions);
            let numbers_of_request = urls.len();
            let (tx, rx) = channel::<Target>();
            let mut results: Vec<Target> = Vec::new();
            let config = Config {
                n_threads,
                ignore_certificate,
            };

            thread::spawn(move || dirbuster::run(tx, urls, &config));

            while results.len() != numbers_of_request {
                let msg = match rx.recv() {
                    Ok(msg) => msg,
                    Err(_err) => { error!("{:?}", _err); continue },
                };

                match &msg.error {
                    Some(e) => {
                        error!("{:?}", e);
                        if results.len() == 0 || exit_on_connection_errors {
                            warn!("Check connectivity to the target");
                            break;
                        }
                    }
                    None => (),
                }

                results.push(msg);
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
