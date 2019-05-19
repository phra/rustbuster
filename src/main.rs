#[macro_use]
extern crate log;

use clap::{App, Arg};

use std::{sync::mpsc::channel, thread, str::FromStr};

mod banner;
mod dirbuster;

use dirbuster::{
    utils::{Config, load_wordlist_and_build_urls},
    result_processor::{SingleScanResult, ScanResult, ResultProcessorConfig}
};

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
            Arg::with_name("no-banner")
                .help("Skips initial banner"),
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
        .arg(
            Arg::with_name("include-status-codes")
                .help("Sets the list of status codes (comma-separated) to include in the results (default: all but the ignored ones)")
                .short("s")
                .default_value("")
                .use_delimiter(true)
        )
        .arg(
            Arg::with_name("ignore-status-codes")
                .help("Sets the list of status codes (comma-separated) to ignore from the results (default: 404)")
                .short("S")
                .default_value("404")
                .use_delimiter(true)
        )
        .get_matches();

    if !matches.is_present("no-banner") {
        println!("{}{}", banner::generate(), "");
    }

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
        .filter(|e| !e.is_empty())
        .collect::<Vec<&str>>();
    let include_status_codes = matches
        .values_of("include-status-codes")
        .unwrap()
        .filter(|s| {
            if s.is_empty() { return false }
            let valid = hyper::StatusCode::from_str(s).is_ok();
            if !valid {
                error!("Ignoring invalid status code for '-s' param: {}", s);
            }
            valid
        })
        .map(|s| hyper::StatusCode::from_str(s).unwrap())
        .collect::<Vec<hyper::StatusCode>>();
    let ignore_status_codes = matches
        .values_of("ignore-status-codes")
        .unwrap()
        .filter(|s| {
            if s.is_empty() { return false }
            let valid = hyper::StatusCode::from_str(s).is_ok();
            if !valid {
                error!("Ignoring invalid status code for '-S' param: {}", s);
            }
            valid
        })
        .map(|s| hyper::StatusCode::from_str(s).unwrap())
        .collect::<Vec<hyper::StatusCode>>();

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
    debug!(
        "Including status codes: {}",
        if include_status_codes.is_empty() {
            String::from("ALL")
        } else {
            format!("{:?}", include_status_codes)
        }
    );
    debug!("Excluding status codes: {:?}", ignore_status_codes);

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
            let (tx, rx) = channel::<SingleScanResult>();
            let config = Config {
                n_threads,
                ignore_certificate,
            };
            let rp_config = ResultProcessorConfig {
                include: include_status_codes,
                ignore: ignore_status_codes
            };
            let mut result_processor = ScanResult::new(rp_config);

            thread::spawn(move || dirbuster::run(tx, urls, &config));

            while result_processor.count() != numbers_of_request {
                let msg = match rx.recv() {
                    Ok(msg) => msg,
                    Err(_err) => { error!("{:?}", _err); continue },
                };

                match &msg.error {
                    Some(e) => {
                        error!("{:?}", e);
                        if result_processor.count() == 0 || exit_on_connection_errors {
                            warn!("Check connectivity to the target");
                            break;
                        }
                    }
                    None => (),
                }

                result_processor.maybe_add_result(msg);
            }
        }
        _ => (),
    }
}
