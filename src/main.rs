#[macro_use]
extern crate log;

use clap::{App, Arg};
use indicatif::{ProgressBar, ProgressStyle};

use std::{
    str::FromStr, sync::mpsc::channel,
    time::SystemTime, thread
};

mod banner;
mod dirbuster;
mod dnsbuster;

use dirbuster::{
    result_processor::{ResultProcessorConfig, ScanResult, SingleDirScanResult},
    utils::*,
};
use dnsbuster::SingleDnsScanResult;

fn main() {
    pretty_env_logger::init();
    let matches = App::new("rustbuster")
        .version("0.1")
        .author("by phra & ps1dr3x")
        .about("DirBuster for rust")
        .arg(
            Arg::with_name("verbose")
                .long("verbose")
                .short("v")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .arg(
            Arg::with_name("no-banner")
                .long("no-banner")
                .help("Skips initial banner"),
        )
        .arg(
            Arg::with_name("url")
                .long("url")
                .help("Sets the target URL")
                .short("u")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("wordlist")
                .long("wordlist")
                .help("Sets the wordlist")
                .short("w")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::with_name("extensions")
                .long("extensions")
                .help("Sets the extensions")
                .short("e")
                .default_value("")
                .use_delimiter(true),
        )
        .arg(
            Arg::with_name("mode")
                .long("mode")
                .help("Sets the mode of operation (dir, dns, fuzz)")
                .short("m")
                .takes_value(true)
                .default_value("dir"),
        )
        .arg(
            Arg::with_name("threads")
                .long("threads")
                .alias("workers")
                .help("Sets the amount of concurrent requests")
                .short("t")
                .default_value("10")
                .takes_value(true),
        )
        .arg(
            Arg::with_name("ignore-certificate")
                .long("ignore-certificate")
                .alias("no-check-certificate")
                .help("Disables TLS certificate validation")
                .short("k"),
        )
        .arg(
            Arg::with_name("exit-on-error")
                .long("exit-on-error")
                .help("Exits on connection errors")
                .short("K"),
        )
        .arg(
            Arg::with_name("include-status-codes")
                .long("include-status-codes")
                .help("Sets the list of status codes to include")
                .short("s")
                .default_value("")
                .use_delimiter(true)
        )
        .arg(
            Arg::with_name("ignore-status-codes")
                .long("ignore-status-codes")
                .help("Sets the list of status codes to ignore")
                .short("S")
                .default_value("404")
                .use_delimiter(true)
        )
        .arg(
            Arg::with_name("output")
                .long("output")
                .help("Saves the results in the specified file")
                .short("o")
                .default_value("")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("no-progress-bar")
                .long("no-progress-bar")
                .help("Disables the progress bar")
        )
        .arg(
            Arg::with_name("http-method")
                .long("http-method")
                .help("Uses the specified HTTP method")
                .short("X")
                .default_value("GET")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("http-body")
                .long("http-body")
                .help("Uses the specified HTTP method")
                .short("b")
                .default_value("")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("http-header")
                .long("http-header")
                .help("Appends the specified HTTP header")
                .short("H")
                .multiple(true)
                .takes_value(true)
        )
        .arg(
            Arg::with_name("user-agent")
                .long("user-agent")
                .help("Uses the specified User-Agent")
                .short("a")
                .default_value("rustbuster")
                .takes_value(true)
        )
        .arg(
            Arg::with_name("append-slash")
                .long("append-slash")
                .help("Tries to also append / to the base request")
                .short("f")
        )
        .get_matches();

    let append_slash = matches.is_present("append-slash");
    let user_agent = matches.value_of("user-agent").unwrap();
    let http_method = matches.value_of("http-method").unwrap();
    let http_body = matches.value_of("http-body").unwrap();
    let url = matches.value_of("url").unwrap();
    let wordlist_path = matches.value_of("wordlist").unwrap();
    let mode = matches.value_of("mode").unwrap();
    let ignore_certificate = matches.is_present("ignore-certificate");
    let no_progress_bar = matches.is_present("no-progress-bar");
    let exit_on_connection_errors = matches.is_present("exit-on-error");
    let http_headers: Vec<(String, String)> = if matches.is_present("http-header") {
        matches.values_of("http-header").unwrap().map(|h| dirbuster::utils::split_http_headers(h)).collect()
    } else {
        Vec::new()
    };
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
            if s.is_empty() {
                return false;
            }
            let valid = hyper::StatusCode::from_str(s).is_ok();
            if !valid {
                error!("Ignoring invalid status code for '-s' param: {}", s);
            }
            valid
        })
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    let ignore_status_codes = matches
        .values_of("ignore-status-codes")
        .unwrap()
        .filter(|s| {
            if s.is_empty() {
                return false;
            }
            let valid = hyper::StatusCode::from_str(s).is_ok();
            if !valid {
                error!("Ignoring invalid status code for '-S' param: {}", s);
            }
            valid
        })
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    let output = matches.value_of("output").unwrap();

    match url.parse::<hyper::Uri>() {
        Err(e) => {
            error!("Invalid URL: {}", e);
            return;
        }
        Ok(_) => (),
    }

    debug!("Using mode: {:?}", mode);
    debug!("Using url: {:?}", url);
    debug!("Using wordlist: {:?}", wordlist_path);
    debug!("Using mode: {:?}", mode);
    debug!("Using extensions: {:?}", extensions);
    debug!("Using concurrent requests: {:?}", n_threads);
    debug!("Using certificate validation: {:?}", !ignore_certificate);
    debug!("Using HTTP headers: {:?}", http_headers);
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

    if !matches.is_present("no-banner") {
        println!("{}", banner::generate());
        println!(
            "{}",
            banner::configuration(
                mode,
                url,
                matches.value_of("threads").unwrap(),
                wordlist_path
            )
        );
        println!("{}", banner::starting_time());
    }

    let mut current_numbers_of_request = 0;
    let start_time = SystemTime::now();

    match mode {
        "dir" => {
            let urls = build_urls(wordlist_path, url, extensions, append_slash);
            let total_numbers_of_request = urls.len();
            let (tx, rx) = channel::<SingleDirScanResult>();
            let config = Config {
                n_threads,
                ignore_certificate,
                http_method: http_method.to_owned(),
                http_body: http_body.to_owned(),
                user_agent: user_agent.to_owned(),
                http_headers,
            };
            let rp_config = ResultProcessorConfig {
                include: include_status_codes,
                ignore: ignore_status_codes,
            };
            let mut result_processor = ScanResult::new(rp_config);
            let bar = if no_progress_bar {
                ProgressBar::hidden()
            } else {
                ProgressBar::new(total_numbers_of_request as u64)
            };
            bar.set_draw_delta(100);
            bar.set_style(ProgressStyle::default_bar()
                .template("{spinner} [{elapsed_precise}] {bar:40.red/white} {pos:>7}/{len:7} ETA: {eta_precise} req/s: {msg}")
                .progress_chars("#>-"));

            thread::spawn(move || dirbuster::run(tx, urls, config));

            while current_numbers_of_request != total_numbers_of_request {
                current_numbers_of_request = current_numbers_of_request + 1;
                bar.inc(1);
                let seconds_from_start = start_time.elapsed().unwrap().as_millis() / 1000;
                if seconds_from_start != 0 {
                    bar.set_message(
                        &(current_numbers_of_request as u64 / seconds_from_start as u64)
                            .to_string(),
                    );
                } else {
                    bar.set_message("warming up...")
                }

                let msg = match rx.recv() {
                    Ok(msg) => msg,
                    Err(_err) => {
                        error!("{:?}", _err);
                        break;
                    }
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

                let was_added = result_processor.maybe_add_result(msg.clone());
                if was_added {
                    let mut extra = msg.extra.unwrap_or("".to_owned());

                    if !extra.is_empty() {
                        extra = format!("\n\t\t\t\t\t\t=> {}", extra)
                    }

                    let n_tabs = match msg.status.len() / 8 {
                        3 => 1,
                        2 => 2,
                        1 => 3,
                        0 => 4,
                        _ => 0,
                    };

                    bar.println(format!("{}\t{}{}{}{}", msg.method, msg.status, "\t".repeat(n_tabs), msg.url, extra));
                }
            }

            bar.finish();
            if !matches.is_present("no-banner") {
                println!("{}", banner::ending_time());
            }

            if !output.is_empty() {
                save_results(output, &result_processor.results);
            }
        }
        "dns" => {
            let domains = build_domains(wordlist_path, url);
            let total_numbers_of_request = domains.len();
            let (tx, rx) = channel::<SingleDnsScanResult>();
            let config = dnsbuster::Config { n_threads };

            let bar = if no_progress_bar {
                ProgressBar::hidden()
            } else {
                ProgressBar::new(total_numbers_of_request as u64)
            };
            bar.set_draw_delta(100);
            bar.set_style(ProgressStyle::default_bar()
                .template("{spinner} [{elapsed_precise}] {bar:40.red/white} {pos:>7}/{len:7} ETA: {eta_precise} req/s: {msg}")
                .progress_chars("#>-"));
            
            thread::spawn(move || dnsbuster::run(tx, domains, config));

            while current_numbers_of_request != total_numbers_of_request {
                current_numbers_of_request = current_numbers_of_request + 1;
                bar.inc(1);

                let msg = match rx.recv() {
                    Ok(msg) => msg,
                    Err(_err) => {
                        error!("{:?}", _err);
                        break;
                    }
                };

                println!("msg: {:?}", msg);
            }
        }
        _ => (),
    }
}
