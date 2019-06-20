#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;

use clap::{App, Arg, SubCommand};
use indicatif::{ProgressBar, ProgressStyle};
use terminal_size::{terminal_size, Height, Width};

use std::{str::FromStr, sync::mpsc::channel, thread, time::SystemTime};

mod banner;
mod dirbuster;
mod dnsbuster;
mod fuzzbuster;
mod vhostbuster;

use dirbuster::{
    result_processor::{ResultProcessorConfig, ScanResult, SingleDirScanResult},
    utils::*,
    DirConfig,
};
use dnsbuster::{
    result_processor::{DnsScanResult, SingleDnsScanResult},
    utils::*,
    DnsConfig,
};
use fuzzbuster::FuzzBuster;
use vhostbuster::{
    result_processor::{SingleVhostScanResult, VhostScanResult},
    utils::*,
    VhostConfig,
};

fn main() {
    if std::env::vars()
        .filter(|(name, _value)| name == "RUST_LOG")
        .collect::<Vec<(String, String)>>()
        .len()
        == 0
    {
        std::env::set_var("RUST_LOG", "rustbuster=warn");
    }

    pretty_env_logger::init();
    let matches = App::new("rustbuster")
        .version(crate_version!())
        .author("by phra & ps1dr3x")
        .about("DirBuster for rust")
        .after_help("EXAMPLES:
    1. Dir mode:
        rustbuster dir -u http://localhost:3000/ -w examples/wordlist -e php
    2. Dns mode:
        rustbuster dns -u google.com -w examples/wordlist
    3. Vhost mode:
        rustbuster vhost -u http://localhost:3000/ -w examples/wordlist -d test.local -x \"Hello\"
    4. Fuzz mode:
        rustbuster fuzz -u http://localhost:3000/login \\
            -X POST \\
            -H \"Content-Type: application/json\" \\
            -b '{\"user\":\"FUZZ\",\"password\":\"FUZZ\",\"csrf\":\"CSRFCSRF\"}' \\
            -w examples/wordlist \\
            -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt \\
            -s 200 \\
            --csrf-url \"http://localhost:3000/csrf\" \\
            --csrf-regex '\\{\"csrf\":\"(\\w+)\"\\}'
")
        .subcommand(set_http_args(set_common_args(SubCommand::with_name("dir")))
            .about("Directories and files enumeration mode")
            .arg(
                Arg::with_name("extensions")
                    .long("extensions")
                    .help("Sets the extensions")
                    .short("e")
                    .default_value("")
                    .use_delimiter(true),
            )
            .arg(
                Arg::with_name("append-slash")
                    .long("append-slash")
                    .help("Tries to also append / to the base request")
                    .short("f"),
            )
            .after_help("EXAMPLE:
    rustbuster dir -u http://localhost:3000/ -w examples/wordlist -e php"))
        .subcommand(set_dns_args(set_common_args(SubCommand::with_name("dns")))
            .about("A/AAAA entries enumeration mode")
            .after_help("EXAMPLE:
    rustbuster dns -u google.com -w examples/wordlist"))
        .subcommand(set_body_args(set_http_args(set_common_args(SubCommand::with_name("vhost"))))
            .about("Virtual hosts enumeration mode")
            .arg(
                Arg::with_name("domain")
                    .long("domain")
                    .help("Uses the specified domain to bruteforce")
                    .short("d")
                    .required(true)
                    .takes_value(true),
            )
            .after_help("EXAMPLE:
    rustbuster vhost -u http://localhost:3000/ -w examples/wordlist -d test.local -x \"Hello\""))
        .subcommand(set_body_args(set_http_args(set_common_args(SubCommand::with_name("fuzz"))))
            .about("Custom fuzzing enumeration mode")
                    .arg(
                Arg::with_name("csrf-url")
                    .long("csrf-url")
                    .help("Grabs the CSRF token via GET to csrf-url")
                    .requires("csrf-regex")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("csrf-regex")
                    .long("csrf-regex")
                    .help("Grabs the CSRF token applying the specified RegEx")
                    .requires("csrf-url")
                    .takes_value(true),
            )
            .arg(
                Arg::with_name("csrf-header")
                    .long("csrf-header")
                    .help("Adds the specified headers to CSRF GET request")
                    .requires("csrf-url")
                    .multiple(true)
                    .takes_value(true),
            )
            .after_help("EXAMPLE:
    rustbuster fuzz -u http://localhost:3000/login \\
        -X POST \\
        -H \"Content-Type: application/json\" \\
        -b '{\"user\":\"FUZZ\",\"password\":\"FUZZ\",\"csrf\":\"CSRFCSRF\"}' \\
        -w examples/wordlist \\
        -w /usr/share/seclists/Passwords/Common-Credentials/10-million-password-list-top-10000.txt \\
        -s 200 \\
        --csrf-url \"http://localhost:3000/csrf\" \\
        --csrf-regex '\\{\"csrf\":\"(\\w+)\"\\}'"))
        .get_matches();

    let mode = matches.subcommand_name().unwrap_or("dir");
    let submatches = match matches.subcommand_matches(mode) {
        Some(v) => v,
        None => {
            println!("{}", matches.usage());
            return;
        }
    };

    let common_args = extract_common_args(submatches);

    let all_wordlists_exist = common_args
        .wordlist_paths
        .iter()
        .map(|wordlist_path| {
            if std::fs::metadata(wordlist_path).is_err() {
                error!("Specified wordlist does not exist: {}", wordlist_path);
                return false;
            } else {
                return true;
            }
        })
        .fold(true, |acc, e| acc && e);

    if !all_wordlists_exist {
        return;
    }

    match submatches.occurrences_of("verbose") {
        0 => trace!("No verbose info"),
        1 => trace!("Some verbose info"),
        2 => trace!("Tons of verbose info"),
        3 | _ => trace!("Don't be crazy"),
    }

    println!("{}", banner::copyright());

    if !common_args.no_banner {
        println!("{}", banner::generate());
    }

    println!("{}", banner::starting_time());

    let mut current_numbers_of_request = 0;
    let start_time = SystemTime::now();

    match mode {
        "dir" => {
            let http_args = extract_http_args(submatches);
            if !url_is_valid(&http_args.url) {
                return;
            }

            let dir_args = extract_dir_args(submatches);
            let urls = build_urls(
                &common_args.wordlist_paths[0],
                &http_args.url,
                dir_args.extensions,
                dir_args.append_slash,
            );
            let total_numbers_of_request = urls.len();
            let (tx, rx) = channel::<SingleDirScanResult>();
            let config = DirConfig {
                n_threads: common_args.n_threads,
                ignore_certificate: http_args.ignore_certificate,
                http_method: http_args.http_method.to_owned(),
                http_body: http_args.http_body.to_owned(),
                user_agent: http_args.user_agent.to_owned(),
                http_headers: http_args.http_headers.clone(),
            };
            let rp_config = ResultProcessorConfig {
                include: http_args.include_status_codes,
                ignore: http_args.ignore_status_codes,
            };
            let mut result_processor = ScanResult::new(rp_config);
            let bar = if common_args.no_progress_bar {
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
                        if current_numbers_of_request == 1 || common_args.exit_on_connection_errors
                        {
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

                    if common_args.no_progress_bar {
                        println!(
                            "{}\t{}{}{}{}",
                            msg.method,
                            msg.status,
                            "\t".repeat(n_tabs),
                            msg.url,
                            extra
                        );
                    } else {
                        bar.println(format!(
                            "{}\t{}{}{}{}",
                            msg.method,
                            msg.status,
                            "\t".repeat(n_tabs),
                            msg.url,
                            extra
                        ));
                    }
                }
            }

            bar.finish();
            println!("{}", banner::ending_time());

            if !common_args.output.is_empty() {
                save_dir_results(&common_args.output, &result_processor.results);
            }
        }
        "dns" => {
            let dns_args = extract_dns_args(submatches);
            let domains = build_domains(&common_args.wordlist_paths[0], &dns_args.domain);
            let total_numbers_of_request = domains.len();
            let (tx, rx) = channel::<SingleDnsScanResult>();
            let config = DnsConfig {
                n_threads: common_args.n_threads,
            };
            let mut result_processor = DnsScanResult::new();

            let bar = if common_args.no_progress_bar {
                ProgressBar::hidden()
            } else {
                ProgressBar::new(total_numbers_of_request as u64)
            };
            bar.set_draw_delta(25);
            bar.set_style(ProgressStyle::default_bar()
                .template("{spinner} [{elapsed_precise}] {bar:40.red/white} {pos:>7}/{len:7} ETA: {eta_precise} req/s: {msg}")
                .progress_chars("#>-"));

            thread::spawn(move || dnsbuster::run(tx, domains, config));

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

                result_processor.maybe_add_result(msg.clone());
                match msg.status {
                    true => {
                        if common_args.no_progress_bar {
                            println!("OK\t{}", &msg.domain[..msg.domain.len() - 3]);
                        } else {
                            bar.println(format!("OK\t{}", &msg.domain[..msg.domain.len() - 3]));
                        }

                        match msg.extra {
                            Some(v) => {
                                for addr in v {
                                    let string_repr = addr.ip().to_string();
                                    match addr.is_ipv4() {
                                        true => {
                                            if common_args.no_progress_bar {
                                                println!("\t\tIPv4: {}", string_repr);
                                            } else {
                                                bar.println(format!("\t\tIPv4: {}", string_repr));
                                            }
                                        }
                                        false => {
                                            if common_args.no_progress_bar {
                                                println!("\t\tIPv6: {}", string_repr);
                                            } else {
                                                bar.println(format!("\t\tIPv6: {}", string_repr));
                                            }
                                        }
                                    }
                                }
                            }
                            None => (),
                        }
                    }
                    false => (),
                }
            }

            bar.finish();
            println!("{}", banner::ending_time());

            if !common_args.output.is_empty() {
                save_dns_results(&common_args.output, &result_processor.results);
            }
        }
        "vhost" => {
            let dns_args = extract_dns_args(submatches);
            let body_args = extract_body_args(submatches);
            if body_args.ignore_strings.is_empty() {
                error!("ignore_strings not specified (-x)");
                return;
            }

            let http_args = extract_http_args(submatches);
            if !url_is_valid(&http_args.url) {
                return;
            }

            let vhosts = build_vhosts(&common_args.wordlist_paths[0], &dns_args.domain);
            let total_numbers_of_request = vhosts.len();
            let (tx, rx) = channel::<SingleVhostScanResult>();
            let config = VhostConfig {
                n_threads: common_args.n_threads,
                ignore_certificate: http_args.ignore_certificate,
                http_method: http_args.http_method.to_owned(),
                user_agent: http_args.user_agent.to_owned(),
                ignore_strings: body_args.ignore_strings,
                original_url: http_args.url.to_owned(),
            };
            let mut result_processor = VhostScanResult::new();
            let bar = if common_args.no_progress_bar {
                ProgressBar::hidden()
            } else {
                ProgressBar::new(total_numbers_of_request as u64)
            };
            bar.set_draw_delta(100);
            bar.set_style(ProgressStyle::default_bar()
                .template("{spinner} [{elapsed_precise}] {bar:40.red/white} {pos:>7}/{len:7} ETA: {eta_precise} req/s: {msg}")
                .progress_chars("#>-"));

            thread::spawn(move || vhostbuster::run(tx, vhosts, config));

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
                        if current_numbers_of_request == 1 || common_args.exit_on_connection_errors
                        {
                            warn!("Check connectivity to the target");
                            break;
                        }
                    }
                    None => (),
                }

                let n_tabs = match msg.status.len() / 8 {
                    3 => 1,
                    2 => 2,
                    1 => 3,
                    0 => 4,
                    _ => 0,
                };

                if !msg.ignored {
                    result_processor.maybe_add_result(msg.clone());
                    if common_args.no_progress_bar {
                        println!(
                            "{}\t{}{}{}",
                            msg.method,
                            msg.status,
                            "\t".repeat(n_tabs),
                            msg.vhost
                        );
                    } else {
                        bar.println(format!(
                            "{}\t{}{}{}",
                            msg.method,
                            msg.status,
                            "\t".repeat(n_tabs),
                            msg.vhost
                        ));
                    }
                }
            }

            bar.finish();
            println!("{}", banner::ending_time());

            if !common_args.output.is_empty() {
                save_vhost_results(&common_args.output, &result_processor.results);
            }
        }
        "fuzz" => {
            let http_args = extract_http_args(submatches);
            if !url_is_valid(&http_args.url) {
                return;
            }

            let body_args = extract_body_args(submatches);
            let csrf_url = match submatches.value_of("csrf-url") {
                Some(v) => Some(v.to_owned()),
                None => None,
            };
            let csrf_regex = match submatches.value_of("csrf-regex") {
                Some(v) => Some(v.to_owned()),
                None => None,
            };
            let csrf_headers: Option<Vec<(String, String)>> =
                if submatches.is_present("csrf-header") {
                    Some(
                        submatches
                            .values_of("csrf-header")
                            .unwrap()
                            .map(|h| fuzzbuster::utils::split_http_headers(h))
                            .collect(),
                    )
                } else {
                    None
                };
            let fuzzbuster = FuzzBuster {
                n_threads: common_args.n_threads,
                ignore_certificate: http_args.ignore_certificate,
                http_method: http_args.http_method.to_owned(),
                http_body: http_args.http_body.to_owned(),
                user_agent: http_args.user_agent.to_owned(),
                http_headers: http_args.http_headers,
                wordlist_paths: common_args.wordlist_paths,
                url: http_args.url.to_owned(),
                ignore_status_codes: http_args.ignore_status_codes,
                include_status_codes: http_args.include_status_codes,
                no_progress_bar: common_args.no_progress_bar,
                exit_on_connection_errors: common_args.exit_on_connection_errors,
                output: common_args.output.to_owned(),
                include_body: body_args.include_strings,
                ignore_body: body_args.ignore_strings,
                csrf_url,
                csrf_regex,
                csrf_headers,
            };

            debug!("FuzzBuster {:#?}", fuzzbuster);

            fuzzbuster.run();
        }
        _ => (),
    }
}

fn set_common_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
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
        Arg::with_name("wordlist")
            .long("wordlist")
            .help("Sets the wordlist")
            .short("w")
            .takes_value(true)
            .multiple(true)
            .use_delimiter(true)
            .required(true),
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
        Arg::with_name("exit-on-error")
            .long("exit-on-error")
            .help("Exits on connection errors")
            .short("K"),
    )
    .arg(
        Arg::with_name("output")
            .long("output")
            .help("Saves the results in the specified file")
            .short("o")
            .default_value("")
            .takes_value(true),
    )
    .arg(
        Arg::with_name("no-progress-bar")
            .long("no-progress-bar")
            .help("Disables the progress bar"),
    )
}

fn set_http_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name("include-status-codes")
            .long("include-status-codes")
            .help("Sets the list of status codes to include")
            .short("s")
            .default_value("")
            .use_delimiter(true),
    )
    .arg(
        Arg::with_name("ignore-status-codes")
            .long("ignore-status-codes")
            .help("Sets the list of status codes to ignore")
            .short("S")
            .default_value("404")
            .use_delimiter(true),
    )
    .arg(
        Arg::with_name("user-agent")
            .long("user-agent")
            .help("Uses the specified User-Agent")
            .short("a")
            .default_value("rustbuster")
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
        Arg::with_name("http-method")
            .long("http-method")
            .help("Uses the specified HTTP method")
            .short("X")
            .default_value("GET")
            .takes_value(true),
    )
    .arg(
        Arg::with_name("http-body")
            .long("http-body")
            .help("Uses the specified HTTP method")
            .short("b")
            .default_value("")
            .takes_value(true),
    )
    .arg(
        Arg::with_name("http-header")
            .long("http-header")
            .help("Appends the specified HTTP header")
            .short("H")
            .multiple(true)
            .takes_value(true),
    )
    .arg(
        Arg::with_name("url")
            .long("url")
            .alias("domain")
            .help("Sets the target URL")
            .short("u")
            .takes_value(true)
            .required(true),
    )
}

fn set_dns_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name("domain")
            .long("domain")
            .help("Uses the specified domain")
            .short("d")
            .required(true)
            .takes_value(true),
    )
}

fn set_body_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name("ignore-string")
            .long("ignore-string")
            .help("Ignores results with specified string in the HTTP Body")
            .short("x")
            .multiple(true)
            .takes_value(true),
    )
    .arg(
        Arg::with_name("include-string")
            .long("include-string")
            .help("Includes results with specified string in the HTTP body")
            .short("i")
            .multiple(true)
            .conflicts_with("ignore-string")
            .takes_value(true),
    )
}

struct CommonArgs {
    wordlist_paths: Vec<String>,
    no_banner: bool,
    no_progress_bar: bool,
    exit_on_connection_errors: bool,
    n_threads: usize,
    output: String,
}

struct DNSArgs {
    domain: String,
}

struct HTTPArgs {
    user_agent: String,
    http_method: String,
    http_body: String,
    url: String,
    ignore_certificate: bool,
    http_headers: Vec<(String, String)>,
    include_status_codes: Vec<String>,
    ignore_status_codes: Vec<String>,
}

struct BodyArgs {
    include_strings: Vec<String>,
    ignore_strings: Vec<String>,
}

struct DirArgs {
    append_slash: bool,
    extensions: Vec<String>,
}

fn extract_common_args<'a>(submatches: &clap::ArgMatches<'a>) -> CommonArgs {
    let wordlist_paths = submatches
        .values_of("wordlist")
        .unwrap()
        .map(|w| w.to_owned())
        .collect::<Vec<String>>();
    let mut no_banner = submatches.is_present("no-banner");
    let mut no_progress_bar = submatches.is_present("no-progress-bar");
    let exit_on_connection_errors = submatches.is_present("exit-on-error");
    let n_threads = submatches
        .value_of("threads")
        .unwrap()
        .parse::<usize>()
        .expect("threads is a number");

    let output = submatches.value_of("output").unwrap();

    if let Some((Width(w), Height(h))) = terminal_size() {
        if w < 122 {
            no_banner = true;
        }

        if w < 104 {
            warn!("Your terminal is {} cols wide and {} lines tall", w, h);
            warn!("Disabling progress bar, minimum cols: 104");
            no_progress_bar = true;
        }
    } else {
        warn!("Unable to get terminal size");
        no_banner = true;
        no_progress_bar = true;
    }

    CommonArgs {
        wordlist_paths,
        no_banner,
        no_progress_bar,
        exit_on_connection_errors,
        n_threads,
        output: output.to_owned(),
    }
}

fn extract_http_args<'a>(submatches: &clap::ArgMatches<'a>) -> HTTPArgs {
    let user_agent = submatches.value_of("user-agent").unwrap();
    let http_method = submatches.value_of("http-method").unwrap();
    let http_body = submatches.value_of("http-body").unwrap();
    let url = submatches.value_of("url").unwrap();
    let ignore_certificate = submatches.is_present("ignore-certificate");
    let http_headers: Vec<(String, String)> = if submatches.is_present("http-header") {
        submatches
            .values_of("http-header")
            .unwrap()
            .map(|h| fuzzbuster::utils::split_http_headers(h))
            .collect()
    } else {
        Vec::new()
    };
    let include_status_codes = submatches
        .values_of("include-status-codes")
        .unwrap()
        .filter(|s| {
            if s.is_empty() {
                return false;
            }
            let valid = hyper::StatusCode::from_str(s).is_ok();
            if !valid {
                warn!("Ignoring invalid status code for '-s' param: {}", s);
            }
            valid
        })
        .map(|s| s.to_string())
        .collect::<Vec<String>>();
    let ignore_status_codes = submatches
        .values_of("ignore-status-codes")
        .unwrap()
        .filter(|s| {
            if s.is_empty() {
                return false;
            }
            let valid = hyper::StatusCode::from_str(s).is_ok();
            if !valid {
                warn!("Ignoring invalid status code for '-S' param: {}", s);
            }
            valid
        })
        .map(|s| s.to_string())
        .collect::<Vec<String>>();

    HTTPArgs {
        user_agent: user_agent.to_owned(),
        http_method: http_method.to_owned(),
        http_body: http_body.to_owned(),
        url: url.to_owned(),
        ignore_certificate,
        http_headers,
        include_status_codes,
        ignore_status_codes,
    }
}

fn extract_dns_args<'a>(submatches: &clap::ArgMatches<'a>) -> DNSArgs {
    let domain = submatches.value_of("domain").unwrap_or("");

    DNSArgs {
        domain: domain.to_owned(),
    }
}

fn extract_body_args<'a>(submatches: &clap::ArgMatches<'a>) -> BodyArgs {
    let ignore_strings: Vec<String> = if submatches.is_present("ignore-string") {
        submatches
            .values_of("ignore-string")
            .unwrap()
            .map(|h| h.to_owned())
            .collect()
    } else {
        Vec::new()
    };
    let include_strings: Vec<String> = if submatches.is_present("include-string") {
        submatches
            .values_of("include-string")
            .unwrap()
            .map(|h| h.to_owned())
            .collect()
    } else {
        Vec::new()
    };

    BodyArgs {
        include_strings,
        ignore_strings,
    }
}

fn extract_dir_args<'a>(submatches: &clap::ArgMatches<'a>) -> DirArgs {
    let append_slash = submatches.is_present("append-slash");
    let extensions = submatches
        .values_of("extensions")
        .unwrap()
        .filter(|e| !e.is_empty())
        .map(|s| s.to_owned())
        .collect::<Vec<String>>();
    DirArgs {
        append_slash,
        extensions,
    }
}

fn url_is_valid(url: &str) -> bool {
    match url.parse::<hyper::Uri>() {
        Err(e) => {
            error!(
                "Invalid URL: {}, consider adding a protocol like http:// or https://",
                e
            );
            return false;
        }
        Ok(v) => {
            match v.scheme_part() {
                Some(s) => {
                    if s != "http" && s != "https" {
                        error!("Invalid URL: invalid protocol, only http:// or https:// are supported");
                        return false;
                    } else {
                        return true;
                    }
                }
                None => {
                    error!("Invalid URL: missing protocol, consider adding http:// or https://");
                    return false;
                }
            }
        }
    }
}
