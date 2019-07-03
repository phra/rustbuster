#[macro_use]
extern crate log;
#[macro_use]
extern crate clap;

use clap::{App, SubCommand};
use indicatif::{ProgressBar, ProgressStyle};
use std::{sync::mpsc::channel, thread, time::SystemTime};

mod args;
mod banner;
mod dirbuster;
mod dnsbuster;
mod fuzzbuster;
mod tildebuster;
mod vhostbuster;

use args::*;
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
use tildebuster::TildeBuster;
use vhostbuster::{
    result_processor::{SingleVhostScanResult, VhostScanResult},
    utils::*,
    VhostConfig,
};

use fuzzbuster::FuzzBuster;

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
        .subcommand(set_wordlist_args(set_dir_args(set_http_args(set_common_args(SubCommand::with_name("dir")))))
            .about("Directories and files enumeration mode")
            .after_help("EXAMPLE:
    rustbuster dir -u http://localhost:3000/ -w examples/wordlist -e php"))
        .subcommand(set_wordlist_args(set_dns_args(set_common_args(SubCommand::with_name("dns"))))
            .about("A/AAAA entries enumeration mode")
            .after_help("EXAMPLE:
    rustbuster dns -u google.com -w examples/wordlist"))
        .subcommand(set_wordlist_args(set_vhost_args(set_http_args(set_common_args(SubCommand::with_name("vhost")))))
            .about("Virtual hosts enumeration mode")
            .after_help("EXAMPLE:
    rustbuster vhost -u http://localhost:3000/ -w examples/wordlist -d test.local -x \"Hello\""))
        .subcommand(set_tilde_args(set_http_args(set_common_args(SubCommand::with_name("tilde"))))
            .about("IIS 8.3 shortname enumeration mode")
            .after_help("EXAMPLE:
    rustbuster tilde -u http://localhost:3000/ -e aspx -X OPTIONS"))
        .subcommand(set_wordlist_args(set_fuzz_args(set_body_args(set_http_args(set_common_args(SubCommand::with_name("fuzz"))))))
            .about("Custom fuzzing enumeration mode")
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
            let wordlist_args = match extract_wordlist_args(submatches) {
                Err(_) => return,
                Ok(v) => v,
            };

            let http_args = extract_http_args(submatches);
            if !url_is_valid(&http_args.url) {
                return;
            }

            let dir_args = extract_dir_args(submatches);
            let urls = build_urls(
                &wordlist_args.wordlist_paths[0],
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
            let wordlist_args = match extract_wordlist_args(submatches) {
                Err(_) => return,
                Ok(v) => v,
            };

            let dns_args = extract_dns_args(submatches);
            let domains = build_domains(&wordlist_args.wordlist_paths[0], &dns_args.domain);
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
            let http_args = extract_http_args(submatches);
            if !url_is_valid(&http_args.url) {
                return;
            }

            let wordlist_args = match extract_wordlist_args(submatches) {
                Err(_) => return,
                Ok(v) => v,
            };

            let vhosts = build_vhosts(&wordlist_args.wordlist_paths[0], &dns_args.domain);
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

            let wordlist_args = match extract_wordlist_args(submatches) {
                Err(_) => return,
                Ok(v) => v,
            };

            let body_args = extract_body_args(submatches);
            let fuzz_args = extract_fuzz_args(submatches);

            let fuzzbuster = FuzzBuster {
                n_threads: common_args.n_threads,
                ignore_certificate: http_args.ignore_certificate,
                http_method: http_args.http_method.to_owned(),
                http_body: http_args.http_body.to_owned(),
                user_agent: http_args.user_agent.to_owned(),
                http_headers: http_args.http_headers,
                wordlist_paths: wordlist_args.wordlist_paths,
                url: http_args.url.to_owned(),
                ignore_status_codes: http_args.ignore_status_codes,
                include_status_codes: http_args.include_status_codes,
                no_progress_bar: common_args.no_progress_bar,
                exit_on_connection_errors: common_args.exit_on_connection_errors,
                output: common_args.output.to_owned(),
                include_body: body_args.include_strings,
                ignore_body: body_args.ignore_strings,
                csrf_url: fuzz_args.csrf_url,
                csrf_regex: fuzz_args.csrf_regex,
                csrf_headers: fuzz_args.csrf_headers,
            };

            debug!("FuzzBuster {:#?}", fuzzbuster);

            fuzzbuster.run();
        }
        "tilde" => {
            let http_args = extract_http_args(submatches);
            if !url_is_valid(&http_args.url) {
                return;
            }

            let tilde_args = extract_tilde_args(submatches);
            let tildebuster = TildeBuster {
                n_threads: common_args.n_threads,
                ignore_certificate: http_args.ignore_certificate,
                http_method: http_args.http_method.to_owned(),
                http_body: http_args.http_body.to_owned(),
                user_agent: http_args.user_agent.to_owned(),
                http_headers: http_args.http_headers,
                url: http_args.url.to_owned(),
                no_progress_bar: common_args.no_progress_bar,
                exit_on_connection_errors: common_args.exit_on_connection_errors,
                output: common_args.output.to_owned(),
                extension: tilde_args.extension,
            };

            debug!("TildeBuster {:#?}", tildebuster);

            tildebuster.run();
        }
        _ => (),
    }
}
