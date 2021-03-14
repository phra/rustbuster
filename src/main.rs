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
    DirBuster,
};
use dnsbuster::{
    result_processor::{DnsScanResult, SingleDnsScanResult},
    utils::*,
    DnsBuster,
};
use tildebuster::TildeBuster;
use vhostbuster::{
    result_processor::{SingleVhostScanResult, VhostScanResult},
    utils::*,
    VhostBuster,
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
        rustbuster dns -d google.com -w examples/wordlist
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
    5. Tilde mode:
        rustbuster tilde -u http://localhost:3000/ -e aspx -X OPTIONS
")
        .subcommand(set_wordlist_args(set_dir_args(set_http_args(set_common_args(SubCommand::with_name("dir")))))
            .about("Directories and files enumeration mode")
            .after_help("EXAMPLE:
    rustbuster dir -u http://localhost:3000/ -w examples/wordlist -e php"))
        .subcommand(set_wordlist_args(set_dns_args(set_common_args(SubCommand::with_name("dns"))))
            .about("A/AAAA entries enumeration mode")
            .after_help("EXAMPLE:
    rustbuster dns -d google.com -w examples/wordlist"))
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

            let dirbuster = DirBuster {
                    n_threads: common_args.n_threads,
                    ignore_certificate: http_args.ignore_certificate,
                    http_method: http_args.http_method.to_owned(),
                    http_body: http_args.http_body.to_owned(),
                    user_agent: http_args.user_agent.to_owned(),
                    http_headers: http_args.http_headers.clone(),
                    url: http_args.url.to_owned(),
                    wordlist_path: wordlist_args.wordlist_paths[0].to_owned(),
                    extensions: dir_args.extensions.clone(),
                    append_slash: dir_args.append_slash,
                    include_status_codes: http_args.include_status_codes.clone(),
                    ignore_status_codes: http_args.ignore_status_codes.clone(),
                    no_progress_bar: common_args.no_progress_bar,
                    exit_on_connection_errors: common_args.exit_on_connection_errors,
                    output: common_args.output.clone(),
            };

            dirbuster.run();
        }
        "dns" => {
            let wordlist_args = match extract_wordlist_args(submatches) {
                Err(_) => return,
                Ok(v) => v,
            };
            
            let dns_args = extract_dns_args(submatches);
            let dnsbuster = DnsBuster {
                n_threads: common_args.n_threads,
                no_progress_bar: common_args.no_progress_bar,
                output: common_args.output,
                domain: dns_args.domain,
                wordlist_path: wordlist_args.wordlist_paths[0].to_owned(),
            };

            dnsbuster.run();
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
            let vhostbuster = VhostBuster {
                n_threads: common_args.n_threads,
                ignore_certificate: http_args.ignore_certificate,
                http_method: http_args.http_method.to_owned(),
                user_agent: http_args.user_agent.to_owned(),
                ignore_strings: body_args.ignore_strings,
                original_url: http_args.url.to_owned(),
                wordlist_path: wordlist_args.wordlist_paths[0].to_owned(),
                domain: dns_args.domain.to_owned(),
                no_progress_bar: common_args.no_progress_bar,
                exit_on_connection_errors: common_args.exit_on_connection_errors,
                output: common_args.output.to_owned(),
            };

            vhostbuster.run();

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
