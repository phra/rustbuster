use clap::{App, Arg};
use terminal_size::{terminal_size, Height, Width};

pub struct CommonArgs {
    pub wordlist_paths: Vec<String>,
    pub no_banner: bool,
    pub no_progress_bar: bool,
    pub exit_on_connection_errors: bool,
    pub n_threads: usize,
    pub output: String,
}

pub struct DNSArgs {
    pub domain: String,
}

pub struct HTTPArgs {
    pub user_agent: String,
    pub http_method: String,
    pub http_body: String,
    pub url: String,
    pub ignore_certificate: bool,
    pub http_headers: Vec<(String, String)>,
    pub include_status_codes: Vec<String>,
    pub ignore_status_codes: Vec<String>,
}

pub struct BodyArgs {
    pub include_strings: Vec<String>,
    pub ignore_strings: Vec<String>,
}

pub struct DirArgs {
    pub append_slash: bool,
    pub extensions: Vec<String>,
}

pub struct FuzzArgs {
    pub csrf_url: Option<String>,
    pub csrf_regex: Option<String>,
    pub csrf_headers: Option<Vec<(String, String)>>,
}

pub fn set_common_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
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

pub fn set_http_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
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
            .help("Uses the specified HTTP body")
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

pub fn set_body_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name("ignore-string")
            .long("ignore-string")
            .help("Ignores results with specified string in the HTTP body")
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

pub fn set_dir_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
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
}

pub fn set_dns_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name("domain")
            .long("domain")
            .help("Uses the specified domain")
            .short("d")
            .required(true)
            .takes_value(true),
    )
}

pub fn set_vhost_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
        Arg::with_name("domain")
            .long("domain")
            .help("Uses the specified domain to bruteforce")
            .short("d")
            .required(true)
            .takes_value(true),
    )
    .arg(
        Arg::with_name("ignore-string")
            .long("ignore-string")
            .help("Ignores results with specified string in the HTTP body")
            .short("x")
            .required(true)
            .multiple(true)
            .takes_value(true),
    )
}

pub fn set_fuzz_args<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app.arg(
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
}

pub fn extract_common_args<'a>(submatches: &clap::ArgMatches<'a>) -> CommonArgs {
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

pub fn extract_http_args<'a>(submatches: &clap::ArgMatches<'a>) -> HTTPArgs {
    let user_agent = submatches.value_of("user-agent").unwrap();
    let http_method = submatches.value_of("http-method").unwrap();
    let http_body = submatches.value_of("http-body").unwrap();
    let url = submatches.value_of("url").unwrap();
    let ignore_certificate = submatches.is_present("ignore-certificate");
    let http_headers: Vec<(String, String)> = if submatches.is_present("http-header") {
        submatches
            .values_of("http-header")
            .unwrap()
            .map(|h| crate::fuzzbuster::utils::split_http_headers(h))
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
            s.parse::<hyper::StatusCode>().is_ok()
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
            s.parse::<hyper::StatusCode>().is_ok()
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

pub fn extract_dns_args<'a>(submatches: &clap::ArgMatches<'a>) -> DNSArgs {
    let domain = submatches.value_of("domain").unwrap_or("");

    DNSArgs {
        domain: domain.to_owned(),
    }
}

pub fn extract_body_args<'a>(submatches: &clap::ArgMatches<'a>) -> BodyArgs {
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

pub fn extract_dir_args<'a>(submatches: &clap::ArgMatches<'a>) -> DirArgs {
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

pub fn extract_fuzz_args<'a>(submatches: &clap::ArgMatches<'a>) -> FuzzArgs {
    let csrf_url = match submatches.value_of("csrf-url") {
        Some(v) => Some(v.to_owned()),
        None => None,
    };
    let csrf_regex = match submatches.value_of("csrf-regex") {
        Some(v) => Some(v.to_owned()),
        None => None,
    };
    let csrf_headers: Option<Vec<(String, String)>> = if submatches.is_present("csrf-header") {
        Some(
            submatches
                .values_of("csrf-header")
                .unwrap()
                .map(|h| crate::fuzzbuster::utils::split_http_headers(h))
                .collect(),
        )
    } else {
        None
    };
    FuzzArgs {
        csrf_url,
        csrf_regex,
        csrf_headers,
    }
}

pub fn url_is_valid(url: &str) -> bool {
    match url.parse::<hyper::Uri>() {
        Err(e) => {
            error!(
                "Invalid URL: {}, consider adding a protocol like http:// or https://",
                e
            );
            return false;
        }
        Ok(v) => match v.scheme_part() {
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
        },
    }
}
