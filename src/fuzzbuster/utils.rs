use std::{fs, fs::File, io::Write, path::Path, str };
use itertools::Itertools;

use super::result_processor::SingleFuzzScanResult;

#[derive(Debug, Clone)]
pub struct FuzzConfig {
    pub n_threads: usize,
    pub ignore_certificate: bool,
    pub http_method: String,
    pub http_body: String,
    pub user_agent: String,
    pub http_headers: Vec<(String, String)>,
    pub wordlist_paths: Vec<String>,
    pub url: String,
}

pub struct FuzzRequest {
    pub uri: hyper::Uri,
    pub method: String,
    pub headers: Vec<(String, String)>,
    pub body: String,
}

fn is_url_case(config: &FuzzConfig) -> bool {
    config.url.contains("FUZZ")
}

fn is_header_case(config: &FuzzConfig) -> bool {
    let sum = config.http_headers.iter().map(|(header, value)| -> usize {
        if header.contains("FUZZ") || value.contains("FUZZ") {
            return 1
        } else {
            return 0
        }
    }).sum::<usize>();

    sum > 0
}

fn is_body_case(config: &FuzzConfig) -> bool {
    config.http_body.contains("FUZZ")
}

pub fn build_requests(
    config: &FuzzConfig,
) -> Vec<FuzzRequest> {
    debug!("building requests");
    let mut requests: Vec<FuzzRequest> = Vec::new();
    let wordlists_iter = config.wordlist_paths.iter()
        .map(|path| {
            fs::read_to_string(path).expect("Something went wrong reading the wordlist file")
        })
        .map(|wordlist| {
            wordlist
                .lines()
                .filter(|word| !word.starts_with('#') && !word.starts_with(' '))
        })
        .multi_cartesian_product();

    let case = if is_url_case(&config) {
        "url"
    } else if is_header_case(&config) {
        "header"
    } else if is_body_case(&config) {
        "body"
    } else { error!("No injection points"); "ERROR" };

    match case {
        "url" => {
            for words in wordlists_iter {
                let mut _url = config.url;

                for word in words {
                    _url = _url.replacen("FUZZ", word, 1);
                }

                match _url.parse::<hyper::Uri>() {
                    Ok(v) => {
                        requests.push(FuzzRequest {
                            body: config.http_body,
                            uri: v,
                            method: config.http_method,
                            headers: config.http_headers,
                        });
                    }
                    Err(e) => {
                        trace!("URI: {}", e);
                    }
                }
            }
        },
        "header" => (),
        "body" => (),
        _ => (),
    }

    requests
}

pub fn save_fuzz_results(path: &str, results: &Vec<SingleFuzzScanResult>) {
    let json_string = serde_json::to_string(&results).unwrap();

    let mut file = match File::create(Path::new(path)) {
        Ok(f) => f,
        Err(e) => {
            error!("Error while creating file: {}\n{}", path, e);
            return;
        }
    };

    match file.write_all(json_string.as_bytes()) {
        Ok(_) => debug!("Results saved to: {}", path),
        Err(e) => error!("Error while writing results to file: {}\n{}", path, e),
    };
}

pub fn split_http_headers(header: &str) -> (String, String) {
    let index = header.find(':').unwrap_or(0);
    let header_name = header[..index].to_owned();
    let header_value = header[index + 2..].to_owned();
    (header_name, header_value)
}
