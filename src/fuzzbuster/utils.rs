use std::{fs, fs::File, io::Write, path::Path, str};

use super::result_processor::SingleFuzzScanResult;

pub fn build_requests(
    wordlist_path: &str,
    url: &str,
    extensions: Vec<&str>,
    append_slash: bool,
) -> Vec<hyper::Uri> {
    debug!("building urls");
    let mut urls: Vec<hyper::Uri> = Vec::new();
    let wordlist =
        fs::read_to_string(wordlist_path).expect("Something went wrong reading the wordlist file");
    let urls_iter = wordlist
        .lines()
        .filter(|word| !word.starts_with('#') && !word.starts_with(' '))
        .map(|word| {
            if url.ends_with("/") {
                format!("{}{}", url, word)
            } else {
                format!("{}/{}", url, word)
            }
        });

    for url in urls_iter {
        if append_slash {
            if !url.ends_with("/") {
                match format!("{}/", url).parse::<hyper::Uri>() {
                    Ok(v) => {
                        urls.push(v);
                    }
                    Err(e) => {
                        trace!("URI: {}", e);
                    }
                }
            }
        }

        match url.parse::<hyper::Uri>() {
            Ok(v) => {
                urls.push(v);
            }
            Err(e) => {
                trace!("URI: {}", e);
            }
        }

        for extension in extensions.iter() {
            if append_slash {
                match format!("{}.{}/", url, extension).parse::<hyper::Uri>() {
                    Ok(v) => {
                        urls.push(v);
                    }
                    Err(e) => {
                        trace!("URI: {}", e);
                    }
                }
            }

            match format!("{}.{}", url, extension).parse::<hyper::Uri>() {
                Ok(v) => {
                    urls.push(v);
                }
                Err(e) => {
                    trace!("URI: {}", e);
                }
            }
        }
    }

    urls
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
