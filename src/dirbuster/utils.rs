use std::{fs, str};

#[derive(Debug)]
pub struct Config {
    pub n_threads: usize,
    pub ignore_certificate: bool,
}

pub fn load_wordlist_and_build_urls(
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