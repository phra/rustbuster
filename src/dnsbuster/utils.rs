use std::{fs, io::Write, path};

use super::result_processor::SingleDnsScanResult;

pub fn build_domains(wordlist_path: &str, url: &str) -> Vec<String> {
    debug!("building urls");
    fs::read_to_string(wordlist_path)
        .expect("Something went wrong reading the wordlist file")
        .lines()
        .filter(|word| !word.starts_with('#') && !word.starts_with(' '))
        .map(|word| format!("{}.{}:80", word, url))
        .collect()
}

pub fn save_dns_results(path: &str, results: &Vec<SingleDnsScanResult>) {
    let json_string = serde_json::to_string(&results).unwrap();

    let mut file = match fs::File::create(path::Path::new(path)) {
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
