use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write, path::Path, str};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum FSObject {
    File,
    Directory,
    DuplicateFile,
    DuplicateDirectory,
    BruteFilename,
    BruteExtension,
    CheckIfDirectory,
    NotExisting,
    Vulnerable,
    NotVulnerable,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TildeRequest {
    pub url: String,
    pub http_method: String,
    pub http_headers: Vec<(String, String)>,
    pub http_body: String,
    pub user_agent: String,
    pub filename: String,
    pub redirect_extension: Option<String>,
    pub extension: String,
    pub duplicate_index: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SingleTildeScanResult {
    pub kind: FSObject,
    pub error: Option<String>,
    pub request: TildeRequest,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TildeScanProcessor {
    pub results: Vec<SingleTildeScanResult>,
}

impl TildeScanProcessor {
    pub fn new() -> Self {
        TildeScanProcessor {
            results: Vec::<SingleTildeScanResult>::new(),
        }
    }

    pub fn maybe_add_result(&mut self, res: SingleTildeScanResult) -> bool {
        trace!("{:?}", res);
        self.results.push(res);
        return true;
    }

    pub fn save_tilde_results(&self, path: &str) {
        let json_string = serde_json::to_string(&self.results).unwrap();

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
}
