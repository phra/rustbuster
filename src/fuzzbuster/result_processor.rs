use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write, path::Path, str};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SingleFuzzScanResult {
    pub url: String,
    pub method: String,
    pub status: String,
    pub error: Option<String>,
    pub extra: Option<String>,
    pub payload: Vec<String>,
    pub body: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FuzzScanProcessorConfig {
    pub include: Vec<String>,
    pub ignore: Vec<String>,
    pub include_body: Vec<String>,
    pub ignore_body: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FuzzScanProcessor {
    pub results: Vec<SingleFuzzScanResult>,
    config: FuzzScanProcessorConfig,
}

impl FuzzScanProcessor {
    pub fn new(config: FuzzScanProcessorConfig) -> Self {
        FuzzScanProcessor {
            results: Vec::<SingleFuzzScanResult>::new(),
            config,
        }
    }

    pub fn maybe_add_result(&mut self, res: SingleFuzzScanResult) -> bool {
        trace!("{:?}", res);

        if self.config.ignore_body.len() != 0 {
            for ignore in &self.config.ignore_body {
                if res.body.contains(ignore) {
                    return false;
                }
            }
        }

        if self.config.include_body.len() != 0 {
            for include in &self.config.include_body {
                if res.body.contains(include) {
                    self.results.push(res);
                    return true;
                }
            }
        }

        if self.config.ignore.len() != 0 {
            for code in &self.config.ignore {
                if res.status.starts_with(code) {
                    return false;
                }
            }
        }

        if self.config.include.len() != 0 {
            for code in &self.config.include {
                if res.status.starts_with(code) {
                    self.results.push(res);
                    return true;
                }
            }
        }

        if self.config.include.len() == 0 && self.config.include_body.len() == 0 {
            self.results.push(res);
            return true;
        }

        false
    }

    pub fn save_fuzz_results(self, path: &str) {
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
