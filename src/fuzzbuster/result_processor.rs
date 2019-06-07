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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FuzzResultProcessorConfig {
    pub include: Vec<String>,
    pub ignore: Vec<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FuzzScanProcessor {
    pub results: Vec<SingleFuzzScanResult>,
    config: FuzzResultProcessorConfig,
}

impl FuzzScanProcessor {
    pub fn new(config: FuzzResultProcessorConfig) -> Self {
        FuzzScanProcessor {
            results: Vec::<SingleFuzzScanResult>::new(),
            config,
        }
    }

    pub fn maybe_add_result(&mut self, res: SingleFuzzScanResult) -> bool {
        trace!("{:?}", res);
        let mut ignore = false;
        let mut include = false;
        for code in self.config.ignore.iter() {
            if res.status.starts_with(code) {
                ignore = true;
                break;
            }
        }

        for code in self.config.include.iter() {
            if res.status.starts_with(code) {
                include = true;
                break;
            }
        }

        if !ignore && (self.config.include.is_empty() || include) {
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
