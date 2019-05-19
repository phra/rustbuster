use serde_derive::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SingleScanResult {
    pub url: String,
    pub method: String,
    pub status: String,
    pub error: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ResultProcessorConfig {
    pub include: Vec<String>,
    pub ignore: Vec<String>
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ScanResult {
    pub results: Vec<SingleScanResult>,
    config: ResultProcessorConfig,
}

impl ScanResult {
    pub fn new(config: ResultProcessorConfig) -> Self {
        ScanResult {
            results: Vec::<SingleScanResult>::new(),
            config,
        }
    }

    pub fn maybe_add_result(&mut self, res: SingleScanResult) {
        if !self.config.ignore.contains(&res.status)
        && (self.config.include.is_empty()
        || self.config.include.contains(&res.status)) {
            self.results.push(res);
        }
    }

    pub fn count(&self) -> usize {
        self.results.len()
    }
}
