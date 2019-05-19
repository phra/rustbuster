#[derive(Debug, Clone)]
pub struct SingleScanResult {
    pub url: hyper::Uri,
    pub method: hyper::Method,
    pub status: hyper::StatusCode,
    pub error: Option<String>,
}

pub struct ResultProcessorConfig {
    pub ignore: Vec<hyper::StatusCode>
}

pub struct ScanResult {
    results: Vec<SingleScanResult>,
    config: ResultProcessorConfig,
}

impl ScanResult {
    pub fn new(config: ResultProcessorConfig) -> Self {
        ScanResult {
            results: Vec::<SingleScanResult>::new(),
            config,
        }
    }

    pub fn add_result(&mut self, res: SingleScanResult) {
        self.results.push(res)
    }

    pub fn count(self) -> usize {
        self.results.len()
    }
}
