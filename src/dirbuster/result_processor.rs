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
}

impl ScanResult {
    pub fn new(results: Vec<SingleScanResult>) -> Self {
        ScanResult {
            results,
        }
    }

    pub fn add_result(&mut self, res: SingleScanResult) {
        self.results.push(res)
    }

    pub fn count(self) -> usize {
        self.results.len()
    }
}
