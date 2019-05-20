use serde::{Deserialize, Serialize};

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
    pub ignore: Vec<String>,
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

    pub fn maybe_add_result(&mut self, res: SingleScanResult) -> bool {
        debug!("{:?}", res);
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
            print_result_stdout(&res);
            self.results.push(res);
            return true;
        }

        false
    }

    pub fn count(&self) -> usize {
        self.results.len()
    }
}

fn print_result_stdout(result: &SingleScanResult) {
    println!("{} {} {}", result.method, result.status, result.url)
}
