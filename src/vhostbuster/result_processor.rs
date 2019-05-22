use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SingleVhostScanResult {
    pub vhost: String,
    pub status: String,
    pub method: String,
    pub error: Option<String>,
    pub ignored: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VhostScanResult {
    pub results: Vec<SingleVhostScanResult>,
}

impl VhostScanResult {
    pub fn new() -> Self {
        VhostScanResult {
            results: Vec::<SingleVhostScanResult>::new(),
        }
    }

    pub fn maybe_add_result(&mut self, res: SingleVhostScanResult) -> bool {
        trace!("{:?}", res);
        self.results.push(res);
        true
    }
}
