use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SingleDnsScanResult {
    pub domain: String,
    pub status: bool,
    pub extra: Option<Vec<std::net::SocketAddr>>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DnsScanResult {
    pub results: Vec<SingleDnsScanResult>,
}

impl DnsScanResult {
    pub fn new() -> Self {
        DnsScanResult {
            results: Vec::<SingleDnsScanResult>::new(),
        }
    }

    pub fn maybe_add_result(&mut self, res: SingleDnsScanResult) -> bool {
        trace!("{:?}", res);
        self.results.push(res);
        true
    }
}
