#[derive(Debug, Clone)]
pub struct SingleScanResult {
    pub url: hyper::Uri,
    pub method: hyper::Method,
    pub status: hyper::StatusCode,
    pub error: Option<String>,
}
