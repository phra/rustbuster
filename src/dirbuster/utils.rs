#[derive(Debug, Clone)]
pub struct Target {
    pub url: hyper::Uri,
    pub method: hyper::Method,
    pub status: hyper::StatusCode,
    pub error: Option<String>,
}

#[derive(Debug)]
pub struct Config {
    pub n_threads: usize,
    pub ignore_certificate: bool,
}
