use hyper::{Client, client::HttpConnector, rt::Future};
use hyper_tls::HttpsConnector;

use std::sync::mpsc::Sender;

use crate::{
    dirbuster::result_processor::SingleDirScanResult,
    dnsbuster::result_processor::SingleDnsScanResult,
    vhostbuster::result_processor::SingleVhostScanResult
};

pub enum ScanResult {
    Dir(SingleDirScanResult),
    Dns(SingleDnsScanResult),
    VHost(SingleVhostScanResult)
}

pub trait Buster {
    fn make_request_future(
        &self,
        tx: Sender<ScanResult>,
        client: &Client<HttpsConnector<HttpConnector>>
    ) -> Future<Item = (), Error = ()>;
}