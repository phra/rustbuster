#[macro_use]
extern crate criterion;
#[macro_use]
extern crate log;

// #[path="../src/fuzzbuster/mod.rs"]
// mod fuzzbuster;
// use fuzzbuster::{FuzzBuster, FuzzRequest};

use criterion::Criterion;
use criterion::black_box;

use librustbuster::fuzzbuster::{FuzzBuster, FuzzRequest};

fn get_fuzzrequest_body() -> FuzzRequest {
    FuzzRequest {
        uri: "http://localhost/".parse::<hyper::Uri>().unwrap(),
        http_method: "GET".to_owned(),
        http_headers: vec![],
        http_body: "CSRFCSRF".to_owned(),
        user_agent: "ua".to_owned(),
        payload: vec!["1".to_owned()],
        csrf_uri: Some("http://localhost/".parse::<hyper::Uri>().unwrap()),
        csrf_regex: Some("(\\w+)".to_owned()),
        csrf_headers: None,
    }
}

fn get_fuzzrequest_header() -> FuzzRequest {
    FuzzRequest {
        uri: "http://localhost/".parse::<hyper::Uri>().unwrap(),
        http_method: "GET".to_owned(),
        http_headers: vec![("X-CSRF-Token".to_owned(), "CSRFCSRF".to_owned())],
        http_body: "body".to_owned(),
        user_agent: "ua".to_owned(),
        payload: vec!["1".to_owned()],
        csrf_uri: Some("http://localhost/".parse::<hyper::Uri>().unwrap()),
        csrf_regex: Some("(\\w+)".to_owned()),
        csrf_headers: None,
    }
}

fn get_fuzzrequest_url() -> FuzzRequest {
    FuzzRequest {
        uri: "http://localhost/CSRFCSRF".parse::<hyper::Uri>().unwrap(),
        http_method: "GET".to_owned(),
        http_headers: vec![],
        http_body: "body".to_owned(),
        user_agent: "ua".to_owned(),
        payload: vec!["1".to_owned()],
        csrf_uri: Some("http://localhost/".parse::<hyper::Uri>().unwrap()),
        csrf_regex: Some("(\\w+)".to_owned()),
        csrf_headers: None,
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("replace_csrf_body", |b| b.iter(|| FuzzBuster::replace_csrf_test(black_box(get_fuzzrequest_body()), black_box("VALUE".to_owned()))));
    c.bench_function("replace_csrf_header", |b| b.iter(|| FuzzBuster::replace_csrf_test(black_box(get_fuzzrequest_header()), black_box("VALUE".to_owned()))));
    c.bench_function("replace_csrf_url", |b| b.iter(|| FuzzBuster::replace_csrf_test(black_box(get_fuzzrequest_url()), black_box("VALUE".to_owned()))));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
