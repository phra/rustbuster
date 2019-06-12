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

fn fuzzrequest_body() -> FuzzRequest {
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

fn fuzzrequest_header() -> FuzzRequest {
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

fn fuzzrequest_url() -> FuzzRequest {
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

fn fuzzbuster_url_single() -> FuzzBuster {
    FuzzBuster {
        n_threads: 1,
        ignore_certificate: true,
        http_method: "GET".to_owned(),
        http_body: "body".to_owned(),
        user_agent: "ua".to_owned(),
        http_headers: vec![("Header".to_owned(), "Value".to_owned())],
        wordlist_paths: vec!["./examples/wordlist_short".to_owned()],
        url: "http://localhost/FUZZ".to_owned(),
        include_status_codes: vec![],
        ignore_status_codes: vec!["404".to_owned()],
        include_body: vec![],
        ignore_body: vec![],
        no_progress_bar: true,
        exit_on_connection_errors: false,
        output: "".to_owned(),
        csrf_url: None,
        csrf_regex: None,
        csrf_headers: None,
    }
}

fn fuzzbuster_url_multiple() -> FuzzBuster {
    FuzzBuster {
        n_threads: 1,
        ignore_certificate: true,
        http_method: "GET".to_owned(),
        http_body: "body".to_owned(),
        user_agent: "ua".to_owned(),
        http_headers: vec![("Header".to_owned(), "Value".to_owned())],
        wordlist_paths: vec!["./examples/wordlist_short".to_owned(), "./examples/wordlist_short".to_owned()],
        url: "http://localhost/FUZZ/FUZZ".to_owned(),
        include_status_codes: vec![],
        ignore_status_codes: vec!["404".to_owned()],
        include_body: vec![],
        ignore_body: vec![],
        no_progress_bar: true,
        exit_on_connection_errors: false,
        output: "".to_owned(),
        csrf_url: None,
        csrf_regex: None,
        csrf_headers: None,
    }
}

fn fuzzbuster_header_single() -> FuzzBuster {
    FuzzBuster {
        n_threads: 1,
        ignore_certificate: true,
        http_method: "GET".to_owned(),
        http_body: "body".to_owned(),
        user_agent: "ua".to_owned(),
        http_headers: vec![("Header".to_owned(), "FUZZ".to_owned())],
        wordlist_paths: vec!["./examples/wordlist_short".to_owned()],
        url: "http://localhost/".to_owned(),
        include_status_codes: vec![],
        ignore_status_codes: vec!["404".to_owned()],
        include_body: vec![],
        ignore_body: vec![],
        no_progress_bar: true,
        exit_on_connection_errors: false,
        output: "".to_owned(),
        csrf_url: None,
        csrf_regex: None,
        csrf_headers: None,
    }
}

fn fuzzbuster_header_multiple() -> FuzzBuster {
    FuzzBuster {
        n_threads: 1,
        ignore_certificate: true,
        http_method: "GET".to_owned(),
        http_body: "body".to_owned(),
        user_agent: "ua".to_owned(),
        http_headers: vec![("FUZZ".to_owned(), "FUZZ".to_owned())],
        wordlist_paths: vec!["./examples/wordlist_short".to_owned(), "./examples/wordlist_short".to_owned()],
        url: "http://localhost/".to_owned(),
        include_status_codes: vec![],
        ignore_status_codes: vec!["404".to_owned()],
        include_body: vec![],
        ignore_body: vec![],
        no_progress_bar: true,
        exit_on_connection_errors: false,
        output: "".to_owned(),
        csrf_url: None,
        csrf_regex: None,
        csrf_headers: None,
    }
}

fn fuzzbuster_body_single() -> FuzzBuster {
    FuzzBuster {
        n_threads: 1,
        ignore_certificate: true,
        http_method: "GET".to_owned(),
        http_body: "FUZZ".to_owned(),
        user_agent: "ua".to_owned(),
        http_headers: vec![("Header".to_owned(), "Value".to_owned())],
        wordlist_paths: vec!["./examples/wordlist_short".to_owned()],
        url: "http://localhost/".to_owned(),
        include_status_codes: vec![],
        ignore_status_codes: vec!["404".to_owned()],
        include_body: vec![],
        ignore_body: vec![],
        no_progress_bar: true,
        exit_on_connection_errors: false,
        output: "".to_owned(),
        csrf_url: None,
        csrf_regex: None,
        csrf_headers: None,
    }
}

fn fuzzbuster_body_multiple() -> FuzzBuster {
    FuzzBuster {
        n_threads: 1,
        ignore_certificate: true,
        http_method: "GET".to_owned(),
        http_body: "FUZZ:FUZZ".to_owned(),
        user_agent: "ua".to_owned(),
        http_headers: vec![("Header".to_owned(), "Value".to_owned())],
        wordlist_paths: vec!["./examples/wordlist_short".to_owned(), "./examples/wordlist_short".to_owned()],
        url: "http://localhost/".to_owned(),
        include_status_codes: vec![],
        ignore_status_codes: vec!["404".to_owned()],
        include_body: vec![],
        ignore_body: vec![],
        no_progress_bar: true,
        exit_on_connection_errors: false,
        output: "".to_owned(),
        csrf_url: None,
        csrf_regex: None,
        csrf_headers: None,
    }
}

fn criterion_benchmark(c: &mut Criterion) {
    c.bench_function("replace_csrf_body", |b| b.iter(|| FuzzBuster::replace_csrf(black_box(fuzzrequest_body()), black_box("VALUE".to_owned()))));
    c.bench_function("replace_csrf_header", |b| b.iter(|| FuzzBuster::replace_csrf(black_box(fuzzrequest_header()), black_box("VALUE".to_owned()))));
    c.bench_function("replace_csrf_url", |b| b.iter(|| FuzzBuster::replace_csrf(black_box(fuzzrequest_url()), black_box("VALUE".to_owned()))));
    c.bench_function("build_requests_url_single", |b| b.iter(|| fuzzbuster_url_single().build_requests()));
    c.bench_function("build_requests_url_multiple", |b| b.iter(|| fuzzbuster_url_multiple().build_requests()));
    c.bench_function("build_requests_header_single", |b| b.iter(|| fuzzbuster_header_single().build_requests()));
    c.bench_function("build_requests_header_multiple", |b| b.iter(|| fuzzbuster_header_multiple().build_requests()));
    c.bench_function("build_requests_body_single", |b| b.iter(|| fuzzbuster_body_single().build_requests()));
    c.bench_function("build_requests_body_multiple", |b| b.iter(|| fuzzbuster_body_multiple().build_requests()));
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
