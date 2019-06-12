use galvanic_test::test_suite;

test_suite! {
    name fuzzbuster;

    fixture fuzzbuster_url_single() -> crate::fuzzbuster::FuzzBuster {
        setup(&mut self) {
            crate::fuzzbuster::FuzzBuster {
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
    }

    fixture fuzzbuster_url_multiple() -> crate::fuzzbuster::FuzzBuster {
        setup(&mut self) {
            crate::fuzzbuster::FuzzBuster {
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
    }

    fixture fuzzbuster_header_single() -> crate::fuzzbuster::FuzzBuster {
        setup(&mut self) {
            crate::fuzzbuster::FuzzBuster {
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
    }

    fixture fuzzbuster_header_multiple() -> crate::fuzzbuster::FuzzBuster {
        setup(&mut self) {
            crate::fuzzbuster::FuzzBuster {
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
    }

    fixture fuzzbuster_body_single() -> crate::fuzzbuster::FuzzBuster {
        setup(&mut self) {
            crate::fuzzbuster::FuzzBuster {
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
    }

    fixture fuzzbuster_body_multiple() -> crate::fuzzbuster::FuzzBuster {
        setup(&mut self) {
            crate::fuzzbuster::FuzzBuster {
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
    }

    fixture fuzzrequest_csrf_body() -> crate::fuzzbuster::FuzzRequest {
        setup(&mut self) {
            crate::fuzzbuster::FuzzRequest {
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
    }

    fixture fuzzrequest_csrf_header() -> crate::fuzzbuster::FuzzRequest {
        setup(&mut self) {
            crate::fuzzbuster::FuzzRequest {
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
    }

    fixture fuzzrequest_csrf_url() -> crate::fuzzbuster::FuzzRequest {
        setup(&mut self) {
            crate::fuzzbuster::FuzzRequest {
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
    }

    test example_passing_test() {
        assert_eq!(6, 6);
    }

    #[should_panic]
    test example_failing_test() {
        assert_eq!(6, 7);
    }

    test build_requests_fuzz_url_single(fuzzbuster_url_single()) {
        let requests = fuzzbuster_url_single.val.build_requests();
        let expected: Vec<crate::fuzzbuster::FuzzRequest> = vec![
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/1".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["1".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/2".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["2".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
        ];
        assert_eq!(expected, requests);
    }

    test build_requests_fuzz_url_multiple(fuzzbuster_url_multiple()) {
        let requests = fuzzbuster_url_multiple.val.build_requests();
        let expected: Vec<crate::fuzzbuster::FuzzRequest> = vec![
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/1/1".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["1".to_owned(), "1".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/1/2".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["1".to_owned(), "2".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/2/1".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["2".to_owned(), "1".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/2/2".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["2".to_owned(), "2".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None }
        ];
        assert_eq!(expected, requests);
    }

    test build_requests_fuzz_header_single(fuzzbuster_header_single()) {
        let requests = fuzzbuster_header_single.val.build_requests();
        let expected: Vec<crate::fuzzbuster::FuzzRequest> = vec![
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "1".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["1".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "2".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["2".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
        ];
        assert_eq!(expected, requests);
    }

    test build_requests_fuzz_header_multiple(fuzzbuster_header_multiple()) {
        let requests = fuzzbuster_header_multiple.val.build_requests();
        let expected: Vec<crate::fuzzbuster::FuzzRequest> = vec![
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("1".to_owned(), "1".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["1".to_owned(), "1".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("1".to_owned(), "2".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["1".to_owned(), "2".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("2".to_owned(), "1".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["2".to_owned(), "1".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("2".to_owned(), "2".to_owned())], http_body: "body".to_owned(), user_agent: "ua".to_owned(), payload: vec!["2".to_owned(), "2".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
        ];
        assert_eq!(expected, requests);
    }

    test build_requests_fuzz_body_single(fuzzbuster_body_single()) {
        let requests = fuzzbuster_body_single.val.build_requests();
        let expected: Vec<crate::fuzzbuster::FuzzRequest> = vec![
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "1".to_owned(), user_agent: "ua".to_owned(), payload: vec!["1".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "2".to_owned(), user_agent: "ua".to_owned(), payload: vec!["2".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
        ];
        assert_eq!(expected, requests);
    }

    test build_requests_fuzz_body_multiple(fuzzbuster_body_multiple()) {
        let requests = fuzzbuster_body_multiple.val.build_requests();
        let expected: Vec<crate::fuzzbuster::FuzzRequest> = vec![
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "1:1".to_owned(), user_agent: "ua".to_owned(), payload: vec!["1".to_owned(), "1".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "1:2".to_owned(), user_agent: "ua".to_owned(), payload: vec!["1".to_owned(), "2".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "2:1".to_owned(), user_agent: "ua".to_owned(), payload: vec!["2".to_owned(), "1".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
            crate::fuzzbuster::FuzzRequest { uri: "http://localhost/".parse::<hyper::Uri>().unwrap(), http_method: "GET".to_owned(), http_headers: vec![("Header".to_owned(), "Value".to_owned())], http_body: "2:2".to_owned(), user_agent: "ua".to_owned(), payload: vec!["2".to_owned(), "2".to_owned()], csrf_uri: None, csrf_regex: None, csrf_headers: None },
        ];
        assert_eq!(expected, requests);
    }

    test split_http_headers() {
        let header = "Header: Value";
        let expected = ("Header".to_owned(), "Value".to_owned());
        assert_eq!(expected, crate::fuzzbuster::utils::split_http_headers(header));
    }

    test replace_csrf_body(fuzzrequest_csrf_body) {
        let request = fuzzrequest_csrf_body.val;
        let actual = crate::fuzzbuster::FuzzBuster::replace_csrf(request, "VALUE".to_owned());
        assert_eq!("VALUE", actual.http_body);
    }

    test replace_csrf_header(fuzzrequest_csrf_header) {
        let request = fuzzrequest_csrf_header.val;
        let actual = crate::fuzzbuster::FuzzBuster::replace_csrf(request, "VALUE".to_owned());
        let expected = vec![("X-CSRF-Token".to_owned(), "VALUE".to_owned())];
        assert_eq!(expected, actual.http_headers);
    }

    test replace_csrf_url(fuzzrequest_csrf_url) {
        let request = fuzzrequest_csrf_url.val;
        let actual = crate::fuzzbuster::FuzzBuster::replace_csrf(request, "VALUE".to_owned());
        assert_eq!("/VALUE", actual.uri.path());
    }
}
