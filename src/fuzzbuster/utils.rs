pub fn split_http_headers(header: &str) -> (String, String) {
    let index = header.find(':').unwrap_or(0);
    let header_name = header[..index].to_owned();
    let header_value = header[index + 2..].to_owned();
    (header_name, header_value)
}
