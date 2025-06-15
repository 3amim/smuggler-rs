use std::collections::HashMap;

/// Represents an HTTP response with status code, headers, and body.
pub struct Response {
    status_code: u16,
    headers: HashMap<String, String>,
    body: String,
}

impl Response {
    /// Parses an HTTP response from raw bytes.
    pub fn from(response_byte: Vec<u8>) -> Self {
        let string_response = match String::from_utf8(response_byte) {
            Ok(s) => s,
            Err(_) => {
                return Response {
                    status_code: 0,
                    headers: HashMap::new(),
                    body: String::new(),
                };
            }
        };
        let split_response: Vec<&str> = string_response.split("\r\n").collect();
        if split_response.is_empty() {
            return Response {
                status_code: 0,
                headers: HashMap::new(),
                body: String::new(),
            };
        }

        let status_code = split_response[0]
            .split(" ")
            .collect::<Vec<&str>>()
            .get(1)
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(0);

        let mut response = Response {
            status_code,
            headers: HashMap::new(),
            body: String::new(),
        };

        let mut lines = split_response.into_iter().skip(1);
        while let Some(line) = lines.next() {
            if line.is_empty() {
                break;
            }
            let split_header: Vec<&str> = line.splitn(2, ':').collect();
            if split_header.len() == 2 {
                response.headers.insert(
                    split_header[0].trim().to_string(),
                    split_header[1].trim().to_string(),
                );
            }
        }
        response.body = lines.collect::<Vec<&str>>().join("\r\n");
        response
    }
    pub fn analyze_smuggling(&self) -> (bool, Vec<String>) {
        let mut reasons = Vec::new();
        let mut is_smuggling = false;

        let has_chunked = self
            .headers
            .get("Transfer-Encoding")
            .map_or(false, |v| v.to_lowercase().contains("chunked"));
        let has_content_length = self.headers.get("Content-Length").is_some();
        if has_chunked && has_content_length {
            is_smuggling = true;
            reasons.push(
                "Both Transfer-Encoding: chunked and Content-Length headers are present."
                    .to_string(),
            );
        }

        if let Some(content_length) = self.headers.get("Content-Length") {
            if let Ok(expected_length) = content_length.parse::<usize>() {
                let actual_length = self.body.as_bytes().len();
                if actual_length != expected_length {
                    is_smuggling = true;
                    reasons.push(format!(
                        "Content-Length ({}) does not match actual body length ({}).",
                        expected_length, actual_length
                    ));
                }
            } else {
                is_smuggling = true;
                reasons.push("Invalid Content-Length header value.".to_string());
            }
        }

        if has_chunked {
            let body_lines: Vec<&str> = self.body.split("\r\n").collect();
            let mut is_valid_chunked = true;
            let mut i = 0;
            while i < body_lines.len() {
                if let Ok(chunk_size) = u64::from_str_radix(body_lines[i].trim(), 16) {
                    if chunk_size == 0 {
                        if i + 1 < body_lines.len() && !body_lines[i + 1].is_empty() {
                            is_valid_chunked = false;
                            reasons.push(
                                "Unexpected data after chunked encoding termination.".to_string(),
                            );
                        }
                        break;
                    }
                    i += 1;
                    if i >= body_lines.len() || body_lines[i].len() as u64 != chunk_size {
                        is_valid_chunked = false;
                        reasons.push("Invalid chunk size or missing chunk data.".to_string());
                        break;
                    }
                    i += 1;
                } else {
                    is_valid_chunked = false;
                    reasons.push("Invalid chunk size format in body.".to_string());
                    break;
                }
            }
            if !is_valid_chunked {
                is_smuggling = true;
            }
        }
        if self.status_code == 400
            || self.status_code == 408
            || self.status_code == 502
            || self.status_code == 0
            || self.status_code == 500
            || self.status_code == 503
        {
            is_smuggling = true;
            reasons.push(format!(
                "Suspicious status code ({}) detected, possibly due to smuggling.",
                self.status_code
            ));
        }

        let suspicious_headers = [
            "X-HTTP-Method-Override",
            "X-Forwarded-For",
            "X-Forwarded-Host",
        ];
        for header in suspicious_headers {
            if self.headers.contains_key(header) {
                is_smuggling = true;
                reasons.push(format!(
                    "Suspicious header '{}' found, possibly injected.",
                    header
                ));
            }
        }

        if self.status_code == 0 && self.body.is_empty() && self.headers.is_empty() {
            is_smuggling = true;
            reasons.push("Empty or invalid response, possibly due to smuggling.".to_string());
        }

        (is_smuggling, reasons)
    }
}
