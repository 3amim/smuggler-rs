# HTTP Request Smuggling Detector

This tool is an asynchronous, multithreaded HTTP request smuggling scanner written in Rust using the `tokio` and `rustls` libraries. It sends multiple mutated HTTP requests to a target endpoint and analyzes the responses to detect possible smuggling vulnerabilities.

## 🔧 Features

- Asynchronous request handling with `tokio`
- TLS support with `rustls`
- Customizable HTTP method
- Multiple attack iterations per payload
- Timeout handling for delayed/suspicious responses
- Built-in response analyzer for smuggling indicators
- Early exit option on first finding
- Optional virtual host support

## 🚀 Usage

### Build

```bash
cargo build --release
```

### RUN

```bash
smuggler --url https://example.com/path
```

## 🛡️ Response Analysis Heuristics

- Presence of both `Transfer-Encoding: chunked` and `Content-Length`
- Mismatch between declared `Content-Length` and actual body
- Malformed chunked encoding
- Suspicious HTTP status codes (400, 408, 502)
- Detection of smuggling-related headers

## 📄 License

MIT License