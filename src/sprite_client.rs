//! Restricted native HTTP/MCP client for the synthetic Sprite workflow.
use crate::{
    mcp, protocol,
    proxy::{self, transport::Client},
    ErrorCode,
};
use axum::http::{HeaderMap, HeaderValue, Method, Uri};
use serde_json::{json, Value};
use std::{
    io::{self, Write},
    path::Path,
};
use zeroize::Zeroizing;

/// Pins one synthetic service instance and carries only one role credential.
pub struct SpriteClient {
    client: Client,
    url: String,
    token: Zeroizing<String>,
    role: String,
    instance: Option<String>,
}
impl SpriteClient {
    pub fn new(
        url: &str,
        file: &Path,
        role: &str,
        instance: Option<String>,
    ) -> Result<Self, proxy::Error> {
        let uri: Uri = url.parse().map_err(|_| proxy::Error::Invalid)?;
        if !["agent", "owner"].contains(&role)
            || uri.authority().is_none_or(|a| a.as_str().contains('@'))
            || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
            || url.contains('#')
            || !(uri.scheme_str() == Some("https")
                || uri.scheme_str() == Some("http")
                    && uri.host().is_some_and(|h| {
                        h.trim_matches(['[', ']'])
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_loopback())
                    }))
        {
            return Err(proxy::Error::Invalid);
        }
        let raw = proxy::store::private(file, 65)?;
        let token = Zeroizing::new(
            std::str::from_utf8(&raw)
                .map_err(|_| proxy::Error::Invalid)?
                .trim_end()
                .to_owned(),
        );
        if token.len() != 64 || !token.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(proxy::Error::Invalid);
        }
        let mut client = Client::new()?;
        client.loopback_http = true;
        Ok(Self {
            client,
            url: url.trim_end_matches('/').into(),
            token,
            role: role.into(),
            instance,
        })
    }
    fn request(&self, path: &str, body: Option<Value>) -> Result<Value, proxy::Error> {
        let mut headers = HeaderMap::new();
        let mut auth = HeaderValue::from_str(&format!("Bearer {}", self.token.as_str()))
            .map_err(|_| proxy::Error::Invalid)?;
        auth.set_sensitive(true);
        headers.insert("authorization", auth);
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        let method = if body.is_some() {
            Method::POST
        } else {
            Method::GET
        };
        let body = body
            .map(|b| serde_json::to_vec(&b))
            .transpose()
            .map_err(|_| proxy::Error::Invalid)?
            .unwrap_or_default();
        if body.len() > 16384 {
            return Err(proxy::Error::Invalid);
        }
        let (status, bytes) = self.client.send(
            method,
            format!("{}{path}", self.url)
                .parse()
                .map_err(|_| proxy::Error::Invalid)?,
            headers,
            body,
            true,
        )?;
        if status != 200 {
            return Err(proxy::Error::Denied);
        }
        let result: Value = serde_json::from_slice(&bytes).map_err(|_| proxy::Error::Invalid)?;
        if self
            .instance
            .as_ref()
            .is_some_and(|id| result["instance_id"].as_str() != Some(id))
        {
            return Err(proxy::Error::Denied);
        }
        Ok(result)
    }
    pub fn session(&mut self) -> Result<Value, proxy::Error> {
        let value = self.request("/v1/session", None)?;
        let id = value["instance_id"].as_str().ok_or(proxy::Error::Invalid)?;
        if id.len() != 64 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(proxy::Error::Invalid);
        }
        self.instance = Some(id.into());
        Ok(value)
    }
    pub fn call(&self, method: &str, params: Option<Value>) -> Result<Value, proxy::Error> {
        let allowed: &[&str] = if self.role == "agent" {
            &[
                "discover_operations",
                "prepare_operation",
                "request_approval",
                "invoke_approved",
                "get_run_status",
                "cancel",
            ]
        } else {
            &[
                "pending", "inspect", "approve", "cancel", "revoke", "evidence",
            ]
        };
        if !allowed.contains(&method) {
            return Err(proxy::Error::Denied);
        }
        let instance = self.instance.as_ref().ok_or(proxy::Error::Denied)?;
        let mut action = json!({"method":method});
        if let Some(params) = params {
            action["params"] = params;
        }
        let body = if self.role == "agent" {
            json!({"instance_id":instance, "request":{"version":1,"action":action}})
        } else {
            json!({"instance_id":instance,"action":action})
        };
        self.request(&format!("/v1/{}", self.role), Some(body))
    }
}
impl mcp::Bridge for SpriteClient {
    fn exchange(&mut self, request: &Value) -> protocol::Response {
        let result = (|| {
            if self.role != "agent" || request["version"] != 1 {
                return Err(proxy::Error::Denied);
            }
            let result = self.call(
                request["action"]["method"]
                    .as_str()
                    .ok_or(proxy::Error::Invalid)?,
                request["action"].get("params").cloned(),
            )?;
            serde_json::from_value(
                json!({"version":1,"result":result["result"],"error":result["error"]}),
            )
            .map_err(|_| proxy::Error::Invalid)
        })();
        result.unwrap_or_else(|_| protocol::Response::failure(ErrorCode::BrokerUnavailable))
    }
}
/// Native replacement for the previous HTTP/MCP helper.
pub fn cli(args: &[String]) -> Result<(), proxy::Error> {
    let mut index = 0;
    let mut flags = std::collections::BTreeMap::new();
    while args.get(index).is_some_and(|s| s.starts_with("--")) {
        flags.insert(
            args[index].as_str(),
            args.get(index + 1).ok_or(proxy::Error::Invalid)?.as_str(),
        );
        index += 2;
    }
    if flags
        .keys()
        .any(|key| !["--url", "--token-file", "--role", "--instance-id"].contains(key))
    {
        return Err(proxy::Error::Invalid);
    }
    let mut client = SpriteClient::new(
        flags.get("--url").ok_or(proxy::Error::Invalid)?,
        Path::new(flags.get("--token-file").ok_or(proxy::Error::Invalid)?),
        flags.get("--role").ok_or(proxy::Error::Invalid)?,
        flags.get("--instance-id").map(|s| s.to_string()),
    )?;
    let method = args.get(index).ok_or(proxy::Error::Invalid)?;
    if method == "mcp" {
        if client.role != "agent" {
            return Err(proxy::Error::Denied);
        }
        client.session()?;
        return mcp::serve(io::stdin().lock(), io::stdout().lock(), client)
            .map_err(|_| proxy::Error::Invalid);
    }
    let value = if method == "session" {
        client.session()?
    } else if method == "review" && client.role == "owner" {
        let id: u64 = args
            .get(index + 1)
            .ok_or(proxy::Error::Invalid)?
            .parse()
            .map_err(|_| proxy::Error::Invalid)?;
        let review = client.call("inspect", Some(json!({"prepared_request_id":id})))?;
        if !review["error"].is_null() {
            return Err(proxy::Error::Denied);
        }
        eprintln!("{}", review["result"]["plan"]);
        eprint!("Type approve for this exact plan: ");
        io::stderr().flush().map_err(|_| proxy::Error::Invalid)?;
        let mut answer = String::new();
        io::stdin()
            .read_line(&mut answer)
            .map_err(|_| proxy::Error::Invalid)?;
        if answer.trim() != "approve" {
            return Err(proxy::Error::Denied);
        }
        client.call(
            "approve",
            Some(json!({"review_id":review["result"]["review_id"]})),
        )?
    } else {
        let params = args
            .get(index + 1)
            .map(|s| serde_json::from_str(s))
            .transpose()
            .map_err(|_| proxy::Error::Invalid)?;
        client.call(method, params)?
    };
    println!("{value}");
    Ok(())
}
