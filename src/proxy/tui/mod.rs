//! Owner-local terminal UI. Uses the same broker checks and persistence as the CLI.
mod terminal;
use super::{valid_id, Broker, Error, Injection, Operation, Policy};
use axum::http::{HeaderName, HeaderValue, Uri};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::Duration,
};
use terminal::Terminal;

type Result<T> = std::result::Result<T, Error>;

/// Open the interactive owner console. Requires an actual terminal on both streams.
pub fn run(path: Option<PathBuf>) -> Result<()> {
    let mut app = App {
        terminal: Terminal::open()?,
        path: path.unwrap_or_else(|| {
            std::env::var_os("HOME")
                .map(PathBuf::from)
                .unwrap_or_default()
                .join(".aegis")
        }),
        server: None,
    };
    app.run()
}
struct Running {
    child: Child,
    address: String,
}
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
struct App {
    terminal: Terminal,
    path: PathBuf,
    server: Option<Running>,
}
impl App {
    fn choose(&mut self, title: &str, hint: &str, items: &[&str]) -> Result<Option<usize>> {
        self.terminal.menu(
            title,
            hint,
            &items.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }
    fn note(&mut self, title: &str, lines: &[&str]) -> Result<()> {
        self.terminal.note(
            title,
            &lines.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    }
    fn confirm(&mut self, title: &str, hint: &str) -> Result<bool> {
        Ok(self.choose(title, hint, &["Go back", "Confirm"])? == Some(1))
    }
    fn text(
        &mut self,
        title: &str,
        hint: &str,
        initial: &str,
        max: usize,
        validate: impl Fn(&str) -> bool,
    ) -> Result<Option<String>> {
        Ok(self
            .terminal
            .field(title, hint, initial, false, max, validate)?
            .map(|s| s.to_string()))
    }
    fn broker(&self) -> Result<Broker> {
        Broker::open(&self.path)
    }
    fn secrets(&self) -> Result<Vec<String>> {
        Ok(self.broker()?.status()?["secrets"]
            .as_array()
            .ok_or(Error::Storage)?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect())
    }
    fn error(&mut self, error: Error) -> Result<()> {
        self.note(
            "Let's fix that",
            match error {
                Error::Storage => &[
                    "Aegis could not open or save its private vault.",
                    "Check that you own this folder and that it is private.",
                    "An existing vault will never be replaced automatically.",
                ],
                Error::Capacity => &[
                    "This vault or service has reached its allowance.",
                    "Review its call limit and retained requests.",
                ],
                Error::Denied => &[
                    "This action is not allowed by the current configuration.",
                    "Reopen the service and check its settings.",
                ],
                _ => &[
                    "Those settings could not be applied.",
                    "Check the endpoint, header names and secret references.",
                    "Your previous settings have been kept.",
                ],
            },
        )
    }
    fn run(&mut self) -> Result<()> {
        loop {
            if !self.path.exists() {
                match self.choose(
                    "Welcome to Aegis",
                    "Private secrets. Scoped access. Apps your agent can run.",
                    &[
                        "Set up a private vault",
                        "Choose a different vault folder",
                        "How Aegis works",
                        "Exit",
                    ],
                )? {
                    Some(0) => {
                        let path = self.path.display().to_string();
                        if self.confirm("Create your vault", &path)? {
                            match Broker::initialize(&self.path) {
                                Ok(()) => self.note(
                                    "Your vault is ready",
                                    &[
                                        "Next, add an API key and connect a service.",
                                        "A service gets permission to use a key, not read it.",
                                        "Only you should administer this Aegis host.",
                                    ],
                                )?,
                                Err(e) => self.error(e)?,
                            }
                        }
                    }
                    Some(1) => self.change_path()?,
                    Some(2) => self.help()?,
                    _ => return Ok(()),
                }
                continue;
            }
            let status = match self.broker().and_then(|b| b.status()) {
                Ok(s) => s,
                Err(e) => {
                    self.error(e)?;
                    if self.choose(
                        "Open a vault",
                        "Existing state is preserved.",
                        &["Choose another folder", "Exit"],
                    )? != Some(0)
                    {
                        return Ok(());
                    }
                    self.change_path()?;
                    continue;
                }
            };
            if let Some(server) = self.server.as_mut() {
                if server
                    .child
                    .try_wait()
                    .map_err(|_| Error::Storage)?
                    .is_some()
                {
                    self.server = None;
                    self.note(
                        "Proxy stopped",
                        &[
                            "The proxy process exited. Your vault is saved.",
                            "Check that its port is available, then start it again.",
                        ],
                    )?;
                }
            }
            let secret_count = status["secrets"].as_array().map_or(0, Vec::len);
            let service_count = status["services"].as_array().map_or(0, Vec::len);
            let title =
                format!("Your workspace  |  {secret_count} secrets  |  {service_count} services");
            let hint = if let Some(server) = &self.server {
                format!("Proxy running at {}", server.address)
            } else if secret_count == 0 {
                "Start here: add your first API key.".into()
            } else if service_count == 0 {
                "Next: connect an app with a service policy.".into()
            } else {
                "Ready. This console has not started a proxy.".into()
            };
            let server_label = if self.server.is_some() {
                "Stop proxy"
            } else {
                "Start proxy"
            };
            let action = self.choose(
                &title,
                &hint,
                &[
                    "Add a secret",
                    "Manage secrets",
                    "Connect a service",
                    "Manage services & policies",
                    server_label,
                    "Connection guide",
                    "Vault settings & help",
                    "Exit",
                ],
            )?;
            let outcome = match action {
                Some(0) => self.add_secret(None),
                Some(1) => self.manage_secrets(),
                Some(2) => self.new_service(),
                Some(3) => self.manage_services(),
                Some(4) => self.toggle_proxy(),
                Some(5) => self.connection_guide(None),
                Some(6) => self.settings(),
                _ => {
                    if self.server.is_none()
                        || self.confirm(
                            "Stop proxy and exit?",
                            "The proxy runs while this console is open.",
                        )?
                    {
                        self.server = None;
                        return Ok(());
                    }
                    Ok(())
                }
            };
            if let Err(error) = outcome {
                self.error(error)?;
            }
        }
    }
    fn change_path(&mut self) -> Result<()> {
        if let Some(path) = self.text(
            "Vault folder",
            "Use an absolute folder path. A new folder is created privately.",
            &self.path.display().to_string(),
            2048,
            |s| Path::new(s).is_absolute(),
        )? {
            self.path = PathBuf::from(path);
        }
        Ok(())
    }
    fn help(&mut self) -> Result<()> {
        self.note(
            "Aegis, in three steps",
            &[
                "1. Store your API key here on the owner-controlled host.",
                "2. Give an app permission to use it at an exact HTTPS endpoint.",
                "3. Start the proxy; the app sends a named operation to Aegis.",
                "",
                "Aegis attaches the key and returns only approved result fields.",
                "Your agent can administer the app host, not this Aegis host.",
                "Provider keys are never revealed in this console.",
                "Remote apps need your HTTPS gateway or private encrypted tunnel.",
                "This experimental proxy supports header-based credentials.",
                "Request signing and app-specific spending rules are separate.",
            ],
        )
    }
    fn settings(&mut self) -> Result<()> {
        match self.choose(
            "Vault settings",
            &self.path.display().to_string(),
            &[
                "About this vault",
                "How Aegis works",
                "Open another vault",
                "Back",
            ],
        )? {
            Some(0) => self.note(
                "Private vault",
                &[
                    &format!("Folder: {}", self.path.display()),
                    "Secret records are encrypted with age.",
                    "The owner key is stored in this private folder.",
                    "Protect the whole host and its backups from agent access.",
                    "Back up the complete folder through your trusted tools.",
                    "Restoring old state can restore already-used permissions.",
                    "Review services before serving a restored backup.",
                ],
            ),
            Some(1) => self.help(),
            Some(2) => {
                if self.server.is_some()
                    && !self.confirm(
                        "Stop proxy and switch vault?",
                        "The current console-managed proxy will stop.",
                    )?
                {
                    return Ok(());
                }
                self.server = None;
                self.change_path()
            }
            _ => Ok(()),
        }
    }
    fn add_secret(&mut self, existing: Option<&str>) -> Result<()> {
        let name = if let Some(name) = existing {
            name.to_owned()
        } else {
            let Some(name) = self.text(
                "Name your secret",
                "A label such as service-api-key. Letters, digits, - and _.",
                "",
                80,
                valid_id,
            )?
            else {
                return Ok(());
            };
            if self.secrets()?.contains(&name)
                && !self.confirm(
                    "Replace existing secret?",
                    "Services will use the replacement on their next new request.",
                )?
            {
                return Ok(());
            }
            name
        };
        let Some(mut value) = self.terminal.field(
            "Enter secret value",
            "Paste your API key. Its value stays hidden.",
            "",
            true,
            4096,
            |s| s.len() >= 8 && HeaderValue::from_str(s).is_ok(),
        )?
        else {
            return Ok(());
        };
        self.broker()?
            .put_secret(&name, std::mem::take(&mut *value))?;
        self.note(
            "Secret saved",
            &[
                &format!("Reference: {name}"),
                "Encrypted and ready to use in a service policy.",
                "The value is not displayed or written to terminal history.",
            ],
        )
    }
    fn manage_secrets(&mut self) -> Result<()> {
        let names = self.secrets()?;
        if names.is_empty() {
            return self.add_secret(None);
        }
        let Some(index) = self.terminal.menu(
            "Your secrets",
            "Only references are shown. Values stay private.",
            &names,
        )?
        else {
            return Ok(());
        };
        let name = &names[index];
        match self.choose(
            name,
            "Changes affect services that use this reference.",
            &["Replace secret value", "Delete secret", "Back"],
        )? {
            Some(0) => self.add_secret(Some(name)),
            Some(1) => {
                if self.confirm(
                    "Delete secret?",
                    "New requests using this secret will fail until it is replaced.",
                )? {
                    self.broker()?.delete_secret(name)?;
                    self.note(
                        "Secret deleted",
                        &[
                            "Existing service policies are preserved.",
                            "Reconnect them to a valid secret before sending new requests.",
                        ],
                    )?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    fn new_service(&mut self) -> Result<()> {
        if self.secrets()?.is_empty() {
            self.note(
                "Add a secret first",
                &["A service needs at least one secret reference."],
            )?;
            return self.add_secret(None);
        }
        let Some(name) = self.text(
            "Name your service",
            "Choose an app identity, such as worker or reporting-app.",
            "",
            80,
            valid_id,
        )?
        else {
            return Ok(());
        };
        let status = self.broker()?.status()?;
        if status["services"]
            .as_array()
            .is_some_and(|s| s.iter().any(|v| v["name"] == name))
        {
            return self.note(
                "That service already exists",
                &["Use Manage services & policies to change it."],
            );
        }
        let policy = Policy {
            allowed_secrets: BTreeSet::new(),
            operations: BTreeMap::new(),
            max_calls: 100,
        };
        self.edit_policy(&name, policy, true)
    }
    fn edit_policy(&mut self, name: &str, mut policy: Policy, new: bool) -> Result<()> {
        let original = serde_json::to_value(&policy).map_err(|_| Error::Invalid)?;
        loop {
            let title = format!("Policy for {name}");
            let hint = format!(
                "{} operations | {} total calls | Unsaved draft",
                policy.operations.len(),
                policy.max_calls
            );
            match self.choose(
                &title,
                &hint,
                &[
                    "Add an operation",
                    "Edit an operation",
                    "Remove an operation",
                    "Set call allowance",
                    "Review and save policy",
                    "Discard changes",
                ],
            )? {
                Some(0) => {
                    if policy.operations.len() >= 32 {
                        self.note(
                            "Operation limit",
                            &["A service can have up to 32 operations."],
                        )?;
                        continue;
                    }
                    if let Some((id, op)) = self.operation(None)? {
                        if policy.operations.contains_key(&id)
                            && !self.confirm("Replace this operation?", &id)?
                        {
                            continue;
                        }
                        policy.operations.insert(id, op);
                    }
                }
                Some(1) => {
                    let keys: Vec<_> = policy.operations.keys().cloned().collect();
                    if keys.is_empty() {
                        self.note(
                            "No operations yet",
                            &["Choose Add an operation to get started."],
                        )?;
                        continue;
                    }
                    if let Some(i) = self.terminal.menu(
                        "Edit operation",
                        "Choose the operation to change.",
                        &keys,
                    )? {
                        if let Some((id, op)) =
                            self.operation(Some((&keys[i], &policy.operations[&keys[i]])))?
                        {
                            if id != keys[i]
                                && policy.operations.contains_key(&id)
                                && !self.confirm("Replace another operation?", &id)?
                            {
                                continue;
                            }
                            policy.operations.remove(&keys[i]);
                            policy.operations.insert(id, op);
                        }
                    }
                }
                Some(2) => {
                    let keys: Vec<_> = policy.operations.keys().cloned().collect();
                    if !keys.is_empty() {
                        if let Some(i) = self.terminal.menu(
                            "Remove operation",
                            "This only changes the draft until you save.",
                            &keys,
                        )? {
                            policy.operations.remove(&keys[i]);
                        }
                    }
                }
                Some(3) => {
                    if let Some(calls) = self.text(
                        "Total call allowance",
                        "Lifetime allowance; saving or rotating tokens does not reset usage.",
                        &policy.max_calls.to_string(),
                        20,
                        |s| s.parse::<u64>().is_ok_and(|n| n > 0),
                    )? {
                        policy.max_calls = calls.parse().map_err(|_| Error::Invalid)?;
                    }
                }
                Some(4) => {
                    policy.allowed_secrets = policy
                        .operations
                        .values()
                        .flat_map(|op| op.secrets.keys().cloned())
                        .collect();
                    if policy.validate().is_err() {
                        self.note(
                            "Policy needs an operation",
                            &[
                                "Add at least one valid operation with a secret binding.",
                                "A service can reference at most 32 secrets.",
                            ],
                        )?;
                        continue;
                    }
                    let mut review = vec![
                        format!("Service: {name}"),
                        format!("Total call allowance: {}", policy.max_calls),
                        "".into(),
                    ];
                    for (id, op) in &policy.operations {
                        review.extend([
                            format!("{id}  /  {}", op.method),
                            format!("  {}", op.url),
                            format!(
                                "  Secrets: {}",
                                op.secrets.keys().cloned().collect::<Vec<_>>().join(", ")
                            ),
                            format!(
                                "  Output fields: {}",
                                if op.response_fields.is_empty() {
                                    "status only".into()
                                } else {
                                    op.response_fields
                                        .keys()
                                        .cloned()
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                }
                            ),
                        ]);
                    }
                    review.extend([
                        "".into(),
                        "Request bodies are controlled by the app.".into(),
                        "Grant only operations the app should be able to perform.".into(),
                    ]);
                    self.terminal.note("Review service access", &review)?;
                    if !self.confirm(
                        "Save this policy?",
                        "These permissions take effect immediately when saved.",
                    )? {
                        continue;
                    }
                    let broker = self.broker()?;
                    let result = if new {
                        broker.add_service(name, policy.clone())
                    } else {
                        broker.set_policy(name, policy.clone())
                    };
                    if let Err(error) = result {
                        self.error(error)?;
                        continue;
                    }
                    self.note(
                        "Service ready",
                        &[
                            "Your policy has been saved.",
                            "Call usage and retry history are preserved.",
                        ],
                    )?;
                    return self.connection_guide(Some(name));
                }
                _ => {
                    if serde_json::to_value(&policy).map_err(|_| Error::Invalid)? != original
                        && !self.confirm(
                            "Discard policy changes?",
                            "Your saved policy will stay unchanged.",
                        )?
                    {
                        continue;
                    }
                    return Ok(());
                }
            }
        }
    }
    fn operation(
        &mut self,
        existing: Option<(&str, &Operation)>,
    ) -> Result<Option<(String, Operation)>> {
        let Some(id) = self.text(
            "Operation name",
            "A name your app will request, such as create-message.",
            existing.map_or("", |(id, _)| id),
            80,
            valid_id,
        )?
        else {
            return Ok(None);
        };
        let Some(url) = self.text(
            "Approved HTTPS endpoint",
            "Exact URL from your provider. Include the path, not an API key.",
            existing.map_or("https://", |(_, op)| op.url.as_str()),
            2048,
            valid_url,
        )?
        else {
            return Ok(None);
        };
        let methods = ["GET", "POST", "PUT", "PATCH", "DELETE"];
        let selected = existing
            .and_then(|(_, op)| methods.iter().position(|m| *m == op.method))
            .unwrap_or(0);
        let Some(method) = self.terminal.menu_at(
            "HTTP method",
            "Choose the method required by this endpoint.",
            &[
                "GET  - Read",
                "POST - Create or submit",
                "PUT  - Replace",
                "PATCH - Update",
                "DELETE - Remove",
            ]
            .map(str::to_string),
            selected,
        )?
        else {
            return Ok(None);
        };
        let mut op = existing.map(|(_, op)| op.clone()).unwrap_or(Operation {
            url: String::new(),
            method: String::new(),
            headers: BTreeMap::new(),
            secrets: BTreeMap::new(),
            response_fields: BTreeMap::new(),
        });
        op.url = url;
        op.method = ["GET", "POST", "PUT", "PATCH", "DELETE"][method].into();
        if op.secrets.is_empty() && !self.bind_secret(&mut op)? {
            return Ok(None);
        }
        loop {
            let hint = format!(
                "{} | {} credentials | {} output fields",
                op.method,
                op.secrets.len(),
                op.response_fields.len()
            );
            match self.choose(
                &format!("Configure {id}"),
                &hint,
                &[
                    "Finish operation",
                    "Add or change secret binding",
                    "Remove secret binding",
                    "Choose response fields",
                    "Extra request headers",
                    "Review operation",
                    "Cancel operation",
                ],
            )? {
                Some(0) => {
                    let check = Policy {
                        allowed_secrets: op.secrets.keys().cloned().collect(),
                        operations: BTreeMap::from([(id.clone(), op.clone())]),
                        max_calls: 1,
                    };
                    if check.validate().is_err() {
                        self.note(
                            "Check this operation",
                            &[
                                "Use at least one secret and distinct, valid header names.",
                                "Routing headers such as Host cannot be changed.",
                            ],
                        )?;
                        continue;
                    }
                    return Ok(Some((id, op)));
                }
                Some(1) => {
                    self.bind_secret(&mut op)?;
                }
                Some(2) => {
                    let keys: Vec<_> = op.secrets.keys().cloned().collect();
                    if !keys.is_empty() {
                        if let Some(i) = self.terminal.menu(
                            "Remove binding",
                            "The stored secret itself is kept.",
                            &keys,
                        )? {
                            op.secrets.remove(&keys[i]);
                        }
                    }
                }
                Some(3) => self.fields(&mut op.response_fields, false)?,
                Some(4) => self.fields(&mut op.headers, true)?,
                Some(5) => {
                    let mut lines = vec![format!("{} {}", op.method, op.url)];
                    for (secret, binding) in &op.secrets {
                        lines.push(format!(
                            "{secret} -> {} (prefix: {:?})",
                            binding.header, binding.prefix
                        ));
                    }
                    for (name, pointer) in &op.response_fields {
                        lines.push(format!("Return {name} from {pointer}"));
                    }
                    if op.response_fields.is_empty() {
                        lines.push("Return HTTP status only (recommended default).".into());
                    }
                    self.terminal.note("Operation details", &lines)?;
                }
                _ => return Ok(None),
            }
        }
    }
    fn bind_secret(&mut self, op: &mut Operation) -> Result<bool> {
        let secrets = self.secrets()?;
        if secrets.is_empty() {
            return Ok(false);
        }
        let Some(i) = self.terminal.menu(
            "Choose a secret",
            "This service can use the selected key, never read it.",
            &secrets,
        )?
        else {
            return Ok(false);
        };
        let Some(kind) = self.choose(
            "How does the API accept this key?",
            "Check the authentication section of your provider's docs.",
            &[
                "Bearer token  - Authorization: Bearer <key>",
                "API key      - X-API-Key: <key>",
                "Raw token    - Authorization: <key>",
                "Custom header and prefix",
            ],
        )?
        else {
            return Ok(false);
        };
        let (header, prefix) = match kind {
            0 => ("Authorization".into(), "Bearer ".into()),
            1 => ("X-API-Key".into(), String::new()),
            2 => ("Authorization".into(), String::new()),
            _ => {
                let Some(header) = self.text(
                    "Header name",
                    "For example, X-Service-Key. Routing headers are not allowed.",
                    "",
                    80,
                    super::safe_header,
                )?
                else {
                    return Ok(false);
                };
                let Some(prefix) = self.text(
                    "Text before the key",
                    "Optional. Include any required trailing space. Do not enter the key.",
                    "",
                    128,
                    |s| HeaderValue::from_str(s).is_ok(),
                )?
                else {
                    return Ok(false);
                };
                (header, prefix)
            }
        };
        if op.headers.keys().any(|h| h.eq_ignore_ascii_case(&header))
            || op
                .secrets
                .iter()
                .any(|(key, b)| key != &secrets[i] && b.header.eq_ignore_ascii_case(&header))
        {
            self.note(
                "Header already used",
                &["Remove its current binding or choose another header."],
            )?;
            return Ok(false);
        }
        op.secrets
            .insert(secrets[i].clone(), Injection { header, prefix });
        Ok(true)
    }
    fn fields(&mut self, fields: &mut BTreeMap<String, String>, headers: bool) -> Result<()> {
        loop {
            let title = if headers {
                "Extra request headers"
            } else {
                "Response fields"
            };
            let hint = if headers {
                "Non-secret headers only. Credentials belong in secret bindings."
            } else {
                "Empty returns status only. Select only safe JSON result fields."
            };
            match self.choose(
                title,
                hint,
                &["Add or replace a field", "Remove a field", "Done"],
            )? {
                Some(0) => {
                    if fields.len() >= if headers { 16 } else { 32 } {
                        self.note("Field limit", &["Remove a field before adding another."])?;
                        continue;
                    }
                    let Some(name) = self.text(
                        if headers {
                            "Header name"
                        } else {
                            "Result field name"
                        },
                        if headers {
                            "For example, Accept or Content-Type."
                        } else {
                            "A name the app will see, such as message_id."
                        },
                        "",
                        80,
                        |s| {
                            if headers {
                                super::safe_header(s) && !s.eq_ignore_ascii_case("authorization")
                            } else {
                                valid_id(s)
                            }
                        },
                    )?
                    else {
                        continue;
                    };
                    let Some(value) = self.text(
                        if headers {
                            "Header value"
                        } else {
                            "JSON pointer"
                        },
                        if headers {
                            "Non-secret value, such as application/json."
                        } else {
                            "Where to read the result, such as /id or /data/status."
                        },
                        "",
                        if headers { 1024 } else { 256 },
                        |s| {
                            if headers {
                                HeaderValue::from_str(s).is_ok()
                            } else {
                                s.starts_with('/')
                            }
                        },
                    )?
                    else {
                        continue;
                    };
                    if headers && HeaderName::from_bytes(name.as_bytes()).is_err() {
                        continue;
                    }
                    fields.insert(name, value);
                }
                Some(1) => {
                    let keys: Vec<_> = fields.keys().cloned().collect();
                    if !keys.is_empty() {
                        if let Some(i) = self.terminal.menu(
                            "Remove field",
                            "Choose a field to remove.",
                            &keys,
                        )? {
                            fields.remove(&keys[i]);
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }
    fn manage_services(&mut self) -> Result<()> {
        let status = self.broker()?.status()?;
        let services = status["services"].as_array().ok_or(Error::Storage)?;
        if services.is_empty() {
            return self.new_service();
        }
        let names: Vec<_> = services
            .iter()
            .map(|v| {
                format!(
                    "{}  |  {}  |  {} / {} calls",
                    v["name"].as_str().unwrap_or(""),
                    if v["enabled"] == true {
                        "enabled"
                    } else {
                        "paused"
                    },
                    v["used"],
                    v["policy"]["max_calls"]
                )
            })
            .collect();
        let Some(i) = self.terminal.menu(
            "Your services",
            "Each app has separate credentials and permissions.",
            &names,
        )?
        else {
            return Ok(());
        };
        let service = &services[i];
        let name = service["name"].as_str().ok_or(Error::Storage)?;
        let enabled = service["enabled"] == true;
        let toggle = if enabled {
            "Pause service"
        } else {
            "Enable service"
        };
        match self.choose(
            name,
            "Manage permissions and access for this app.",
            &[
                "Edit policy",
                toggle,
                "Rotate service token",
                "Connection details",
                "Back",
            ],
        )? {
            Some(0) => self.edit_policy(
                name,
                serde_json::from_value(service["policy"].clone()).map_err(|_| Error::Storage)?,
                false,
            ),
            Some(1) => {
                if self.confirm(toggle, "Already-dispatched requests cannot be recalled.")? {
                    self.broker()?.control(name, Some(!enabled), false)?;
                    self.note(
                        "Service updated",
                        &[if enabled {
                            "New requests are paused."
                        } else {
                            "The service is enabled."
                        }],
                    )?;
                }
                Ok(())
            }
            Some(2) => {
                if self.confirm(
                    "Rotate service token?",
                    "The app must receive the replacement token to keep working.",
                )? {
                    self.broker()?.control(name, None, true)?;
                    self.connection_guide(Some(name))?;
                }
                Ok(())
            }
            Some(3) => self.connection_guide(Some(name)),
            _ => Ok(()),
        }
    }
    fn connection_guide(&mut self, service: Option<&str>) -> Result<()> {
        let mut lines = vec![
            "Keep this Aegis host owner-controlled.".into(),
            "Connect other hosts through your HTTPS gateway or private tunnel.".into(),
            "The proxy listens locally; starting it does not publish a URL.".into(),
            "".into(),
            "App endpoint: POST /v1/proxy".into(),
            "Authentication: Authorization: Bearer <service token>".into(),
            "Body: request_id, operation, inject (secret names), optional body.".into(),
        ];
        if let Some(name) = service {
            lines.push("".into());
            lines.push(format!("Service: {name}"));
            lines.push("Private token file (transfer only to this app):".into());
            lines.push(
                self.path
                    .join(format!("{name}.token"))
                    .display()
                    .to_string(),
            );
            lines.push("This token grants operation access, not owner access.".into());
        }
        lines.push("Full integration examples: docs/secret-proxy.md".into());
        self.terminal.note("Connect your application", &lines)
    }
    fn toggle_proxy(&mut self) -> Result<()> {
        if self.server.is_some() {
            if self.confirm(
                "Stop the proxy?",
                "In-flight requests may have an unknown outcome. Reconcile before retrying.",
            )? {
                self.server = None;
            }
            return Ok(());
        }
        let Some(port) = self.text(
            "Start local proxy",
            "Choose a local port. Remote access requires your HTTPS gateway.",
            "7980",
            5,
            |s| s.parse::<u16>().is_ok_and(|v| v > 0),
        )?
        else {
            return Ok(());
        };
        let address = format!("127.0.0.1:{port}");
        let mut child = Command::new(std::env::current_exe().map_err(|_| Error::Storage)?)
            .arg("proxy")
            .arg("--state-dir")
            .arg(&self.path)
            .arg("serve")
            .arg(&address)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| Error::Storage)?;
        let stdout = child.stdout.take().ok_or(Error::Storage)?;
        let mut server = Running {
            child,
            address: address.clone(),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let _ = reader.read_line(&mut line);
            let _ = tx.send(line);
            let _ = std::io::copy(&mut reader, &mut std::io::sink());
        });
        if rx.recv_timeout(Duration::from_secs(5)).ok().as_deref()
            != Some(&format!("aegis_proxy_ready {address}\n"))
            || server
                .child
                .try_wait()
                .map_err(|_| Error::Storage)?
                .is_some()
        {
            return self.note(
                "Could not start proxy",
                &[
                    "The selected port may be in use, or the vault is unavailable.",
                    "Choose another port or review the vault folder permissions.",
                ],
            );
        }
        server.address = address;
        self.server = Some(server);
        self.note(
            "Proxy is running",
            &[
                "You can manage policies while it runs.",
                "Keep this console open. Exiting stops this proxy process.",
                "For unattended hosting, use your platform's service supervisor.",
            ],
        )
    }
}
fn valid_url(s: &str) -> bool {
    s.parse::<Uri>().is_ok_and(|uri| {
        uri.scheme_str() == Some("https")
            && uri.host().is_some()
            && uri.authority().is_some_and(|a| !a.as_str().contains('@'))
    }) && !s.contains('#')
}
