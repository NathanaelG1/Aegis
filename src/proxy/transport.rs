//! Small HTTPS connector around the project's existing Hyper and Rustls stack.
//! One connection, one request, no redirects, retries, cookies or proxy discovery.
use super::Error;
use axum::http::{HeaderMap, Method, Uri};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use std::{sync::Arc, time::Duration};
use zeroize::Zeroizing;

pub(crate) struct Client {
    pub(super) tls: Arc<ClientConfig>,
    pub(crate) loopback_http: bool,
}
impl Client {
    pub(crate) fn new() -> Result<Self, Error> {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|_| Error::Storage)?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(Self {
            tls: Arc::new(config),
            loopback_http: false,
        })
    }
    pub(crate) fn send(
        &self,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Vec<u8>,
        read_body: bool,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), Error> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| Error::Storage)?;
        runtime.block_on(async {
            tokio::time::timeout(
                Duration::from_secs(30),
                self.send_async(method, uri, headers, body, read_body),
            )
            .await
            .map_err(|_| Error::OutcomeUnknown)?
        })
    }
    async fn send_async(
        &self,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Vec<u8>,
        read_body: bool,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), Error> {
        let authority = uri.authority().ok_or(Error::Invalid)?;
        if authority.as_str().contains('@') {
            return Err(Error::Invalid);
        }
        let host = uri.host().ok_or(Error::Invalid)?.trim_matches(['[', ']']);
        if uri.scheme_str() == Some("http")
            && self.loopback_http
            && host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
        {
            let tcp = tokio::net::TcpStream::connect((host, uri.port_u16().unwrap_or(80)))
                .await
                .map_err(|_| Error::OutcomeUnknown)?;
            return Self::exchange(tcp, method, uri, headers, body, read_body).await;
        }
        if uri.scheme_str() != Some("https") {
            return Err(Error::Invalid);
        }
        let name = ServerName::try_from(host.to_owned()).map_err(|_| Error::Invalid)?;
        let tcp = tokio::net::TcpStream::connect((host, uri.port_u16().unwrap_or(443)))
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        let tls = tokio_rustls::TlsConnector::from(self.tls.clone())
            .connect(name, tcp)
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        Self::exchange(tls, method, uri, headers, body, read_body).await
    }
    async fn exchange<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static>(
        tls: T,
        method: Method,
        uri: Uri,
        headers: HeaderMap,
        body: Vec<u8>,
        read_body: bool,
    ) -> Result<(u16, Zeroizing<Vec<u8>>), Error> {
        let authority = uri.authority().ok_or(Error::Invalid)?;
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .max_buf_size(32768)
            .handshake(TokioIo::new(tls))
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut request = hyper::Request::builder()
            .method(method)
            .uri(uri.path_and_query().map(|v| v.as_str()).unwrap_or("/"))
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| Error::Invalid)?;
        *request.headers_mut() = headers;
        request.headers_mut().insert(
            "host",
            authority.as_str().parse().map_err(|_| Error::Invalid)?,
        );
        request
            .headers_mut()
            .insert("connection", "close".parse().map_err(|_| Error::Invalid)?);
        let mut response = sender
            .send_request(request)
            .await
            .map_err(|_| Error::OutcomeUnknown)?;
        let status = response.status();
        let mut bytes = Zeroizing::new(Vec::new());
        if read_body && status.is_success() {
            while let Some(frame) = response.frame().await {
                let frame = frame.map_err(|_| Error::ResponseDenied)?;
                if let Some(chunk) = frame.data_ref() {
                    if bytes.len() + chunk.len() > 65536 {
                        return Err(Error::ResponseDenied);
                    }
                    bytes.extend_from_slice(chunk);
                }
            }
        }
        Ok((status.as_u16(), bytes))
    }
}

pub(super) fn prompt() -> Result<String, Error> {
    use nix::sys::termios::{self, LocalFlags, SetArg, Termios};
    use std::{
        fs::{File, OpenOptions},
        io::{BufRead, BufReader, Write},
    };
    struct Restore(File, Termios);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = termios::tcsetattr(&self.0, SetArg::TCSANOW, &self.1);
        }
    }
    let mut tty = OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .map_err(|_| Error::Invalid)?;
    let saved = termios::tcgetattr(&tty).map_err(|_| Error::Invalid)?;
    let mut hidden = saved.clone();
    hidden
        .local_flags
        .remove(LocalFlags::ECHO | LocalFlags::ECHONL);
    // Ctrl-C is read as data so normal error cleanup always restores echo.
    hidden.local_flags.remove(LocalFlags::ISIG);
    let restore = Restore(tty.try_clone().map_err(|_| Error::Invalid)?, saved);
    tty.write_all(b"Secret (hidden): ")
        .map_err(|_| Error::Invalid)?;
    termios::tcsetattr(&tty, SetArg::TCSANOW, &hidden).map_err(|_| Error::Invalid)?;
    let mut value = Zeroizing::new(String::new());
    std::io::Read::take(BufReader::new(&tty), 4097)
        .read_line(&mut value)
        .map_err(|_| Error::Invalid)?;
    drop(restore);
    tty.write_all(b"\n").map_err(|_| Error::Invalid)?;
    if value.len() > 4096 || value.contains('\u{3}') {
        return Err(Error::Invalid);
    }
    Ok(value.trim_end_matches(['\r', '\n']).to_owned())
}
