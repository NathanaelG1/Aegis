//! ANSI terminal surface using the existing safe nix termios API.
use super::super::Error;
use nix::sys::termios::{self, SetArg, SpecialCharacterIndices, Termios};
use std::io::{self, IsTerminal, Read, Write};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

const LOGO: [&str; 5] = [
    "   .-------.     _    _____ ____ ___ ____  ",
    "   |  /\\   |    / \\  | ____/ ___|_ _/ ___| ",
    "   | /__\\  |   / _ \\ |  _|| |  _ | |\\___ \\ ",
    "   |       |  / ___ \\| |__| |_| || | ___) |",
    "    '.___.'  /_/   \\_\\_____\\____|___|____/ ",
];
#[derive(PartialEq, Eq)]
pub(super) enum Key {
    Up,
    Down,
    Enter,
    Back,
    Delete,
    Clear,
    Text(char),
    Refresh,
}

pub(super) struct Terminal {
    saved: Termios,
    pub(super) width: usize,
    pub(super) height: usize,
    color: bool,
    queried: Instant,
    paste: Zeroizing<String>,
    paste_invalid: bool,
}
impl Terminal {
    pub(super) fn open() -> Result<Self, Error> {
        if !io::stdin().is_terminal()
            || !io::stdout().is_terminal()
            || std::env::var("TERM").is_ok_and(|v| v == "dumb")
        {
            return Err(Error::Invalid);
        }
        let saved = termios::tcgetattr(io::stdin()).map_err(|_| Error::Invalid)?;
        let mut raw = saved.clone();
        termios::cfmakeraw(&mut raw);
        raw.control_chars[SpecialCharacterIndices::VMIN as usize] = 0;
        raw.control_chars[SpecialCharacterIndices::VTIME as usize] = 1;
        termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &raw).map_err(|_| Error::Invalid)?;
        let mut terminal = Self {
            saved,
            width: 80,
            height: 24,
            color: std::env::var_os("NO_COLOR").is_none(),
            queried: Instant::now(),
            paste: Zeroizing::new(String::new()),
            paste_invalid: false,
        };
        terminal.write("\x1b[?1049h\x1b[?25l\x1b[?2004h")?;
        terminal.size_query()?;
        Ok(terminal)
    }
    fn write(&mut self, value: &str) -> Result<(), Error> {
        let mut out = io::stdout().lock();
        out.write_all(value.as_bytes())
            .and_then(|_| out.flush())
            .map_err(|_| Error::Invalid)
    }
    fn size_query(&mut self) -> Result<(), Error> {
        self.queried = Instant::now();
        self.write("\x1b7\x1b[999;999H\x1b[6n\x1b8")
    }
    fn byte(&self) -> Result<Option<u8>, Error> {
        let mut byte = [0u8];
        match io::stdin().read(&mut byte) {
            Ok(0) => Ok(None),
            Ok(_) => Ok(Some(byte[0])),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => Ok(None),
            Err(_) => Err(Error::Invalid),
        }
    }
    pub(super) fn key(&mut self) -> Result<Key, Error> {
        loop {
            if self.queried.elapsed() > Duration::from_secs(2) {
                self.size_query()?;
            }
            let Some(byte) = self.byte()? else {
                continue;
            };
            return Ok(match byte {
                b'\r' | b'\n' => Key::Enter,
                3 | 4 => Key::Back,
                8 | 127 => Key::Delete,
                21 => Key::Clear,
                27 => {
                    let Some(next) = self.byte()? else {
                        return Ok(Key::Back);
                    };
                    if next != b'[' && next != b'O' {
                        continue;
                    }
                    let mut sequence = String::new();
                    while sequence.len() < 32 {
                        let Some(b) = self.byte()? else {
                            break;
                        };
                        sequence.push(b as char);
                        if (0x40..=0x7e).contains(&b) {
                            break;
                        }
                    }
                    match sequence.as_str() {
                        "A" => Key::Up,
                        "B" => Key::Down,
                        "200~" => {
                            // Pasted newlines never submit forms or activate menus.
                            self.paste.clear();
                            self.paste_invalid = false;
                            let mut complete = false;
                            let mut pending = Zeroizing::new(Vec::new());
                            let deadline = Instant::now() + Duration::from_secs(5);
                            while Instant::now() < deadline {
                                if let Some(b) = self.byte()? {
                                    pending.push(b);
                                    if pending.ends_with(b"\x1b[201~") {
                                        let end = pending.len() - 6;
                                        pending.truncate(end);
                                        for b in pending.iter() {
                                            self.paste_byte(*b);
                                        }
                                        complete = true;
                                        break;
                                    }
                                    if pending.len() > 6 {
                                        let b = pending.remove(0);
                                        self.paste_byte(b);
                                    }
                                }
                            }
                            self.paste_invalid |= !complete;
                            Key::Refresh
                        }
                        s if s.ends_with('R') => {
                            if let Some((h, w)) = s.trim_end_matches('R').split_once(';') {
                                if let (Ok(h), Ok(w)) = (h.parse::<usize>(), w.parse::<usize>()) {
                                    if h >= 8 && w >= 20 {
                                        let height = h.min(200);
                                        let width = w.min(300);
                                        if self.height == height && self.width == width {
                                            continue;
                                        }
                                        self.height = height;
                                        self.width = width;
                                        return Ok(Key::Refresh);
                                    }
                                }
                            }
                            continue;
                        }
                        _ => continue,
                    }
                }
                32..=126 => Key::Text(byte as char),
                _ => continue,
            });
        }
    }
    fn paste_byte(&mut self, byte: u8) {
        if self.paste.len() < 4097 && ((32..=126).contains(&byte) || matches!(byte, b'\r' | b'\n'))
        {
            self.paste.push(byte as char);
        } else {
            self.paste_invalid = true;
        }
    }
    pub(super) fn paint(
        &mut self,
        title: &str,
        hint: &str,
        lines: &[String],
        footer: &str,
    ) -> Result<(), Error> {
        let mut page = String::from("\x1b[H\x1b[2J");
        let cyan = if self.color { "\x1b[1;36m" } else { "" };
        let dim = if self.color { "\x1b[2m" } else { "" };
        let selected = if self.color { "\x1b[1;30;46m" } else { "" };
        let reset = "\x1b[0m";
        if self.height >= 24 && self.width >= 58 {
            for line in LOGO {
                page.push_str(&format!("{cyan}{line}{reset}\r\n"));
            }
        } else {
            page.push_str(&format!("{cyan}  /\\  A E G I S{reset}\r\n"));
        }
        page.push_str(&format!(
            "\r\n{cyan}  {}{reset}\r\n",
            clip(title, self.width - 4)
        ));
        page.push_str(&format!(
            "{dim}  {}{reset}\r\n\r\n",
            clip(hint, self.width - 4)
        ));
        for line in lines.iter().take(self.room()) {
            let style = if line.starts_with("> ") { selected } else { "" };
            page.push_str(&format!(
                "  {style}{}{reset}\r\n",
                clip(line, self.width - 4)
            ));
        }
        page.push_str(&format!(
            "\x1b[{};1H{dim}  {}{reset}",
            self.height,
            clip(footer, self.width - 4)
        ));
        self.write(&page)
    }
    pub(super) fn room(&self) -> usize {
        self.height
            .saturating_sub(if self.height >= 24 && self.width >= 58 {
                11
            } else {
                7
            })
            .max(1)
    }
    pub(super) fn menu(
        &mut self,
        title: &str,
        hint: &str,
        options: &[String],
    ) -> Result<Option<usize>, Error> {
        self.menu_at(title, hint, options, 0)
    }
    pub(super) fn menu_at(
        &mut self,
        title: &str,
        hint: &str,
        options: &[String],
        mut selected: usize,
    ) -> Result<Option<usize>, Error> {
        if options.is_empty() {
            return Ok(None);
        }
        selected = selected.min(options.len() - 1);
        loop {
            self.paste.clear();
            let start = (selected / self.room()) * self.room();
            let rows: Vec<_> = options
                .iter()
                .enumerate()
                .skip(start)
                .take(self.room())
                .map(|(i, s)| format!("{} {}", if i == selected { ">" } else { " " }, s))
                .collect();
            self.paint(
                title,
                hint,
                &rows,
                "Up/Down or j/k  Move    Enter  Select    Esc  Back",
            )?;
            match self.key()? {
                Key::Up | Key::Text('k') => {
                    selected = selected.checked_sub(1).unwrap_or(options.len() - 1)
                }
                Key::Down | Key::Text('j') => selected = (selected + 1) % options.len(),
                Key::Enter => return Ok(Some(selected)),
                Key::Back => return Ok(None),
                _ => {}
            }
        }
    }
    pub(super) fn note(&mut self, title: &str, lines: &[String]) -> Result<(), Error> {
        let mut offset = 0;
        loop {
            // Details, URLs and paths must remain fully reviewable on narrow screens.
            let wrapped: Vec<String> = lines
                .iter()
                .flat_map(|line| {
                    let chars: Vec<_> = line
                        .chars()
                        .map(|c| if c.is_control() { ' ' } else { c })
                        .collect();
                    if chars.is_empty() {
                        vec![String::new()]
                    } else {
                        chars
                            .chunks(self.width - 4)
                            .map(|s| s.iter().collect())
                            .collect()
                    }
                })
                .collect();
            self.paste.clear();
            self.paint(
                title,
                "",
                &wrapped.iter().skip(offset).cloned().collect::<Vec<_>>(),
                "Enter / Esc  Back    Up/Down  Scroll",
            )?;
            match self.key()? {
                Key::Enter | Key::Back => return Ok(()),
                Key::Down => offset = (offset + 1).min(wrapped.len().saturating_sub(1)),
                Key::Up => offset = offset.saturating_sub(1),
                _ => {}
            }
        }
    }
    pub(super) fn field(
        &mut self,
        title: &str,
        hint: &str,
        initial: &str,
        hidden: bool,
        limit: usize,
        validate: impl Fn(&str) -> bool,
    ) -> Result<Option<Zeroizing<String>>, Error> {
        self.paste.clear();
        self.paste_invalid = false;
        let mut value = Zeroizing::new(initial.to_string());
        let mut invalid = false;
        let mut overflow = false;
        loop {
            let shown = if hidden {
                if value.is_empty() {
                    "[ hidden input ]".into()
                } else {
                    "[ value entered - hidden ]".into()
                }
            } else {
                format!(
                    "> {}_",
                    value
                        .chars()
                        .rev()
                        .take(self.width.saturating_sub(9))
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect::<String>()
                )
            };
            let lines = vec![
                shown,
                String::new(),
                if overflow {
                    "Input is too long or unsupported. Ctrl-U clears it.".into()
                } else if invalid {
                    "Please check this value and try again.".into()
                } else {
                    "".into()
                },
            ];
            self.paint(
                title,
                hint,
                &lines,
                "Enter  Continue    Esc  Cancel    Ctrl-U  Clear",
            )?;
            match self.key()? {
                Key::Enter if !overflow && validate(&value) => return Ok(Some(value)),
                Key::Enter => invalid = true,
                Key::Back => return Ok(None),
                Key::Delete => {
                    value.pop();
                    invalid = false;
                    overflow = false;
                }
                Key::Clear => {
                    value.clear();
                    invalid = false;
                    overflow = false;
                }
                Key::Text(c) if value.len() < limit => {
                    value.push(c);
                    invalid = false;
                }
                Key::Refresh => {
                    let available = limit.saturating_sub(value.len());
                    let pasted = self.paste.trim_end_matches(['\r', '\n']);
                    if self.paste_invalid || pasted.len() > available {
                        overflow = true;
                    } else {
                        value.push_str(pasted);
                    }
                    self.paste.clear();
                    self.paste_invalid = false;
                }
                Key::Text(_) => overflow = true,
                _ => {}
            }
        }
    }
}
fn clip(text: &str, width: usize) -> String {
    let safe: String = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect();
    if safe.chars().count() <= width {
        safe
    } else {
        format!(
            "{}...",
            safe.chars()
                .take(width.saturating_sub(3))
                .collect::<String>()
        )
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = self.write("\x1b[0m\x1b[?2004l\x1b[?25h\x1b[?1049l");
        let _ = termios::tcsetattr(io::stdin(), SetArg::TCSANOW, &self.saved);
    }
}
