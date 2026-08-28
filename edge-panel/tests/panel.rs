use std::sync::Arc;

use std::sync::Mutex;

use edge_panel::{
    router, router_with_actions, Actions, AtResult, LogRing, MemoryInbox, PanelError, ProfileBody,
    ProfilesResult, ReportResult, ScanResult, ScannedOperatorBody, UsbResetResult, UssdResult,
};
use edge_store::{LocalMessage, LocalModem};
use http_body_util::BodyExt;
use tower::ServiceExt;

/// Fetch the panel page the way a browser would.
async fn panel_page() -> String {
    let app = router(Arc::new(MemoryInbox::default()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    String::from_utf8(response.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap()
}

/// Where a marker has to be found for its presence to mean anything.
///
/// This panel is one HTML file, so the same bytes carry three unrelated
/// things: code that runs, attributes that bind markup to it, and copy an
/// operator reads. `page.contains(marker)` cannot tell them apart, and T026
/// measured what that costs on this exact file:
///
/// * with all fifteen `/api` call sites deleted, four of the thirteen
///   endpoint assertions were still green — held up by a `<dt>` label, a
///   tooltip and two comments;
/// * with every consequence sentence cut out of the usbnet dialog, all five
///   consequence assertions were still green — held up by the static
///   paragraph above the input box;
/// * `没有发出` went from one occurrence to four, and `/api/esim` from two to
///   ten, as later cards added honest copy. A bare substring marker does not
///   stay a wiring check; it decays into a prose check without anybody
///   touching it.
///
/// So every assertion names the region its marker has to live in.
#[derive(Clone, Copy, Debug)]
enum In {
    /// `#panel-script` with the comments blanked out: behaviour that runs.
    Code,
    /// Inside a `<tag …>`: the attributes that bind markup to that behaviour.
    Tags,
    /// Between tags: the words an operator can read.
    Text,
    /// The two `<style>` blocks.
    Styles,
}

/// The panel cut into those regions, once.
struct Panel {
    /// The whole served page, unchanged, for the few assertions that are
    /// genuinely about the file rather than about one of its regions.
    page: String,
    code: String,
    tags: String,
    text: String,
    styles: String,
}

impl Panel {
    async fn load() -> Panel {
        let page = panel_page().await;
        let script = body_of(&page, "<script id=\"panel-script\">", "</script>").to_string();
        let code = blank_comments(&script);
        // Blanked rather than removed so byte offsets do not move: `body_of`
        // finds the end of a function by the indentation its closer is
        // written at, and a shortened string would slide those closers under
        // each other.
        assert_eq!(
            code.len(),
            script.len(),
            "blanking the comments moved the script's offsets"
        );
        let styles = format!(
            "{}\n{}",
            body_of(&page, "<style id=\"vendor-pico\">", "</style>"),
            body_of(&page, "<style id=\"panel-style\">", "</style>"),
        );
        let (tags, text) = split_tags(&markup_only(&page));
        Panel { page, code, tags, text, styles }
    }

    fn region(&self, place: In) -> &str {
        match place {
            In::Code => &self.code,
            In::Tags => &self.tags,
            In::Text => &self.text,
            In::Styles => &self.styles,
        }
    }

    /// A marker has to appear in its own region, at least once.
    ///
    /// A lower bound rather than T005's exact `== 1`. Exactly-once is the
    /// stronger answer to a marker that also matches its own declaration, but
    /// it fails the day a second, perfectly good call site appears (T026 P10)
    /// — and it was never the property being asserted. Pinning the region is
    /// what makes a lower bound safe: prose, comments and copy are not in the
    /// region, so the count cannot be padded by them, and a marker chosen at
    /// the call site cannot be padded by its declaration either.
    fn wired(&self, place: In, feature: &str, marker: &str) {
        let region = self.region(place);
        assert!(
            region.contains(marker),
            "{feature} is missing: no {marker} in the panel's {place:?} \
             ({} bytes scanned)",
            region.len()
        );
    }
}

/// The page's markup: no comments, and no `<style>` or `<script>` contents.
fn markup_only(page: &str) -> String {
    let mut kept = markup_without_comments(page);
    for block in ["style", "script"] {
        kept = drop_blocks(&kept, block);
    }
    kept
}

/// Everything from `<name` to the matching `</name>`, gone.
fn drop_blocks(text: &str, name: &str) -> String {
    let open = format!("<{name}");
    let close = format!("</{name}>");
    let mut kept = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find(&open) {
        kept.push_str(&rest[..start]);
        rest = match rest[start..].find(&close) {
            Some(end) => &rest[start + end + close.len()..],
            None => "",
        };
    }
    kept.push_str(rest);
    kept
}

/// Markup split into what is inside a tag and what is between tags.
///
/// Quote-aware, because this panel writes `x-show="logHits > logHitsDrawn"`
/// and `x-show="index < 3"`. A scanner that stopped at the first `>` would
/// spill half a tag into the text and then take the rest of the document with
/// it — and it would do that silently, with every assertion still green.
///
/// Text nodes are joined with a newline rather than concatenated, so a phrase
/// cannot be assembled out of two nodes that have a tag between them.
fn split_tags(markup: &str) -> (String, String) {
    let mut tags = String::with_capacity(markup.len());
    let mut text = String::with_capacity(markup.len());
    let mut rest = markup;
    while let Some(at) = rest.find('<') {
        let after = rest[at + 1..].chars().next();
        let opens_a_tag = matches!(after, Some(c) if c.is_ascii_alphabetic() || c == '/' || c == '!');
        if !opens_a_tag {
            text.push_str(&rest[..at + 1]);
            rest = &rest[at + 1..];
            continue;
        }
        text.push_str(&rest[..at]);
        text.push('\n');
        let tag = &rest[at..];
        let mut quote = None;
        let mut end = tag.len();
        for (offset, c) in tag.char_indices() {
            match (quote, c) {
                (None, '"') | (None, '\'') => quote = Some(c),
                (Some(q), c) if c == q => quote = None,
                (None, '>') => {
                    end = offset + 1;
                    break;
                }
                _ => {}
            }
        }
        tags.push_str(&tag[..end]);
        tags.push('\n');
        rest = &tag[end..];
    }
    text.push_str(rest);
    (tags, text)
}

/// The script with its comments blanked out, byte for byte.
///
/// Comments are where this file keeps its reasoning, which means they are
/// also where every phrase an assertion might look for is written down in
/// English and in Chinese. A marker that matches a comment is a check on the
/// documentation, not on the panel.
fn blank_comments(js: &str) -> String {
    enum S {
        Code,
        Line,
        Block,
        Quoted(char),
        Regex,
        RegexClass,
    }
    let mut out = String::with_capacity(js.len());
    let mut state = S::Code;
    // The last character that was not whitespace, which is what says whether a
    // `/` opens a regular expression or divides.
    let mut previous = ' ';
    let mut escaped = false;
    let mut star = false;
    let mut chars = js.chars().peekable();
    while let Some(c) = chars.next() {
        match state {
            S::Code => match c {
                '/' if chars.peek() == Some(&'/') => {
                    chars.next();
                    out.push_str("  ");
                    state = S::Line;
                }
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    out.push_str("  ");
                    state = S::Block;
                    star = false;
                }
                '/' if opens_a_regex(previous) => {
                    out.push(c);
                    previous = c;
                    state = S::Regex;
                }
                '"' | '\'' | '`' => {
                    out.push(c);
                    previous = c;
                    state = S::Quoted(c);
                }
                _ => {
                    out.push(c);
                    if !c.is_whitespace() {
                        previous = c;
                    }
                }
            },
            S::Line => {
                if c == '\n' {
                    out.push(c);
                    state = S::Code;
                } else {
                    blank(&mut out, c);
                }
            }
            S::Block => {
                blank(&mut out, c);
                if star && c == '/' {
                    state = S::Code;
                }
                star = c == '*';
            }
            S::Quoted(quote) => {
                out.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == quote {
                    state = S::Code;
                }
            }
            S::Regex => {
                out.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '[' {
                    state = S::RegexClass;
                } else if c == '/' {
                    state = S::Code;
                }
            }
            S::RegexClass => {
                out.push(c);
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == ']' {
                    state = S::Regex;
                }
            }
        }
    }
    out
}

/// Spaces, one per byte, so a comment full of Chinese does not shorten the
/// string it is blanked out of.
fn blank(out: &mut String, c: char) {
    if c == '\n' {
        out.push(c);
    } else {
        for _ in 0..c.len_utf8() {
            out.push(' ');
        }
    }
}

/// Whether a `/` here starts a regular expression rather than dividing.
fn opens_a_regex(previous: char) -> bool {
    matches!(
        previous,
        ' ' | '(' | ',' | '=' | ':' | '[' | '!' | '&' | '|' | '?' | '{' | '}' | ';' | '+' | '-' | '*' | '%' | '^' | '~' | '<' | '>'
    )
}

/// Drop HTML comments before scanning the markup.
///
/// The page documents the no-external-references rule in a comment, so a
/// scanner that reads inert text would be tripped by the rule's own
/// description. A comment cannot load anything, which is why ignoring it
/// costs the check nothing.
fn markup_without_comments(page: &str) -> String {
    let mut kept = String::with_capacity(page.len());
    let mut rest = page;
    while let Some(start) = rest.find("<!--") {
        kept.push_str(&rest[..start]);
        rest = match rest[start..].find("-->") {
            Some(end) => &rest[start + end + 3..],
            None => "",
        };
    }
    kept.push_str(rest);
    kept
}

/// Every `<name ...>` opening tag in the markup, as written.
fn opening_tags<'a>(markup: &'a str, name: &str) -> Vec<&'a str> {
    let needle = format!("<{name}");
    let mut found = Vec::new();
    let mut rest = markup;
    while let Some(start) = rest.find(&needle) {
        let tag = &rest[start..];
        let end = tag.find('>').map(|at| at + 1).unwrap_or(tag.len());
        found.push(&tag[..end]);
        rest = &tag[end..];
    }
    found
}

/// This file's own negative control.
///
/// Every pinned assertion below rests on the four regions being cut apart. A
/// comment stripper that quietly stopped stripping, or a tag scanner that
/// fell out of step at the first `>` inside an attribute, would turn every
/// one of them back into the substring search it replaced — and it would do
/// it in silence, with the whole suite still green. A harness that reports
/// green on everything has measured nothing, so the regions are checked here
/// against text that is known to be in exactly one of them.
#[tokio::test]
async fn the_regions_this_file_asserts_in_are_actually_cut_apart() {
    let panel = Panel::load().await;

    // Code survives; both comment forms do not.
    assert!(panel.code.contains("const CONSOLE_KEEP = 200;"), "the stripper ate the code");
    assert!(
        !panel.code.contains("Where the corpus disagreed"),
        "a block comment is still in the code region"
    );
    assert!(
        !panel.code.contains("A verdict is about one card"),
        "a line comment is still in the code region"
    );
    // The endpoint names that appear only as prose stay out of the code.
    assert!(
        !panel.code.contains("`/api/esim` still showed the profile disabled"),
        "the code region still carries the comment that names an endpoint"
    );

    // Attributes and copy are on opposite sides.
    assert!(panel.tags.contains("x-data=\"panel\""), "the tag scanner found no tags");
    assert!(
        panel.tags.contains("x-show=\"logHits > logHitsDrawn\""),
        "the tag scanner stopped at a `>` written inside an attribute"
    );
    assert!(
        panel.tags.contains("x-show=\"index < 3\""),
        "the tag scanner stopped at a `<` written inside an attribute"
    );
    assert!(!panel.tags.contains("只读探针"), "a text node leaked into the tags");
    assert!(panel.text.contains("只读探针"), "the text region lost the copy");
    assert!(!panel.text.contains("x-text="), "an attribute leaked into the text");
    assert!(
        !panel.text.contains("const CONSOLE_KEEP"),
        "the script block leaked into the text"
    );
    assert!(
        !panel.text.contains("--pico-background-color"),
        "a style block leaked into the text"
    );

    // The stylesheets are their own region.
    assert!(panel.styles.contains(".con-entry.is-fail"), "the panel's own sheet is missing");
    assert!(panel.styles.contains("--pico-background-color"), "Pico's sheet is missing");
}

/// Command controls acknowledge a press before their request returns. Selection
/// controls deliberately do not move: their pressed state already has a stable
/// selected treatment.
#[tokio::test]
async fn command_buttons_have_press_feedback_while_selection_controls_stay_stable() {
    let panel = Panel::load().await;
    let motion = body_of(
        &panel.styles,
        ".btn, .chip-probe, .con-act, .log-copy, .jump {",
        "}",
    );
    assert!(
        motion.contains("transform var(--pico-transition)"),
        "command feedback no longer eases with the panel's shared transition"
    );
    let press_start = panel
        .styles
        .find(".btn:not(:disabled):not([aria-busy=\"true\"]):active,")
        .expect("the panel has no command press rule");
    let press_rule = &panel.styles[press_start..];
    let press = &press_rule[..press_rule
        .find('}')
        .expect("the panel command press rule has no closing brace")];
    assert!(
        press.contains("transform:translateY(1px)"),
        "a command button no longer moves by one pixel"
    );
    for control in [".btn", ".chip-probe", ".con-act", ".log-copy", ".jump"] {
        assert!(
            press.contains(&format!(
                "{control}:not(:disabled):not([aria-busy=\"true\"]):active"
            )),
            "{control} no longer has a busy-safe press state"
        );
    }
    for control in [".modem", ".chip-pick", ".tab", ".lvl-chip"] {
        assert!(
            !press.contains(control),
            "{control} is a selection control and must not shift while pressed"
        );
    }
}

/// Nothing on this page may make the browser reach off the page.
///
/// `the_panel_loads_nothing_from_outside_itself` below covers the shapes a
/// stylesheet uses. It is green for `<img src="https://…">`, for `<iframe
/// src>`, for `fetch("https://…")` and for `new Image().src` — T026 ported it
/// to Node and measured all four. Every one of those is a shape the tabs
/// still to be built reach for first: a flag next to an operator, a carrier
/// logo, a map tile next to a cell. On a machine with no route out they do
/// not degrade, they hang.
///
/// The check that did catch all four was a browser run under a DNS blackhole,
/// and it lived in a Worker's scratchpad, so each card had to rebuild it and
/// the repository kept the weaker one. This is that check, written down where
/// `cargo test` runs it.
///
/// It is still worth loading the page in a real browser before a release —
/// that is the only thing that observes what is actually requested rather
/// than what is written. The invocation, for whoever does it next:
///
/// ```text
/// chrome --headless=new --remote-debugging-port=9222 \
///        --host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1" \
///        --proxy-server=direct:// http://127.0.0.1:<port>/
/// ```
///
/// serving the built tree's own `index.html` from `127.0.0.1`, proxying only
/// `GET /api/*` to the edge daemon, and refusing every other method — so no
/// verification run can put a write on a modem. Then list every URL the page
/// requested: the count of external ones is the measurement.
#[tokio::test]
async fn the_panel_asks_the_browser_for_nothing_outside_the_page() {
    let panel = Panel::load().await;

    // 1. Every attribute that makes the browser fetch something.
    let mut loaders = 0;
    for (name, value) in attributes(&panel.tags) {
        let attribute = name
            .trim_start_matches(':')
            .trim_start_matches("x-bind:")
            .to_ascii_lowercase();
        if !LOADING_ATTRIBUTES.contains(&attribute.as_str()) {
            continue;
        }
        loaders += 1;
        assert!(
            is_local(&value),
            "<… {name}=\"{value}\"> would be fetched from somewhere other than this page"
        );
    }
    assert!(
        loaders > 0,
        "no loading attribute found at all, so this half of the check measured nothing"
    );

    // 2. Every string the panel's own code could hand to a loader. A URL with
    //    a host in it has no other use in a page that is only allowed to talk
    //    to the machine it was served from, so the literal is the check —
    //    which also covers the loaders that are built rather than written,
    //    `new Image().src = …` being the one T026 used.
    let literals = string_literals(&panel.code);
    assert!(
        literals.len() > 100 && literals.iter().any(|literal| literal == "application/json"),
        "the literal scanner found {} strings and not the one the panel posts with, \
         so it is not reading the code",
        literals.len()
    );
    for literal in &literals {
        assert!(
            !literal.contains("://") && !literal.starts_with("//"),
            "the panel's code carries an absolute URL: {literal}"
        );
    }

    // 3. The vendor blocks are pasted in verbatim and are not edited here, so
    //    they are checked for the constructs rather than for the literals:
    //    Alpine names its own plugin documentation in an error message, and a
    //    string in a diagnostic is not a request.
    let vendor = format!(
        "{}\n{}",
        body_of(&panel.page, "<style id=\"vendor-pico\">", "</style>"),
        body_of(&panel.page, "<script id=\"vendor-alpine\">", "</script>"),
    );
    for shape in [
        "fetch(\"http", "fetch('http", "fetch(`http", "src=\"http", "src='http",
        ".src = \"http", ".src=\"http", "url(http", "url(\"http", "url('http",
        "importScripts(", "new WebSocket(", "new EventSource(", "sendBeacon(",
    ] {
        assert!(
            !vendor.contains(shape),
            "a vendor block reaches off the page: {shape}"
        );
    }
}

/// The attributes that make a browser go and get something.
///
/// `content` is in the list for `<meta http-equiv="refresh" content="0;url=…">`,
/// which is a navigation rather than a subresource but leaves the page just
/// the same. The two `content` attributes this page already has carry a
/// viewport and a colour, and neither has a host in it.
const LOADING_ATTRIBUTES: [&str; 13] = [
    "src", "srcset", "imagesrcset", "href", "poster", "data", "action", "formaction",
    "background", "ping", "manifest", "xlink:href", "content",
];

/// Whether a URL stays on the page it was written in.
fn is_local(value: &str) -> bool {
    let value = value.trim();
    if value.starts_with("//") || value.contains("://") {
        return false;
    }
    match value.split_once(':') {
        // A scheme, and only one of them keeps the bytes inside the file.
        Some((scheme, _))
            if !scheme.is_empty()
                && scheme
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.')
                && scheme.chars().next().is_some_and(|c| c.is_ascii_alphabetic()) =>
        {
            scheme.eq_ignore_ascii_case("data")
        }
        _ => true,
    }
}

/// Every `name="value"` in a run of tags.
fn attributes(tags: &str) -> Vec<(String, String)> {
    let mut found = Vec::new();
    for tag in tags.lines() {
        let bytes: Vec<char> = tag.chars().collect();
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at] != '=' || at + 1 >= bytes.len() {
                at += 1;
                continue;
            }
            let quote = bytes[at + 1];
            if quote != '"' && quote != '\'' {
                at += 1;
                continue;
            }
            let mut start = at;
            while start > 0
                && (bytes[start - 1].is_ascii_alphanumeric()
                    || matches!(bytes[start - 1], '-' | ':' | '.' | '_' | '@'))
            {
                start -= 1;
            }
            let name: String = bytes[start..at].iter().collect();
            let mut end = at + 2;
            while end < bytes.len() && bytes[end] != quote {
                end += 1;
            }
            let value: String = bytes[at + 2..end.min(bytes.len())].iter().collect();
            if !name.is_empty() {
                found.push((name, value));
            }
            at = end + 1;
        }
    }
    found
}

/// Every string literal in the panel's code.
///
/// Regular expressions are stepped over rather than read: this file writes
/// `/^at\+qcfg\s*=\s*"usbnet"\s*,\s*(\d+)/i`, and a scanner that took those
/// two quotes for a string would spend the rest of the file one state behind.
fn string_literals(code: &str) -> Vec<String> {
    enum S {
        Code,
        Quoted(char),
        Regex,
        RegexClass,
    }
    let mut found = Vec::new();
    let mut state = S::Code;
    let mut current = String::new();
    let mut previous = ' ';
    let mut escaped = false;
    for c in code.chars() {
        match state {
            S::Code => match c {
                '"' | '\'' | '`' => {
                    state = S::Quoted(c);
                    current.clear();
                    previous = c;
                }
                '/' if opens_a_regex(previous) => state = S::Regex,
                _ => {
                    if !c.is_whitespace() {
                        previous = c;
                    }
                }
            },
            S::Quoted(quote) => {
                if escaped {
                    escaped = false;
                    current.push(c);
                } else if c == '\\' {
                    escaped = true;
                } else if c == quote {
                    found.push(current.clone());
                    state = S::Code;
                } else {
                    current.push(c);
                }
            }
            S::Regex => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == '[' {
                    state = S::RegexClass;
                } else if c == '/' {
                    state = S::Code;
                }
            }
            S::RegexClass => {
                if escaped {
                    escaped = false;
                } else if c == '\\' {
                    escaped = true;
                } else if c == ']' {
                    state = S::Regex;
                }
            }
        }
    }
    found
}

/// The panel must load nothing from anywhere.
///
/// It is served over the site LAN to a machine that may have no route to the
/// internet at all. A linked stylesheet or a CDN script is not a dependency
/// here, it is an outage: the operator standing next to a wedged modem would
/// get an unstyled page with no behaviour at exactly the moment the panel is
/// the only tool they have. This is the assertion that keeps that true after
/// somebody reaches for a charting library.
#[tokio::test]
async fn the_panel_loads_nothing_from_outside_itself() {
    let page = panel_page().await;
    let markup = markup_without_comments(&page).to_lowercase();

    for tag in opening_tags(&markup, "script") {
        assert!(!tag.contains("src="), "script loads something external: {tag}");
    }
    for tag in opening_tags(&markup, "link") {
        assert!(
            tag.contains("href=\"data:"),
            "link points somewhere other than an inline data: uri: {tag}"
        );
    }
    assert!(!markup.contains("@import"), "css imports another sheet");
    assert!(!markup.contains("src=\"//"), "protocol-relative script source");
    assert!(!markup.contains("href=\"//"), "protocol-relative link target");

    // Fonts, icons and images all have to be inline too, so every url() in the
    // stylesheets has to resolve to a data: uri.
    let mut scanned = 0;
    let mut rest = markup.as_str();
    while let Some(at) = rest.find("url(") {
        let argument = rest[at + 4..].trim_start_matches(['"', '\'']);
        assert!(
            argument.starts_with("data:"),
            "stylesheet fetches something: url({}…)",
            argument.chars().take(40).collect::<String>()
        );
        scanned += 1;
        rest = &rest[at + 4..];
    }
    assert!(scanned > 0, "no url() found at all, so this check measured nothing");
}

/// The rule above is trivially satisfiable by shipping no framework, so this
/// asserts the frameworks are in fact there — inlined rather than dropped.
#[tokio::test]
async fn the_panel_carries_its_framework_inline() {
    let page = panel_page().await;
    assert!(page.contains("id=\"vendor-pico\""), "no inline Pico block");
    assert!(page.contains("Pico CSS"), "Pico's own banner is missing");
    assert!(page.contains("--pico-background-color"), "Pico's variables are missing");
    assert!(page.contains("id=\"vendor-alpine\""), "no inline Alpine block");
    assert!(page.contains("_x_dataStack"), "Alpine's runtime is missing");
    assert!(page.contains("alpine:init"), "the panel never registers its component");
    // Alpine self-starts, so the component has to be registered before it runs.
    let component = page.find("id=\"panel-script\"").expect("panel script");
    let alpine = page.find("id=\"vendor-alpine\"").expect("alpine script");
    assert!(component < alpine, "Alpine starts before the panel registers its component");
}

/// Every `/api` path the panel's code actually asks the browser for.
///
/// Parsed out of the call rather than searched for in the page. The endpoint
/// names are all over this panel as copy — a `<dt>/api/esim 回读</dt>` in the
/// switch receipt, a filter's tooltip that admits `/api/logs` carries no
/// level, a comment explaining where a cached number came from — and a
/// substring search cannot tell any of that from a call.
///
/// A path counts only as the literal first argument of `fetch(` or
/// `this.post(`, and its query string is cut off because that is not the
/// route. Splitting on the exact path is also what tells `/api/esim` from
/// `/api/esim/switch` and `/api/ussd` from `/api/ussd/cancel`: under a
/// substring search the shorter of each pair is satisfied by the longer, so
/// the eSIM readback could be deleted outright with the suite still green.
fn api_call_sites(code: &str) -> Vec<String> {
    let mut found = Vec::new();
    for opener in ["fetch(\"", "this.post(\""] {
        let mut rest = code;
        while let Some(at) = rest.find(opener) {
            let tail = &rest[at + opener.len()..];
            let end = tail.find('"').unwrap_or(0);
            found.push(tail[..end].split('?').next().unwrap_or("").to_string());
            rest = &tail[end..];
        }
    }
    found
}

/// Reshaping the page must not quietly orphan an endpoint.
///
/// `/api/restart` is deliberately absent: it had no caller in the panel before
/// this layout either, so wiring one would be adding an action rather than
/// moving one. It is asserted absent rather than merely left out.
#[tokio::test]
async fn every_endpoint_the_panel_used_is_still_reachable_from_the_page() {
    let panel = Panel::load().await;
    let sites = api_call_sites(&panel.code);
    assert!(
        sites.len() >= 13,
        "the call-site scan found {} calls, which is fewer than there are endpoints — \
         it has stopped reading the code",
        sites.len()
    );

    for endpoint in [
        "/api/status",
        "/api/logs",
        "/api/messages",
        "/api/send",
        "/api/at",
        "/api/report",
        "/api/esim",
        "/api/esim/switch",
        "/api/scan",
        "/api/ussd",
        "/api/ussd/cancel",
        "/api/radio",
        "/api/usb-reset",
    ] {
        assert!(
            sites.iter().any(|path| path == endpoint),
            "nothing on the page calls {endpoint}: the {} calls it does make are {sites:?}",
            sites.len()
        );
    }

    // The routes `lib.rs` serves, and nothing else. A path that is not one of
    // them is a call that answers 404 at the moment somebody needs it.
    for site in &sites {
        assert!(
            [
                "/api/status", "/api/logs", "/api/messages", "/api/send", "/api/at",
                "/api/report", "/api/esim", "/api/esim/switch", "/api/scan", "/api/ussd",
                "/api/ussd/cancel", "/api/radio", "/api/usb-reset", "/api/restart",
            ]
            .contains(&site.as_str()),
            "the panel calls {site}, which the daemon does not serve"
        );
    }
    assert!(
        !sites.iter().any(|path| path == "/api/restart"),
        "the panel now restarts a modem, which it never did before this layout"
    );

    // Both indirections are named, so a third one cannot appear and take a
    // request out of this scan's sight.
    assert_eq!(
        panel.code.matches("this.post(").count(),
        panel.code.matches("this.post(\"").count(),
        "a POST is aimed at something other than a literal path"
    );
    let helper = body_of(&panel.code, "async post(path, body) {", "\n        },");
    assert!(
        helper.contains("await fetch(path, {"),
        "the one fetch that takes a variable is no longer the post helper"
    );
    assert_eq!(
        panel.code.matches("fetch(").count() - panel.code.matches("fetch(\"").count(),
        1,
        "a fetch is built from something other than a literal path"
    );
}

/// Nothing on this panel calls itself unfinished any more.
///
/// While the migration was running, a section that had not been restyled yet
/// had to name the card that would restyle it — a placeholder saying only
/// "coming soon" is how a migration loses a feature without anybody noticing it
/// went. Every one of those cards has now landed, so the assertion inverts: a
/// note left behind after the work is done is worse than no note, because it
/// tells the next reader that a finished surface is a stub.
///
/// The `panel-note` class goes with them. Leaving the styling for a
/// placeholder nobody renders is an invitation to add another one silently.
#[tokio::test]
async fn no_section_still_calls_itself_unfinished() {
    let panel = Panel::load().await;
    for done in ["T002", "T003", "T004", "T005", "T006"] {
        assert!(
            !panel.page.contains(done),
            "a finished tab still calls itself unfinished: {done}"
        );
    }
    assert!(
        !panel.tags.contains("class=\"panel-note\""),
        "a placeholder note is still rendered somewhere on the page"
    );
    assert!(
        !panel.styles.contains(".panel-note"),
        "the placeholder style outlived the last placeholder, so the next one can be added \
         without anybody having to write a card number"
    );
}

/// Everything the console card promised, pinned to the thing that implements
/// it. Markers rather than wording: the copy will keep changing and the
/// mechanism should not.
#[tokio::test]
async fn the_console_has_what_a_debugging_console_needs() {
    let panel = Panel::load().await;
    // Each marker names where the feature is *wired up*, not where it is
    // defined, and is asserted in the region that wiring has to live in.
    for (feature, place, marker) in [
        ("one block per command", In::Tags, "class=\"con-entry\""),
        ("each block carries its own clock", In::Tags, "x-text=\"clock(entry.at)\""),
        ("a failed exchange is marked as one", In::Styles, ".con-entry.is-fail"),
        ("the tone is actually set on a failure", In::Code, "entry.tone = \"is-fail\""),
        ("command history", In::Tags, "@keydown.arrow-up.prevent=\"historyBack()\""),
        ("history keeps the half-written line", In::Code, "this.consoleDraft = this.consoleInput;"),
        ("a past command can be put back in the box", In::Tags, "@click=\"recall(entry)\""),
        ("copy one exchange", In::Tags, "@click=\"copyEntry(entry, $event.currentTarget)\""),
        ("copy the whole transcript", In::Tags, "@click=\"copyConsole($event.currentTarget)\""),
        // The panel is opened at http://<lan-ip>:8743 far more often than at
        // localhost, and that is not a secure context, so this is the path
        // that actually runs on site rather than a courtesy to old browsers.
        ("copy without a secure context", In::Code, "execCommand(\"copy\")"),
        ("the quick probes are labelled read-only", In::Text, "只读探针"),
        ("an open USSD session is visible", In::Tags, "class=\"con-ussd\""),
    ] {
        panel.wired(place, feature, marker);
    }

    // Three of these were measured green with the wiring deleted, because the
    // marker matched something else that was still there. Each one is now
    // pinned inside the block that has to do the work.
    let slash = body_of(&panel.code, "if (event.key === \"/\") {", "\n          }");
    assert!(
        slash.contains("this.focusCommand();"),
        "the / key does not focus the command box: `recall()` calls focusCommand too, \
         so the bare name stayed green with this binding deleted"
    );
    let escape = body_of(&panel.code, "if (event.key === \"Escape\") {", "\n          }");
    assert!(
        escape.contains("this.cancelInput();"),
        "Esc does not cancel what is being typed"
    );

    let new_entry = body_of(&panel.code, "newEntry(kind, title, titleCls) {", "\n        },");
    assert!(
        new_entry.contains("const over = this.consoleLog.length - CONSOLE_KEEP;"),
        "the transcript is not measured against its cap: `const CONSOLE_KEEP` is a \
         declaration, and it stayed green with the eviction deleted"
    );
    assert!(
        new_entry.contains("this.consoleLog.splice(0, over);"),
        "nothing evicts the oldest entries, so the transcript grows without a bound"
    );
    assert!(
        new_entry.contains("this.consoleDropped += over;"),
        "eviction is not reported, so entries would leave without a trace"
    );
}

/// `AT+QCFG="usbnet"` is the one command in this box that takes away the port
/// the undo would have to travel on.
///
/// On these EC20s it applies on the spot rather than at the next restart, and
/// every mode but rmnet has no QMI control port — which is how the agent finds
/// a module at all. So the stick leaves the inventory immediately and the
/// panel can no longer reach it. There is no `/api` route for this: the
/// daemon's `set_usbnet_mode` is a cloud-dispatched command, so the only way
/// to reach it from the panel is to type it, and the only place a guard can
/// sit is on the command itself.
#[tokio::test]
async fn the_console_confirms_the_command_that_removes_the_module() {
    let panel = Panel::load().await;
    // The call site, not the declaration: `function guardFor(command)` matches
    // a bare `guardFor(command)` too, so that spelling stayed green with the
    // only caller deleted.
    let typed = body_of(&panel.code, "async runAt(command) {", "\n        },");
    assert!(
        typed.contains("const tripped = guardFor(command);"),
        "nothing checks a typed command against the guard list"
    );
    assert!(
        typed.contains("!confirm(tripped.guard.ask("),
        "the guard does not ask before the command goes out"
    );
    assert!(
        typed.find("guardFor(command)") < typed.find("this.post(\"/api/at\""),
        "the guard is consulted after the command has already gone out"
    );

    // Asking is worth nothing if the dialog does not say what will happen —
    // and the words have to be in the dialog. T026 emptied every consequence
    // sentence out of this constructor and watched all five assertions stay
    // green, held up by the static paragraph above the input box. That
    // paragraph is a good thing and is asserted separately below; what it is
    // not is evidence that the dialog says anything at all.
    let dialog = body_of(&panel.code, "ask(command, imei, found) {", "\n        },");
    for consequence in ["立即生效", "重新枚举", "cdc-wdm", "从机队里消失", "rmnet"] {
        assert!(
            dialog.contains(consequence),
            "the confirmation never mentions {consequence}"
        );
    }

    // On screen before anybody types, too: a consequence that only appears
    // inside the dialog has arrived after the decision that opened it.
    let ahead = body_of(&panel.page, "<p class=\"con-guard\">", "</p>");
    for consequence in ["立即生效", "重新枚举", "cdc-wdm", "从机队里消失"] {
        assert!(
            ahead.contains(consequence),
            "the console does not say {consequence} until the dialog is already open"
        );
    }

    assert!(
        typed.contains("refused.meta = \"没有发出\";"),
        "a refused command leaves no trace saying it was not sent — and the bare phrase \
         is now on the page four times, so it is no longer evidence of this one"
    );
}

/// The guard has to fire on the write and stay out of the way of the read.
///
/// `AT+QCFG="usbnet"` with no value is a query and changes nothing; making an
/// operator confirm it would train them to dismiss the dialog, which is how a
/// guard stops working. The comma in the pattern is what separates the two.
#[tokio::test]
async fn the_usbnet_guard_fires_on_the_write_not_the_read() {
    let panel = Panel::load().await;
    assert!(
        panel.code.contains("\"usbnet\"\\s*,\\s*(\\d+)"),
        "the guard pattern does not require a value, so it also traps the query form"
    );
    assert!(
        panel.code.contains("const USBNET_MODES"),
        "the dialog cannot name the mode it is switching to"
    );
}

/// Every action that takes the module off the air asks before it does it, and
/// a refusal sends nothing.
///
/// The guard T004 built sits on the command string, which means it only ever
/// covered the box somebody types into. Four of the five actions on this
/// panel that take a module away do not go through a command string at all —
/// they go through an endpoint — and nothing in this file had noticed. This
/// asserts the shape they share: ask, return on a refusal, and only then
/// send. The wording each one uses is asserted where that wording lives.
#[tokio::test]
async fn every_action_that_takes_the_module_off_the_air_asks_first() {
    let panel = Panel::load().await;
    for (action, opening, ask) in [
        ("the radio switch", "async toggleRadio(button) {", "confirm(radioAsk("),
        (
            "a profile switch",
            "async switchProfile(iccid, enable, button) {",
            "confirm(esimAsk(",
        ),
        ("a full-band scan", "async runScan(button) {", "confirm(scanAsk("),
        ("a USB re-enumeration", "async usbReset(button) {", "confirm("),
        ("a guarded typed command", "async runAt(command) {", "confirm(tripped.guard.ask("),
    ] {
        let body = body_of(&panel.code, opening, "\n        },");
        let asked = body
            .find(ask)
            .unwrap_or_else(|| panic!("{action} sends without asking: no {ask}"));
        let sent = body
            .find("this.post(\"/api/")
            .unwrap_or_else(|| panic!("{action} no longer posts anything"));
        assert!(asked < sent, "{action} goes out before anybody is asked");
        assert!(
            body[asked..sent].contains("return;"),
            "{action} carries on after a refusal, so the dialog only delays it"
        );
    }
}

/// Taking the radio down says what it costs, and a refusal leaves a trace.
///
/// `/api/radio` had a bare `confirm("关闭 … 的射频？")` in front of it: a
/// question with not one consequence in it. The consequences are not invented
/// for the dialog, they are what this repository already says about this
/// operation, and the reasons are written out beside `radioAsk` in the page.
#[tokio::test]
async fn taking_the_radio_down_says_what_it_costs() {
    let panel = Panel::load().await;
    let dialog = body_of(&panel.code, "function radioAsk(imei, goOnline) {", "\n    }");
    for consequence in [
        // The mechanism, because the operator will read `+CFUN` in the status
        // bar and conclude the panel sent one.
        "LowPower",
        "不是 AT+CFUN",
        // What it costs.
        "立刻脱网",
        "收不到短信",
        "从机队里消失",
        // And why the way back is not a certainty.
        "没有人能物理接触",
        "+CFUN: 7",
    ] {
        assert!(
            dialog.contains(consequence),
            "the radio dialog never mentions {consequence}"
        );
    }
    assert!(
        dialog.contains("Online"),
        "the dialog cannot tell the operator what bringing it back does"
    );

    // On screen before anybody clicks, next to the button itself.
    let ahead = body_of(&panel.page, "<p class=\"danger-note\">", "</p>");
    assert!(
        ahead.contains("从机队消失"),
        "the danger zone does not say what its buttons do until one is pressed"
    );

    let body = body_of(&panel.code, "async toggleRadio(button) {", "\n        },");
    assert!(
        body.contains("refused.meta = \"没有发出 —— 射频没有被碰过\";"),
        "a refused radio switch leaves no trace saying it was not sent"
    );
}

/// Restyling the console must not add a command the panel never sent.
///
/// The quick row is the panel's only list of commands it issues by itself, and
/// its whole design is that every one of them is a query. A convenience button
/// added here is a new action rather than a moved one — including a usbnet one,
/// however useful it would look next to the guard above.
#[tokio::test]
async fn the_console_issues_no_command_the_panel_did_not_issue_before() {
    let panel = Panel::load().await;
    // Past the declaration itself: `const QUICK = [` carries an `=` of its own,
    // and the count below is what proves no probe writes anything.
    let head = "const QUICK = [";
    let start = panel.code.find(head).expect("no quick probe list") + head.len();
    let end = start + panel.code[start..].find("];").expect("unterminated quick probe list");
    let quick = &panel.code[start..end];

    for command in [
        "AT+CSQ",
        "AT+CREG?",
        "AT+CEREG?",
        "AT+COPS?",
        "AT+CPIN?",
        "AT+QCCID",
        "AT+CIMI",
        "AT+CNUM",
        "AT+QGMR",
        "AT+CSCA?",
        "AT+QCFG=\"ims\"",
    ] {
        assert!(quick.contains(command), "the quick row lost {command}");
    }
    assert_eq!(
        quick.matches("AT+").count(),
        11,
        "the quick row has gained or lost a probe"
    );
    assert!(
        !quick.contains("usbnet"),
        "the quick row would now write a usbnet mode on one click"
    );
    // Every one of them is a query: a `=` that is not part of `="…"` would be
    // a write. `AT+QCFG="ims"` is the only `=` the list is allowed to carry.
    assert_eq!(
        quick.matches('=').count(),
        1,
        "a quick probe now assigns something"
    );
}

/// Where an unaimed command lands is neither obvious nor harmless.
///
/// With no IMEI the daemon takes the first AT control port it finds
/// (`at_port_by_imei` in edge-bin), so the reply can come back from a stick
/// nobody was looking at. The console says so rather than leaving the target
/// blank.
#[tokio::test]
async fn the_console_says_where_an_unaimed_command_lands() {
    let panel = Panel::load().await;
    // The readout the operator looks at, not merely the phrase somewhere on
    // the page: the usbnet dialog says the same thing, so a bare substring
    // stayed green with the readout itself cut back to "未选模组".
    panel.wired(
        In::Tags,
        "the console does not say where a command with no modem selected goes",
        "未选模组 · 命令交给第一个应答的控制口",
    );
}

/// Esc must not claim to do something it cannot.
///
/// Once a command is on the wire the modem has it, and abandoning this end of
/// the request would only hide the reply — so the panel says what Esc actually
/// cancels instead of implying it can call a command back.
#[tokio::test]
async fn the_console_says_what_esc_does_not_do() {
    let panel = Panel::load().await;
    panel.wired(
        In::Text,
        "the console lets Esc look like it aborts a command in flight",
        "已经发出的命令收不回来",
    );
}

/// An open USSD session has to stay cancellable.
///
/// Changing the AT/USSD dropdown used to clear `ussdOpen`, which hid the only
/// control that calls `/api/ussd/cancel` — leaving a session open on the
/// network with nothing on the panel able to close it, while `lib.rs` says an
/// abandoned session keeps the network waiting and blocks the next request.
/// The pre-refactor panel did this too (`$("ussd-cancel").hidden = true` in its
/// mode-change listener), so this is a deliberate departure from moving the
/// section across untouched, not a regression being repaired.
#[tokio::test]
async fn an_open_ussd_session_survives_a_change_of_command_mode() {
    let panel = Panel::load().await;
    panel.wired(In::Tags, "nothing cancels a USSD session", "@click=\"cancelUssd()\"");
    assert!(
        panel.code.contains("this.post(\"/api/ussd/cancel\""),
        "the cancel control is bound to nothing that cancels"
    );
    assert!(
        !panel.tags.contains("@change=\"ussdOpen = false\""),
        "changing the command mode still forgets an open USSD session"
    );
}

/// The text between an opening line and the first line that closes it at the
/// indentation the closer is written at.
///
/// Used to ask *where inside a function* something happens. "The page contains
/// a readback" is a much weaker statement than "the readback is reached from
/// both branches of the send", and only the second one is the property that
/// keeps a false success off the screen.
fn body_of<'a>(page: &'a str, opening: &str, closing: &str) -> &'a str {
    let start = page
        .find(opening)
        .unwrap_or_else(|| panic!("the page has no {opening}"));
    let rest = &page[start + opening.len()..];
    let end = rest
        .find(closing)
        .unwrap_or_else(|| panic!("{opening} is never closed by {closing}"));
    &rest[..end]
}

/// Everything the eSIM card promised, pinned to the wiring that implements it.
///
/// T005 asserted each of these appeared **exactly once**, which was the right
/// answer to the console card's three assertions that stayed green after
/// their only call site was deleted. It carries a failure mode of its own
/// (T026 P10): the second legitimate call site turns the check red for a
/// reason that has nothing to do with the property. The region does that work
/// instead — a marker chosen at the call site and looked for only in the code
/// or only in the attributes cannot be padded by copy, comments or a
/// declaration, and it does not mind a second caller.
#[tokio::test]
async fn the_esim_tab_has_what_switching_a_profile_needs() {
    let panel = Panel::load().await;
    for (feature, place, marker) in [
        ("the tab reads the card", In::Code, "const list = await this.readProfiles();"),
        (
            "switching asks first",
            In::Code,
            "if (!confirm(esimAsk(profile, enable, this.profiles, this.activeImei))) {",
        ),
        (
            "refusing leaves a trace",
            In::Code,
            "declined.meta = \"没有发出 —— 卡没有被碰过\";",
        ),
        (
            "the switch itself is unchanged",
            In::Code,
            "await this.post(\"/api/esim/switch\", { imei: this.activeImei, iccid, enable });",
        ),
        (
            "the card is asked afterwards",
            In::Code,
            "judgeSwitch(s, await this.readProfiles());",
        ),
        (
            "a verdict left on screen is re-decided by a fresh read",
            In::Code,
            "if (this.esimSwitch && this.esimSwitch.verdict !== \"refused\") judgeSwitch(this.esimSwitch, list);",
        ),
        (
            "the wait before the readback is visible",
            In::Code,
            "state.step = \"等卡片 REFRESH… \" + Math.ceil(left / 1000) + \" 秒\";",
        ),
        ("a readback that fails is its own outcome", In::Code, "s.verdict = \"unknown\";"),
        (
            "the receipt keeps the endpoint's claim apart",
            In::Tags,
            "x-text=\"esimSwitch.claim || '还没有答复'\"",
        ),
        (
            "the receipt shows what the card said",
            In::Tags,
            "x-text=\"esimSwitch.seenText || '还没有回读'\"",
        ),
        ("the verdict is what gets drawn", In::Tags, "x-text=\"esimSwitch.verdictText\""),
        (
            "which profile is live is stated in words",
            In::Tags,
            "x-text=\"liveProfile ? profileName(liveProfile) : ''\"",
        ),
        ("a card with nothing enabled is called out", In::Text, "卡上没有任何 profile 处于启用"),
        ("the enabled row is marked", In::Tags, ":class=\"p.enabled ? 'is-live' : ''\""),
        ("the profile class is readable", In::Tags, "x-text=\"classLabel(p.class)\""),
        ("the table says when it was read", In::Tags, "x-text=\"'回读于 ' + clock(esimReadAt)\""),
        (
            "the row button goes through the guarded path",
            In::Tags,
            "@click=\"switchProfile(p.iccid, !p.enabled, $event.currentTarget)\"",
        ),
        (
            "the receipt can be re-checked against the card",
            In::Tags,
            ":disabled=\"!activeImei || esimSwitch.busy\"",
        ),
        ("selecting another modem drops the old verdict", In::Code, "this.esimSwitch = null;"),
    ] {
        panel.wired(place, feature, marker);
    }

    // The readback is a call to `/api/esim`, and it is the one wiring on this
    // tab a substring search cannot see going: `/api/esim` is a prefix of
    // `/api/esim/switch`, so with the readback deleted outright the whole
    // suite stayed green.
    let read = body_of(&panel.code, "async readProfiles() {", "\n        },");
    assert!(
        read.contains("await this.post(\"/api/esim\", { imei: this.activeImei });"),
        "the tab no longer reads the card, it only writes to it"
    );
}

/// The switch is confirmed first, and the dialog says what it costs.
///
/// The consequences are not invented for the dialog; they are the repository's
/// own words about this operation. `edge-panel/src/lib.rs`: switching "takes
/// the modem off its current network while the card refreshes".
/// `edge-modem/src/es10c.rs`: "Exactly one profile can be enabled", so
/// enabling one is disabling another; and "on hardware nobody can physically
/// reach", so there is no undoing it by hand.
#[tokio::test]
async fn switching_a_profile_asks_before_it_sends() {
    let panel = Panel::load().await;
    let page = &panel.page;
    let dialog = body_of(&panel.code, "function esimAsk(profile, enable, profiles, imei) {", "\n    }");
    for consequence in [
        "摘下来",
        "REFRESH",
        "只有一个 profile 启用",
        "没有网络可以回去",
        "没有人能物理接触",
        "回读 /api/esim",
    ] {
        assert!(
            dialog.contains(consequence),
            "the confirmation never mentions {consequence}"
        );
    }

    // And on screen before anybody clicks. A warning that only exists inside
    // the dialog has arrived after the decision that opened it.
    let ahead = body_of(page, "<p class=\"esim-guard\">", "</p>");
    for consequence in [
        "REFRESH",
        "同一时刻只有一个 profile 启用",
        "没有人能物理接触",
        "回读 /api/esim",
    ] {
        assert!(
            ahead.contains(consequence),
            "the tab does not say {consequence} until the dialog is already open"
        );
    }
}

/// What is on the card decides what the panel says, in both directions.
///
/// `/api/esim/switch` has been measured wrong both ways on this fleet: it
/// returned `ok` for a switch that had not happened — `/api/esim` still showed
/// the profile disabled — and it has also reported a failure for one that had.
/// An endpoint that is wrong in both directions confirms nothing, so a
/// readback reached only from the success branch would still leave half of it
/// unchecked. This asserts the order, not merely the presence.
#[tokio::test]
async fn a_switch_is_reported_from_the_card_and_not_from_the_endpoint() {
    let panel = Panel::load().await;
    let body = body_of(
        &panel.code,
        "async switchProfile(iccid, enable, button) {",
        "\n        },",
    );

    let sent = body
        .find("this.post(\"/api/esim/switch\"")
        .expect("the switch is never sent");
    let claimed_ok = body
        .find("s.claim = \"ok\";")
        .expect("an ok answer is not recorded");
    let claimed_failure = body
        .find("s.failed = true;")
        .expect("an error answer is not recorded");
    let read_back = body
        .find("judgeSwitch(s, await this.readProfiles());")
        .expect("the switch never reads the card back");

    assert!(sent < read_back, "the card is read before the switch is sent");
    assert!(
        claimed_ok < read_back,
        "the readback does not follow an ok answer"
    );
    assert!(
        claimed_failure < read_back,
        "the readback does not follow an error answer"
    );

    // Nothing may announce an outcome in the stretch that only knows the POST
    // came back. This is the pre-refactor panel's exact mistake.
    let between = &body[sent..read_back];
    for claim in ["已启用", "已停用", "已生效", "切换成功", "已切换"] {
        assert!(
            !between.contains(claim),
            "the panel announces {claim} before it has read the card"
        );
    }
    assert!(
        !panel.code.contains("(enable ? \" 已启用\" : \" 已停用\")"),
        "the pre-refactor line that printed the outcome from the POST is back"
    );

    // The verdict is judgeSwitch's to write. The one exception is the case
    // where the card could not be reached at all, which is neither success nor
    // failure and is reported as neither.
    assert!(
        !body.contains("s.verdict = \"match\""),
        "the switch decides success without asking the card"
    );
    assert!(
        !body.contains("s.verdict = \"mismatch\""),
        "the switch decides failure without asking the card"
    );
}

/// The verdict is a function of the profile list and nothing else.
#[tokio::test]
async fn the_verdict_is_computed_from_the_profile_list_alone() {
    let panel = Panel::load().await;
    let judge = body_of(&panel.code, "function judgeSwitch(state, profiles) {", "\n    }");

    assert!(
        judge.contains("profiles.find((p) => p.iccid === state.iccid)"),
        "the verdict does not look the profile up in what was read back"
    );
    assert!(
        judge.contains("state.seen === state.enable"),
        "the verdict does not compare the card against what was asked for"
    );
    // Three outcomes, because there are three: it matches, it does not, or the
    // profile is not in the list the card handed back at all.
    for outcome in ["\"match\"", "\"mismatch\"", "\"missing\""] {
        assert!(judge.contains(outcome), "the verdict cannot come out {outcome}");
    }
    assert!(
        !judge.contains("claim"),
        "the verdict reads the endpoint's answer instead of the card"
    );
}

/// The process-wide log ring is shared by every test in this binary, so the two
/// tests that write to it take turns. Without this, the six hundred lines one
/// of them pushes evict the single line the other is looking for.
static LOG_RING_TURN: Mutex<()> = Mutex::new(());

/// Read the panel's `/api/logs` the way the column does.
async fn read_logs(after: u64) -> serde_json::Value {
    let app = router(Arc::new(MemoryInbox::default()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri(format!("/api/logs?after={after}"))
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

/// Every entry in the guard table, as the page writes it.
///
/// Read out of the table rather than listed here, so a guard added without a
/// `label`, without a `warn` or without an `ask` is a failure rather than
/// something the assertions below quietly skip. The pattern is captured as a
/// string because the shape of the regular expression is the thing the
/// read/write assertions are about.
struct Guard {
    label: String,
    warn: String,
    pattern: String,
    ask: String,
}

fn guard_table(code: &str) -> Vec<Guard> {
    let table = body_of(code, "const GUARDED = [", "\n    ];");
    let mut guards = Vec::new();
    let mut rest = table;
    while let Some(at) = rest.find("        label: ") {
        rest = &rest[at + "        label: ".len()..];
        let label = quoted(rest);
        let warn_at = rest.find("        warn: ").expect("a guard with no warn");
        let warn = quoted(&rest[warn_at + "        warn: ".len()..]);
        // Every pattern here is case-insensitive, and it has to be: `at+cfun`
        // typed in lower case is the same command. `/i,` is therefore the
        // terminator, and a pattern written without the flag fails here rather
        // than silently guarding only the shouted spelling.
        let match_at = rest.find("        match: /").expect("a guard with no pattern");
        let pattern_from = &rest[match_at + "        match: /".len()..];
        let pattern = pattern_from[..pattern_from
            .find("/i,")
            .expect("a guard pattern is not case-insensitive, or is unterminated")]
            .to_string();
        let ask_at = rest.find("        ask(").expect("a guard with no dialog");
        let ask_body = body_of(&rest[ask_at..], "{", "\n        },").to_string();
        guards.push(Guard { label, warn, pattern, ask: ask_body });
    }
    guards
}

/// The contents of the first `"…"` or `'…'` at the start of `text`.
fn quoted(text: &str) -> String {
    let mut chars = text.chars();
    let opener = chars.next().expect("nothing to quote");
    assert!(opener == '"' || opener == '\'', "not a string literal: {}", &text[..20.min(text.len())]);
    let mut out = String::new();
    let mut escaped = false;
    for c in chars {
        if escaped {
            out.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == opener {
            break;
        } else {
            out.push(c);
        }
    }
    out
}

/// The commands that can leave a module somewhere software cannot get it out
/// of are all guarded, and each one says what it costs.
///
/// T004 built the mechanism and shipped it with one entry, leaving "which
/// other commands belong here" as a product question. It has been answered:
/// an entry earns its place by being able to leave the module in a state no
/// further command can undo — on hardware that reaches this site over USB/IP,
/// where nobody can pull a stick.
///
/// The consequence sentences are pinned inside each `ask`, not on the page.
/// T026 emptied every consequence out of the one dialog that existed and
/// watched all five assertions stay green, propped up by a paragraph of static
/// copy. The static copy is a good thing and is asserted separately; what it
/// is not is evidence that a dialog says anything.
#[tokio::test]
async fn every_command_that_cannot_be_undone_is_guarded_and_says_why() {
    let panel = Panel::load().await;
    let guards = guard_table(&panel.code);
    assert!(
        guards.len() >= 8,
        "the guard table has {} entries; it should carry usbnet, both AT+CFUN forms, \
         AT+COPS manual selection, AT+CRSM writes, AT+CSIM, the logical-channel trio \
         and AT+QPRTPARA",
        guards.len()
    );

    // Each command shape, and the words its dialog cannot be missing. Every
    // one of these is quoted from this repository rather than written for the
    // dialog — the provenance is beside each entry in the page.
    for (shape, consequences) in [
        // T004's original. Named here too so a rewrite of the table cannot
        // drop it while the rest of this test still passes.
        ("usbnet", vec!["立即生效", "重新枚举", "cdc-wdm", "从机队里消失"]),
        // `AT+CFUN=<n>,1`: the reset form. edge-panel/src/lib.rs refuses to put
        // it on a button; edge-modem/src/session.rs records it as the only
        // measured way out of `+CFUN: 7`, on one observation. Both halves have
        // to be in the dialog, because an operator who is in the second
        // situation is being told to do this by the daemon's own error text.
        //
        // The shape names the command, not just the argument: a guard renamed
        // to match some other command keeps its whole dialog, so a lookup by
        // "the bit in brackets" finds it still there and says nothing. That was
        // measured — two mutations that pointed a guard at `AT+NEVER` stayed
        // green until the shapes below carried the command name.
        (
            "cfun\\s*=\\s*(\\d+)\\s*,",
            vec!["重新枚举", "没有人能物理接触", "+CFUN: 7", "唯一量到过的解药", "40 秒"],
        ),
        // `AT+CFUN=0/4/7`: off the air. The way back exists for 0 and 4 and is
        // named, because a dialog that implies otherwise is the kind operators
        // learn to dismiss. 7 is the exception and is called one.
        (
            "cfun\\s*=\\s*(0|4|7)",
            vec!["立刻脱网", "AT+CFUN=1", "+CME ERROR: 4", "没有人能物理接触"],
        ),
        // `AT+COPS=1,…` / `=2`: manual selection and deregistration. The query
        // form `AT+COPS=?` is deliberately *not* here — see
        // `the_sweep_is_not_guarded_and_the_manual_selection_still_is`.
        ("cops\\s*=\\s*([12])", vec!["手动", "脱网", "AT+COPS=0"]),
        // `AT+CRSM` writes. The read form is deliberately not trapped, and the
        // dialog says so by naming the read the agent itself sends.
        ("crsm", vec!["没有撤销", "AT+CRSM=176", "换卡不是退路"]),
        // `AT+CSIM`: a raw APDU, which the panel cannot classify at all. The
        // dialog has to say which channel it runs on, because the entry below
        // is the one that opens channels and two rows claiming the same
        // consequence is how an operator learns neither of them.
        ("csim", vec!["APDU", "基本通道", "AT+CCHO", "+CME ERROR: 13"]),
        // `AT+CCHO` / `AT+CGLA` / `AT+CCHC`: the logical-channel trio, and the
        // only commands here that can exhaust a card-level resource for good.
        // vowifi T089 found them missing while running one on real hardware.
        // The close is in the same entry as the open on purpose: on its own
        // row it reads as optional, and a leaked channel has no software way
        // back on hardware nobody can unplug.
        (
            "(ccho|cgla|cchc)",
            vec![
                "逻辑通道只有 3",
                "开了就必须关",
                "没有软件办法收回",
                "没有人能拔插",
                "AT+CCHC",
                "T089",
                "必须失败",
            ],
        ),
        // `AT+QPRTPARA`: NV.
        ("qprtpara", vec!["NV", "没有第二次机会", "没有人能拔插"]),
    ] {
        let guard = guards
            .iter()
            .find(|g| g.pattern.contains(shape))
            .unwrap_or_else(|| {
                panic!(
                    "nothing in the guard table matches {shape}; the patterns are {:?}",
                    guards.iter().map(|g| &g.pattern).collect::<Vec<_>>()
                )
            });
        for consequence in consequences {
            assert!(
                guard.ask.contains(consequence),
                "the dialog for {} never mentions {consequence}",
                guard.label
            );
        }
        assert!(
            !guard.warn.trim().is_empty(),
            "{} has no one-line warning for the on-screen list",
            guard.label
        );
    }

    // Two dialogs name the value the operator typed through a lookup rather
    // than in a sentence, which is right — the sentence cannot know it — but it
    // puts the words somewhere the loop above cannot see. Asserted where they
    // live, or "UPDATE BINARY" could disappear with the dialog still full of
    // consequences and this test still green.
    let crsm_table = body_of(&panel.code, "const CRSM_WRITES = {", "};");
    for (code, name) in [("214", "UPDATE BINARY"), ("219", "SET DATA"), ("220", "UPDATE RECORD")] {
        assert!(
            crsm_table.contains(code) && crsm_table.contains(name),
            "the CRSM dialog cannot name what {code} does: {crsm_table}"
        );
    }
    // And the read codes stay out of it, so the table cannot become the place
    // a read quietly acquires a dialog.
    for read in ["176", "178", "192", "242"] {
        assert!(
            !crsm_table.contains(read),
            "the CRSM write table lists the read code {read}"
        );
    }
    let cfun_table = body_of(&panel.code, "const CFUN_MEANING = {", "\n    };");
    for (value, meaning) in [("0:", "射频与卡一起下电"), ("4:", "飞行模式"), ("7:", "离线")] {
        assert!(
            cfun_table.contains(value) && cfun_table.contains(meaning),
            "the radio-down dialog cannot say what {value} means: {cfun_table}"
        );
    }
    // The lookups have to be read by the dialogs that need them.
    let crsm_ask = &guards
        .iter()
        .find(|g| g.pattern.contains("crsm"))
        .expect("no CRSM guard")
        .ask;
    assert!(
        crsm_ask.contains("CRSM_WRITES[Number(found[1])]"),
        "the CRSM dialog does not name the operation it is about to send"
    );
    let cfun_ask = &guards
        .iter()
        .find(|g| g.pattern.contains("cfun\\s*=\\s*(0|4|7)"))
        .expect("no radio-down guard")
        .ask;
    assert!(
        cfun_ask.contains("CFUN_MEANING[value]"),
        "the radio-down dialog does not say which of the three values was typed"
    );

    // One entry's provenance is not this repository, and the dialog has to say
    // so in its own words rather than let an operator assume it was read off a
    // line in `lib.rs`. `AT+QPRTPARA` appears in no source file here; it comes
    // from the vowifi board's T028, which listed a factory NV reset as an
    // option it did not take. The entry earns its row on the property — no
    // second chance, no physical access — not on the citation, so the citation
    // is stated rather than implied. A dialog that quietly dropped it would be
    // one whose reader cannot check it.
    let nv = &guards
        .iter()
        .find(|g| g.pattern.contains("qprtpara"))
        .expect("no NV guard")
        .ask;
    for source in ["vowifi", "T028", "不来自本仓库"] {
        assert!(
            nv.contains(source),
            "the NV dialog does not say where its evidence comes from: no {source} in it"
        );
    }
}

/// A guard fires on the form that cannot be undone and stays out of the way of
/// the one that can.
///
/// This is the rule usbnet's query/write split established, applied to the
/// rest: a dialog in front of a harmless command trains the reflex that
/// dismisses the dialog in front of a harmful one. Three shapes have to pass
/// through untouched, and each is here because this repository sends it:
///
/// * `AT+CRSM=176,…` — the agent reads `EF_AD` with it on every report;
/// * `AT+CFUN=1` — the plain form, which is the *recovery* in `session.rs`'s
///   own ladder;
/// * `AT+COPS=0` — automatic selection, measured on this bench to bring two
///   sticks back to LTE in 15-90 seconds.
#[tokio::test]
async fn the_guards_fire_on_the_form_that_does_not_come_back() {
    let panel = Panel::load().await;
    let guards = guard_table(&panel.code);
    let pattern_for = |shape: &str| -> String {
        guards
            .iter()
            .find(|g| g.pattern.contains(shape))
            .unwrap_or_else(|| panic!("no guard matches {shape}"))
            .pattern
            .clone()
    };

    // `AT+CFUN=<n>,1` has to require the reset argument, or it swallows every
    // plain `AT+CFUN=1`.
    let reset = pattern_for("cfun\\s*=\\s*(\\d+)\\s*,");
    assert!(
        reset.contains(",\\s*1\\s*$"),
        "the reset guard does not require the reset argument, so it also traps AT+CFUN=1: {reset}"
    );
    // And the radio-down guard has to stop at 0, 4 and 7 rather than any digit.
    let off = pattern_for("cfun\\s*=\\s*(0|4|7)");
    assert!(
        off.contains("(0|4|7)"),
        "the radio-down guard takes any value, so it also traps AT+CFUN=1: {off}"
    );

    // `AT+CRSM` on the update codes only.
    let crsm = pattern_for("crsm");
    for write in ["214", "219", "220"] {
        assert!(crsm.contains(write), "the CRSM guard misses the write code {write}: {crsm}");
    }
    for read in ["176", "178", "192", "242"] {
        assert!(
            !crsm.contains(read),
            "the CRSM guard traps the read code {read}, which the agent itself sends on every \
             report — a dialog in front of that is one an operator learns to dismiss: {crsm}"
        );
    }

    // `AT+COPS` on manual selection and deregistration, never on automatic.
    let cops = pattern_for("cops\\s*=\\s*([12])");
    assert!(
        cops.contains("([12])"),
        "the COPS guard does not name which values it traps, so it may also trap AT+COPS=0 — \
         which is the way back: {cops}"
    );

    // The logical-channel trio is one entry covering all three spellings. Not
    // three entries: `AT+CCHC` on a row of its own is a row an operator can
    // decide not to read, and closing is not a separate decision from opening.
    let channel = pattern_for("(ccho|cgla|cchc)");
    for verb in ["ccho", "cgla", "cchc"] {
        assert!(
            channel.contains(verb),
            "the logical-channel guard misses AT+{}: {channel}",
            verb.to_uppercase()
        );
    }
    assert_eq!(
        guards
            .iter()
            .filter(|g| g.pattern.contains("ccho")
                || g.pattern.contains("cgla")
                || g.pattern.contains("cchc"))
            .count(),
        1,
        "the logical-channel commands are split across rows; the close then reads as optional"
    );
    // And the row the operator reads before typing has to carry all three too,
    // or the on-screen list announces an open with no close.
    let channel_guard = guards
        .iter()
        .find(|g| g.pattern.contains("(ccho|cgla|cchc)"))
        .expect("no logical-channel guard");
    for spelling in ["CCHO", "CGLA", "CCHC"] {
        assert!(
            channel_guard.label.contains(spelling),
            "the on-screen label for the channel guard does not name AT+{spelling}: {}",
            channel_guard.label
        );
    }
    assert!(
        channel_guard.warn.contains("开了必须关"),
        "the one-line warning does not say the close is not optional: {}",
        channel_guard.warn
    );

    // Every guard is anchored. An unanchored pattern matches the command
    // somewhere in the middle of a longer one, which is how a guard starts
    // firing on things nobody meant it to.
    for guard in &guards {
        assert!(
            guard.pattern.starts_with("^at\\+"),
            "{} is not anchored at the start of the command: {}",
            guard.label,
            guard.pattern
        );
    }
}

/// The sweep is not guarded, and the manual selection still is.
///
/// `AT+COPS=?` had an entry for one card. The argument for it was symmetry —
/// the 网络 tab's button asks before running the same command, so typing it
/// should not be the cheaper way round that dialog — and symmetry is not the
/// test this table applies. The sweep is slow, not irreversible: `edge-bin`
/// runs it under `SCAN_TIMEOUT` and the modem returns by itself with nothing
/// to undo. A dialog in front of a command that comes back is what teaches an
/// operator to confirm without reading, which is how the entries that cannot
/// come back stop working. The complaint underneath it — nobody expects three
/// minutes — is answered by the progress bar on the 网络 tab, asserted in
/// `a_slow_sweep_shows_progress_rather_than_looking_hung`.
///
/// This test exists because "we removed one" is the easy half. The hard half
/// is that removing one must not widen the rest, and the way that happens
/// quietly is the manual form going with it: `AT+COPS=1,…` locks the stick to
/// a PLMN that may not be here, and there is nothing on screen to tell that
/// apart from no coverage.
#[tokio::test]
async fn the_sweep_is_not_guarded_and_the_manual_selection_still_is() {
    let panel = Panel::load().await;
    let guards = guard_table(&panel.code);
    let cops: Vec<_> = guards.iter().filter(|g| g.pattern.contains("cops")).collect();
    assert_eq!(
        cops.len(),
        1,
        "there should be exactly one COPS guard, the manual one; found {:?}",
        cops.iter().map(|g| &g.label).collect::<Vec<_>>()
    );
    let cops = cops[0];
    assert!(
        cops.pattern.contains("([12])"),
        "the surviving COPS guard is not the manual one: {}",
        cops.pattern
    );
    assert!(
        !cops.pattern.contains("\\?"),
        "the surviving COPS guard also traps the query form: {}",
        cops.pattern
    );
    assert!(
        cops.label.contains('1') && !cops.label.contains('?'),
        "the on-screen row still advertises the sweep as guarded: {}",
        cops.label
    );
    // The sweep's own dialog stays where it belongs — on the button, which
    // reaches `/api/scan` rather than the command box — and it is the place
    // that says why the sweep is not in the table. Removing the typed guard
    // must not have taken that sentence with it, or the distinction this card
    // drew survives only in a commit message.
    let scan = body_of(&panel.code, "function scanAsk(imei) {", "\n    }");
    for consequence in ["AT+COPS=?", "没有走不回来的那一半"] {
        assert!(
            scan.contains(consequence),
            "the scan button's dialog no longer mentions {consequence}"
        );
    }
}

/// Every guarded command is named on screen before anybody types one.
///
/// The console has always carried a paragraph about usbnet, and it is still
/// there. What it could not do is grow: a guard added to the table with no copy
/// anywhere would first announce itself inside the dialog it opens, which is
/// after the decision that opened it. The list is therefore rendered from the
/// table, and this pins that wiring rather than the words.
#[tokio::test]
async fn every_guarded_command_is_named_before_anybody_types_one() {
    let panel = Panel::load().await;
    for (feature, place, marker) in [
        ("the list is drawn from the guard table", In::Tags, "x-for=\"g in GUARDED\""),
        ("each row names the command", In::Tags, "x-text=\"g.label\""),
        ("each row says what it costs", In::Tags, "x-text=\"g.warn\""),
    ] {
        panel.wired(place, feature, marker);
    }
    // The table has to be reachable from the component, or the loop above
    // renders nothing and the assertions are about dead markup.
    let data = body_of(&panel.code, "Alpine.data(\"panel\", () => ({", "\n        boot() {");
    assert!(
        data.contains("GUARDED, SCAN_LIMIT,"),
        "the guard table is not exposed to the component, so the on-screen list is empty"
    );
    // And the usbnet paragraph the console has always had is still there.
    let ahead = body_of(&panel.page, "<p class=\"con-guard\">", "</p>");
    assert!(
        ahead.contains("cdc-wdm"),
        "the console lost the paragraph that explains usbnet in full"
    );
}

/// A sweep that runs for three minutes has to look like it is running.
///
/// `edge-bin` gives `AT+COPS=?` `SCAN_TIMEOUT`, 180 seconds, and the modem
/// serves nothing for the whole of it. The pre-refactor panel showed a disabled
/// button and the words "最长两分钟" — a disabled button is what a hung page
/// shows too, and the number was sixty seconds short of what the endpoint
/// waits.
#[tokio::test]
async fn a_slow_sweep_shows_progress_rather_than_looking_hung() {
    let panel = Panel::load().await;
    assert_eq!(
        constant(&panel.code, "SCAN_LIMIT"),
        180_000,
        "the scan budget no longer matches the daemon's SCAN_TIMEOUT of 180s, so the bar is \
         drawn against the wrong maximum"
    );

    for (feature, place, marker) in [
        ("the sweep is timed from when it started", In::Code, "this.scanStartedAt = Date.now();"),
        (
            "elapsed is derived from the tick, not from the reply",
            In::Code,
            "return Math.max(0, Math.round((this.now - this.scanStartedAt) / 1000));",
        ),
        ("there is a bar", In::Tags, "class=\"scan-bar\""),
        ("the bar is filled by the elapsed time", In::Tags, ":value=\"Math.min(scanElapsed, SCAN_LIMIT / 1000)\""),
        ("the bar is sized by the daemon's own timeout", In::Tags, ":max=\"SCAN_LIMIT / 1000\""),
        ("the progress is readable as a number too", In::Tags, "x-show=\"scanBusy\""),
        ("the result carries when it was taken", In::Tags, "x-text=\"'扫于 ' + clock(scanAt)\""),
        ("the current network is marked in the table", In::Tags, "op.status === 'current' ? 'is-current'"),
        ("a sweep in flight says the stick is not serving", In::Text, "不注册、不收短信、没有数据"),
        ("and that it comes back by itself", In::Text, "扫完自己回来"),
    ] {
        panel.wired(place, feature, marker);
    }

    // The elapsed counter has to be reset, or the next sweep's bar starts
    // full — which reads as "already timed out" from the first frame.
    let sweep = body_of(&panel.code, "async runScan(button) {", "\n        },");
    assert!(
        sweep.contains("this.scanStartedAt = 0;"),
        "the elapsed counter is never cleared, so the next sweep starts with a full bar"
    );

    // And the dialog in front of it says the two things that decide whether to
    // press it: how long, and that the way back is nothing.
    let dialog = body_of(&panel.code, "function scanAsk(imei) {", "\n    }");
    for consequence in ["不服务", "AT+COPS=?", "扫完它自己回来", "忙"] {
        assert!(
            dialog.contains(consequence),
            "the sweep dialog never mentions {consequence}"
        );
    }
    assert!(
        dialog.contains("Math.round(SCAN_LIMIT / 1000)"),
        "the dialog states a duration of its own rather than the one the daemon waits"
    );
}

/// The panel will not send a message from the stick that leaves the bus.
///
/// `867018069509705` stalls its own QMI interrupt endpoint on every MO submit
/// and drops off USB/IP for the length of a re-enumeration. Both transports do
/// it and a full `AT+CFUN=1,1` does not clear it, so there is nothing this side
/// can fix — but the message usually *does* go out (the SIM's own MO counter in
/// `EF_SMSS` advanced by 34 over a day of "failed" sends), which is why the
/// wording has to be about the module rather than about the message.
///
/// Two separate things are asserted, because a label is not a guard: the stick
/// is marked, *and* the send path refuses.
#[tokio::test]
async fn the_panel_will_not_send_from_the_stick_that_leaves_the_bus() {
    let panel = Panel::load().await;
    let blocked = "867018069509705";

    // Marked, in the code that decides it and on the page that shows it.
    let table = body_of(&panel.code, "const SMS_BLOCKED = {", "\n    };");
    assert!(
        table.contains(blocked),
        "the block list does not name {blocked}"
    );
    for (feature, place, marker) in [
        ("the rail marks the stick", In::Tags, "x-show=\"smsBlock(m.imei)\""),
        ("the mark is a badge, not only a tooltip", In::Text, "MO 短信禁发"),
        ("the sms tab explains it in full", In::Tags, "x-text=\"smsBlock(activeImei).why\""),
        ("and says the message probably went out anyway", In::Tags, "x-text=\"smsBlock(activeImei).also\""),
        ("and where that was measured", In::Tags, "x-text=\"smsBlock(activeImei).source\""),
        ("the controls are disabled", In::Tags, ":disabled=\"!canSend\""),
    ] {
        panel.wired(place, feature, marker);
    }

    // And refused in the send path itself. `:disabled` on a fieldset is one
    // stale render away from not existing, and Enter in a text input submits a
    // form, so the check that matters is the one in front of the request.
    let send = body_of(&panel.code, "async sendSms() {", "\n        },");
    let asked = send
        .find("const blocked = this.smsBlock(this.activeImei);")
        .expect("the send path does not consult the block list");
    let sent = send
        .find("await this.post(\"/api/send\"")
        .expect("the send path no longer sends anything");
    assert!(asked < sent, "the block list is consulted after the message has gone out");
    assert!(
        send[asked..sent].contains("if (blocked) {"),
        "the block list is read and then ignored"
    );

    // An unaimed send is the same refusal by another route: with no IMEI the
    // daemon takes the first entry out of its modem map, and the stick above is
    // in that map.
    let unaimed = send
        .find("if (!this.activeImei) {")
        .expect("an unaimed send is allowed, and the daemon picks the modem — including that one");
    assert!(unaimed < sent, "the unaimed check happens after the message has gone out");

    // Each refusal has to return inside *its own* branch. Looking for a
    // `return;` anywhere between the first check and the request is not the
    // same assertion: with two refusals in a row, deleting the first one's
    // `return;` leaves the second one's inside the same span, and it was
    // measured staying green that way.
    for (refusal, from, to) in [
        ("a blocked stick", asked, unaimed),
        ("an unaimed send", unaimed, sent),
    ] {
        assert!(
            send[from..to].contains("return;"),
            "{refusal} carries on to the send anyway, so the refusal only delays it"
        );
    }
    assert!(
        send.contains("refused.meta = \"没有发出 —— 模组没有被碰过\";"),
        "a refused send leaves no trace saying it was not sent"
    );
    let gate = body_of(&panel.code, "get canSend() {", "\n        },");
    assert!(
        gate.contains("!!this.activeImei") && gate.contains("!this.smsBlock(this.activeImei)"),
        "the send controls are enabled without both checks: {gate}"
    );
}

/// The SMS tab shows what the payload already carries and what the encoder will
/// do, without asking for anything new.
///
/// `/api/messages` has carried `direction` and `modem_imei` all along and the
/// pre-refactor panel threw both away, so three sticks' traffic arrived as one
/// undifferentiated list. And `edge-modem`'s encoder does not segment: past 160
/// GSM-7 septets or 70 UCS-2 characters `encode_submit` returns `TooLong` and
/// the send is refused, which is worth knowing before the button rather than
/// after.
#[tokio::test]
async fn the_sms_tab_has_what_sending_and_reading_messages_needs() {
    let panel = Panel::load().await;
    assert_eq!(constant(&panel.code, "GSM7_MAX_SEPTETS"), 160);
    assert_eq!(constant(&panel.code, "UCS2_MAX_CHARS"), 70);

    for (feature, place, marker) in [
        ("which way a message went", In::Tags, "x-text=\"m.direction === 'outbound' ? '发出'"),
        ("which stick it belongs to", In::Tags, "x-text=\"m.modem_imei ? shortImei(m.modem_imei) : '—'\""),
        ("the inbox can be narrowed to one stick", In::Tags, "x-model=\"inboxMine\""),
        ("and says how much it is hiding", In::Tags, "x-text=\"inbox.length + ' / ' + messages.length + ' 条'\""),
        ("the draft is measured", In::Tags, "x-text=\"draftText\""),
        ("and marked when it will be refused", In::Tags, ":class=\"draft.over ? 'is-over' : ''\""),
    ] {
        panel.wired(place, feature, marker);
    }

    // The filter must not drop a message whose stick was never recorded:
    // hiding mail because a field is missing is a worse failure than showing
    // one row too many.
    let filter = body_of(&panel.code, "get inbox() {", "\n        },");
    assert!(
        filter.contains("!m.modem_imei || m.modem_imei === this.activeImei"),
        "the inbox filter drops messages with no modem recorded: {filter}"
    );

    // The encoder mirror has to say it does not segment, or the count reads as
    // "this will be two messages" — which is what every other SMS box means.
    // Both branches, separately: the meter has an empty state and an
    // over-the-limit state, and a single search for "不分片" was measured
    // staying green with the over-the-limit sentence deleted, propped up by the
    // empty-state hint.
    let meter = body_of(&panel.code, "get draftText() {", "\n        },");
    assert!(
        meter.contains("本机编码器不分片"),
        "the empty draft hint does not say the encoder refuses rather than segments: {meter}"
    );
    assert!(
        meter.contains("会被编码器拒掉（不会分片发出去）"),
        "an over-length draft is flagged without saying it will be refused rather than split, \
         which is what every other SMS box means by a segment count: {meter}"
    );
    let shape = body_of(&panel.code, "function draftShape(body) {", "\n    }");
    assert!(
        shape.contains("gsm7 ? GSM7_MAX_SEPTETS : UCS2_MAX_CHARS"),
        "the limit is not chosen by the encoding the body forces: {shape}"
    );
}

/// The health tab answers the three questions it is opened for, in words.
///
/// Every one of them is already somewhere in the grid — as a tone on one of ten
/// rows — and that is the failure this fixes: a module attached for data with
/// no circuit-switched domain and no message centre reads as healthy right up
/// to the moment a message disappears. Nothing here is a second request; it is
/// the same `/api/report` read, said out loud.
#[tokio::test]
async fn the_health_tab_says_whether_the_stick_can_carry_anything() {
    let panel = Panel::load().await;
    for (feature, place, marker) in [
        ("the read is timed", In::Code, "this.reportAt = Date.now();"),
        ("and the time is shown", In::Tags, "x-text=\"'读于 ' + clock(reportAt)\""),
        ("the verdict is drawn", In::Tags, "x-for=\"v in reportVerdict\""),
        ("with its own tone", In::Tags, ":class=\"v.tone\""),
        ("the facts are grouped by the question they answer", In::Tags, "x-for=\"group in reportGroups\""),
        // In the attribute rather than in a text node: the sentence only makes
        // sense when there is a refusal to explain, so it is drawn with the
        // list it explains.
        ("a refusal is explained rather than left as a list", In::Tags, "'（拒绝也是回答"),
    ] {
        panel.wired(place, feature, marker);
    }

    let verdict = body_of(&panel.code, "get reportVerdict() {", "\n        },");
    // The one combination that is invisible in a grid of tones: attached for
    // data, no CS domain. That is the state in which SMS fails silently, and
    // the panel's own comment on the two rows says so.
    assert!(
        verdict.contains("reg(ps) && !reg(cs)"),
        "the verdict does not separate a PS-only attach from a full one, which is the state \
         in which SMS fails without an error: {verdict}"
    );
    assert!(
        verdict.contains("短信会安静地失败"),
        "a PS-only attach is reported without saying what it costs"
    );
    assert!(
        verdict.contains("r.sms_centre"),
        "the verdict ignores the message centre, whose absence fails a send with an error \
         that does not mention it"
    );
    // Derived from the read, never from a second request.
    assert!(
        !verdict.contains("this.post(") && !verdict.contains("fetch("),
        "the verdict asks the modem something instead of reading what the report already said"
    );
    // And it carries the block list, because this tab is where somebody checks
    // a stick before sending from it.
    assert!(
        verdict.contains("SMS_BLOCKED[r.imei]"),
        "the health tab does not mention that this stick must not send"
    );

    let groups = body_of(&panel.code, "get reportGroups() {", "\n        },");
    assert!(
        groups.contains("this.reportFacts"),
        "the groups are built from something other than the facts of the read: {groups}"
    );
}

/// Pull an integer constant out of the page's script.
fn constant(page: &str, name: &str) -> u64 {
    let needle = format!("const {name} = ");
    let at = page
        .find(&needle)
        .unwrap_or_else(|| panic!("the page defines no {name}"));
    page[at + needle.len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '_')
        .filter(|c| *c != '_')
        .collect::<String>()
        .parse()
        .unwrap_or_else(|_| panic!("{name} is not a number"))
}

/// The premise the whole log column rests on: a served line carries a sequence
/// number, a timestamp and text, and nothing else.
///
/// `log_line` and `log_error` push into the same ring and the distinction is
/// dropped there, so severity, which module a line is about and which endpoint
/// produced it are all absent from the wire. The column therefore infers them
/// from the text. If this ever stops being true — if `logs.rs` grows a `level`
/// — this test fails and says so, which is the signal to delete the guessing
/// rather than to leave two sources of truth disagreeing.
#[tokio::test]
async fn a_served_log_line_carries_no_level_module_or_endpoint() {
    let _turn = LOG_RING_TURN.lock().unwrap_or_else(|held| held.into_inner());
    let marker = "panel-test-marker line for the shape assertion";
    LogRing::global().push(marker);

    let body = read_logs(0).await;
    let line = body["lines"]
        .as_array()
        .expect("lines")
        .iter()
        .find(|line| line["text"] == marker)
        .expect("the line just pushed is not in the ring");

    let mut fields: Vec<&str> = line
        .as_object()
        .expect("a line is an object")
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        ["at", "seq", "text"],
        "the served shape changed; the column's inferred level/module/source \
         should be replaced by the real field instead of layered on top"
    );
}

/// The panel must hold more history than the server does.
///
/// The ring keeps 500 lines. Measured on this fleet, the daemon prints about
/// 17.7 lines a minute with nothing wrong, so 500 lines is a 28-minute window:
/// once the panel has been open longer than that, its own buffer is the only
/// longer record that exists anywhere. A retention cap at or below the ring's
/// would make the buffer pointless.
#[tokio::test]
async fn the_column_retains_more_than_the_server_ring_does() {
    let _turn = LOG_RING_TURN.lock().unwrap_or_else(|held| held.into_inner());
    let ring = LogRing::global();
    for index in 0..600 {
        ring.push(format!("ring capacity probe {index}"));
    }
    let served = read_logs(0).await;
    let held = served["lines"].as_array().expect("lines").len();
    assert_eq!(held, 500, "the server ring no longer holds 500 lines");

    let panel = Panel::load().await;
    let keep = constant(&panel.code, "LOG_KEEP");
    let render = constant(&panel.code, "LOG_RENDER");
    assert!(
        keep > held as u64,
        "the column keeps {keep} lines but the server already holds {held}"
    );

    // The cap has to be applied, not merely declared. Deleting the two lines
    // that do the trimming left the constant, its readout and this test all
    // green, with the buffer growing without a bound — which is the one thing
    // the retention cap exists to prevent.
    let trim = body_of(&panel.code, "trim() {", "\n        },");
    assert!(
        trim.contains("LOG.lines.splice(0, LOG.lines.length - LOG_KEEP);"),
        "nothing trims the retained buffer to LOG_KEEP"
    );
    assert!(
        trim.contains("LOG.held.splice(0, LOG.held.length - LOG_KEEP);"),
        "nothing trims the buffer that fills up while the column is paused"
    );
    assert!(
        trim.contains("LOG.dropped +="),
        "lines are evicted without being counted, so the column cannot report the loss"
    );
    // And it has to be reached from the poll, in both the running and the
    // paused branch: the paused buffer is the one that grows unattended.
    let poll = body_of(&panel.code, "async pollLogs() {", "\n        },");
    assert_eq!(
        poll.matches("this.trim();").count(),
        2,
        "the poll does not trim on both the paused and the running path"
    );
    // Retaining and drawing are capped separately because their costs are
    // different: a retained line is a small object, a drawn one is four DOM
    // nodes and layout. Collapsing the two would either shrink how far a
    // search reaches or paint thousands of rows nobody asked for.
    assert!(
        render < keep,
        "the drawn cap ({render}) is not below the retained cap ({keep})"
    );
}

/// The column is a cursor poll, and has to keep saying so.
///
/// A log pane that looks like a tail and is not one is worse than an obviously
/// periodic one: the operator reads "nothing new" as "nothing happened" when it
/// may only mean the last request never came back.
#[tokio::test]
async fn the_log_column_admits_it_is_polling_rather_than_tailing() {
    let panel = Panel::load().await;
    assert!(
        panel.code.contains("fetch(\"/api/logs?after=\" + LOG.cursor)"),
        "the column is not a cursor poll"
    );
    panel.wired(In::Tags, "the poll interval is not on screen", "s 轮询'");
    panel.wired(In::Tags, "the last refresh time is not on screen", "'刷新于 '");
    panel.wired(In::Tags, "a failed poll is not reported", "logPollFailed");
    panel.wired(
        In::Tags,
        "the column does not say it is not a stream",
        "不是推送流",
    );
}

/// Everything this card promised, pinned to the thing that implements it.
///
/// These are markers rather than wording: the copy will keep changing and the
/// mechanism should not.
#[tokio::test]
async fn the_log_column_has_what_a_debugging_log_needs() {
    let panel = Panel::load().await;
    for (feature, place, marker) in [
        ("level colouring", In::Styles, "log-row.lvl-err"),
        ("level filtering", In::Tags, "logLevels[level.key]"),
        ("level counts", In::Tags, "logCounts["),
        ("filter by module", In::Tags, "x-model=\"logImei\""),
        ("filter by source", In::Tags, "x-model=\"logTopic\""),
        ("search", In::Tags, "x-model=\"logQuery\""),
        ("search highlighting", In::Styles, "log-row mark"),
        ("walking the hits", In::Tags, "stepMatch("),
        ("pause and resume", In::Tags, "togglePause()"),
        ("copy one line", In::Code, "className = \"log-copy\""),
        ("copy without a secure context", In::Code, "execCommand(\"copy\")"),
        ("arrival cue", In::Styles, "@keyframes log-arrive"),
        ("arrival cue is applied to the new rows", In::Code, "classList.add(\"is-new\")"),
        ("arrival cue while scrolled away", In::Tags, "logNewErr"),
        ("quieting the heartbeat", In::Tags, "logQuiet = !logQuiet"),
        // Only the `ok` form: folding in the `at-only` sibling would let
        // "静音" hide a module that answered over serial after QMI did not.
        ("the heartbeat is only the ok form", In::Code, "imei=\\d+ ok$/i"),
        ("eviction is reported", In::Tags, "已丢弃最旧"),
    ] {
        panel.wired(place, feature, marker);
    }
}

/// The inferred fields have to be labelled as inferred where they are used.
///
/// Colouring a line red on a guess is defensible; letting an operator believe
/// the daemon called it an error is not, because they will trust it in the one
/// case where the guess is wrong.
#[tokio::test]
async fn the_column_says_the_level_and_source_are_inferred() {
    let panel = Panel::load().await;
    panel.wired(
        In::Tags,
        "the level control does not admit the level is inferred",
        "没有级别字段",
    );
    panel.wired(
        In::Tags,
        "the source control does not admit an endpoint is not in the data",
        "日志里没有 /api 端点字段",
    );
}

#[tokio::test]
async fn panel_serves_embedded_html_and_local_json() {
    let inbox = Arc::new(MemoryInbox {
        messages: vec![LocalMessage {
            seq: 1,
            peer: "10086".into(),
            body: "hello".into(),
            bearer: "cellular".into(),
            direction: "inbound".into(),
            received_at: 1_700_000_000_000,
            modem_imei: Some("867018069509705".into()),
        }],
        modems: vec![LocalModem {
            imei: "867018069509705".into(),
            family: "EC20".into(),
            iccid: None,
            state: "registered".into(),
            last_seen: Some(1_700_000_000_000),
            mcc: Some(460),
            mnc: Some(0),
        home_mcc: None,
        home_mnc: None,
        imsi: None,
        }],
    });
    let app = router(inbox);

    let html = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(html.status(), 200);
    let page = String::from_utf8(html.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();
    // What this test is for is that the router serves the embedded page at all
    // and answers the two local reads below. Which endpoints the page is wired
    // to is asserted by call site in
    // `every_endpoint_the_panel_used_is_still_reachable_from_the_page`; six
    // substring checks here only looked like a second opinion, because every
    // one of them was also satisfied by the copy on the page.
    assert!(page.contains("<!DOCTYPE html>"), "the served page is not the panel");
    assert!(page.contains("x-ref=\"cmd\""), "the command box is not mounted");

    let status = app
        .clone()
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(status.status(), 200);
    let status_json: serde_json::Value =
        serde_json::from_slice(&status.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(status_json["mode"], "local");
    assert_eq!(status_json["modems"][0]["family"], "EC20");

    let messages = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/messages")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let inbox_json: serde_json::Value =
        serde_json::from_slice(&messages.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(inbox_json["messages"][0]["body"], "hello");
}

struct RecordingActions {
    sent: Mutex<Vec<(String, String)>>,
    at: Mutex<Vec<String>>,
    switched: Mutex<Vec<(String, bool)>>,
    ussd: Mutex<Vec<String>>,
    radio: Mutex<Vec<bool>>,
}

impl RecordingActions {
    fn new() -> Self {
        Self {
            sent: Mutex::new(Vec::new()),
            at: Mutex::new(Vec::new()),
            switched: Mutex::new(Vec::new()),
            ussd: Mutex::new(Vec::new()),
            radio: Mutex::new(Vec::new()),
        }
    }
}

impl Actions for RecordingActions {
    fn send_sms(&self, to: String, body: String, _imei: Option<String>) -> Result<(), PanelError> {
        self.sent.lock().expect("sent").push((to, body));
        Ok(())
    }

    fn restart_modem(&self, _imei: String) -> Result<(), PanelError> {
        Ok(())
    }

    fn at_command(&self, _imei: Option<String>, command: String) -> Result<AtResult, PanelError> {
        self.at.lock().expect("at").push(command.clone());
        Ok(AtResult {
            port: "/dev/ttyUSB2".into(),
            command,
            lines: vec!["+CSQ: 24,99".into()],
            terminator: "OK".into(),
            ok: true,
            elapsed_ms: 7,
        })
    }

    fn usb_reset(&self, _imei: Option<String>) -> Result<UsbResetResult, PanelError> {
        Ok(UsbResetResult {
            device: "2-4.1".into(),
            node: "/dev/bus/usb/002/052".into(),
        })
    }

    fn modem_report(&self, imei: Option<String>) -> Result<ReportResult, PanelError> {
        Ok(ReportResult {
            imei,
            port: "/dev/ttyUSB2".into(),
            signal_dbm: Some(-65),
            operator: Some("CHN-UNICOM".into()),
            ..ReportResult::default()
        })
    }

    fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
        Ok(ProfilesResult {
            imei,
            profiles: vec![ProfileBody {
                iccid: "89852351225042214201".into(),
                label: "WEBBING".into(),
                enabled: true,
                provider: Some("Saily".into()),
                name: Some("WEBBING".into()),
                nickname: None,
                class: Some(2),
                isdp_aid: None,
            }],
        })
    }

    fn switch_profile(
        &self,
        _imei: Option<String>,
        iccid: String,
        enable: bool,
    ) -> Result<(), PanelError> {
        self.switched.lock().expect("switched").push((iccid, enable));
        Ok(())
    }

    fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
        Ok(ScanResult {
            imei,
            elapsed_ms: 42_000,
            operators: vec![ScannedOperatorBody {
                numeric: "46001".into(),
                long_name: "CHN-UNICOM".into(),
                short_name: "UNICOM".into(),
                status: "current".into(),
                access_technology: Some("LTE".into()),
            }],
        })
    }

    fn ussd(&self, _imei: Option<String>, code: String) -> Result<UssdResult, PanelError> {
        self.ussd.lock().expect("ussd").push(code.clone());
        Ok(UssdResult {
            code,
            stage: "complete".into(),
            text: "余额 12.30".into(),
            dcs: Some(72),
            expects_reply: false,
            elapsed_ms: 3200,
        })
    }

    fn ussd_cancel(&self, _imei: Option<String>) -> Result<(), PanelError> {
        Ok(())
    }

    fn set_radio(&self, _imei: Option<String>, online: bool) -> Result<(), PanelError> {
        self.radio.lock().expect("radio").push(online);
        Ok(())
    }
}

#[tokio::test]
async fn panel_sends_sms_locally() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/send")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"to":"10086","body":"hi"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        actions.sent.lock().expect("sent").as_slice(),
        &[("10086".into(), "hi".into())]
    );
}

#[tokio::test]
async fn panel_runs_an_at_command() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/at")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"command":"AT+CSQ"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["terminator"], "OK");
    assert_eq!(body["lines"][0], "+CSQ: 24,99");
    assert_eq!(actions.at.lock().expect("at").as_slice(), &["AT+CSQ"]);
}

/// A module that answers `+CME ERROR` has answered. The console must show that
/// as the module's reply, not as a transport failure.
#[tokio::test]
async fn panel_reports_a_rejected_at_command_as_a_reply() {
    struct Rejecting;
    impl Actions for Rejecting {
        fn send_sms(&self, _: String, _: String, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn restart_modem(&self, _: String) -> Result<(), PanelError> {
            Ok(())
        }
        fn at_command(&self, _: Option<String>, command: String) -> Result<AtResult, PanelError> {
            Ok(AtResult {
                port: "/dev/ttyUSB2".into(),
                command,
                lines: Vec::new(),
                terminator: "+CME ERROR: 10".into(),
                ok: false,
                elapsed_ms: 3,
            })
        }

        fn usb_reset(&self, _imei: Option<String>) -> Result<UsbResetResult, PanelError> {
            Ok(UsbResetResult {
                device: "2-4.1".into(),
                node: "/dev/bus/usb/002/052".into(),
            })
        }

        fn modem_report(&self, _: Option<String>) -> Result<ReportResult, PanelError> {
            Ok(ReportResult::default())
        }

        fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
            Ok(ProfilesResult {
                imei,
                profiles: Vec::new(),
            })
        }

        fn switch_profile(&self, _: Option<String>, _: String, _: bool) -> Result<(), PanelError> {
            Ok(())
        }

        fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
            Ok(ScanResult {
                imei,
                elapsed_ms: 0,
                operators: Vec::new(),
            })
        }

        fn ussd(&self, _: Option<String>, code: String) -> Result<UssdResult, PanelError> {
            Ok(UssdResult {
                code,
                stage: "complete".into(),
                text: String::new(),
                dcs: None,
                expects_reply: false,
                elapsed_ms: 0,
            })
        }

        fn ussd_cancel(&self, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn set_radio(&self, _: Option<String>, _: bool) -> Result<(), PanelError> {
            Ok(())
        }
    }

    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(Arc::new(Rejecting)));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/at")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"command":"AT+CPIN?"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["ok"], false);
    assert_eq!(body["terminator"], "+CME ERROR: 10");
}

#[tokio::test]
async fn panel_rejects_an_empty_at_command() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/at")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"command":"   "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.at.lock().expect("at").is_empty());
}

#[tokio::test]
async fn panel_reports_modem_diagnostics() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/report")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"imei":"867018069514820"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["imei"], "867018069514820");
    assert_eq!(body["signal_dbm"], -65);
    assert_eq!(body["operator"], "CHN-UNICOM");
}

#[tokio::test]
async fn panel_lists_euicc_profiles() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/esim")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"imei":"867018069514820"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["profiles"][0]["label"], "WEBBING");
    assert_eq!(body["profiles"][0]["enabled"], true);
}

#[tokio::test]
async fn panel_switches_a_profile_by_iccid() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/esim/switch")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(
                    r#"{"iccid":"89852351225042214201","enable":true}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        actions.switched.lock().expect("switched").as_slice(),
        &[("89852351225042214201".to_string(), true)]
    );
}

/// Switching takes the modem off its network, so an unnamed profile must be
/// refused rather than guessed at.
#[tokio::test]
async fn panel_refuses_a_switch_without_an_iccid() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/esim/switch")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"iccid":"  ","enable":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.switched.lock().expect("switched").is_empty());
}

#[tokio::test]
async fn panel_scans_for_operators() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/scan")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"imei":"867018069514820"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["operators"][0]["numeric"], "46001");
    assert_eq!(body["operators"][0]["status"], "current");
}

/// A modem mid-scan stops answering the poll loop for longer than the
/// staleness window. Reporting that as offline sends the operator looking for
/// a fault that is not there.
#[tokio::test]
async fn panel_reports_a_busy_modem_as_busy_not_offline() {
    struct Busy;
    impl Actions for Busy {
        fn send_sms(&self, _: String, _: String, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn restart_modem(&self, _: String) -> Result<(), PanelError> {
            Ok(())
        }
        fn at_command(&self, _: Option<String>, command: String) -> Result<AtResult, PanelError> {
            Ok(AtResult {
                port: "/dev/ttyUSB2".into(),
                command,
                lines: Vec::new(),
                terminator: "OK".into(),
                ok: true,
                elapsed_ms: 1,
            })
        }
        fn usb_reset(&self, _: Option<String>) -> Result<UsbResetResult, PanelError> {
            Ok(UsbResetResult {
                device: "2-4.1".into(),
                node: "/dev/bus/usb/002/052".into(),
            })
        }
        fn modem_report(&self, _: Option<String>) -> Result<ReportResult, PanelError> {
            Ok(ReportResult::default())
        }
        fn list_profiles(&self, imei: Option<String>) -> Result<ProfilesResult, PanelError> {
            Ok(ProfilesResult {
                imei,
                profiles: Vec::new(),
            })
        }
        fn switch_profile(&self, _: Option<String>, _: String, _: bool) -> Result<(), PanelError> {
            Ok(())
        }
        fn scan_operators(&self, imei: Option<String>) -> Result<ScanResult, PanelError> {
            Ok(ScanResult {
                imei,
                elapsed_ms: 0,
                operators: Vec::new(),
            })
        }
        fn ussd(&self, _: Option<String>, code: String) -> Result<UssdResult, PanelError> {
            Ok(UssdResult {
                code,
                stage: "complete".into(),
                text: String::new(),
                dcs: None,
                expects_reply: false,
                elapsed_ms: 0,
            })
        }

        fn ussd_cancel(&self, _: Option<String>) -> Result<(), PanelError> {
            Ok(())
        }
        fn set_radio(&self, _: Option<String>, _: bool) -> Result<(), PanelError> {
            Ok(())
        }

        fn busy_modems(&self) -> Vec<String> {
            vec!["867018069509705".into()]
        }
    }

    // last_seen far in the past, so without the busy marker this is "Offline".
    let inbox = Arc::new(MemoryInbox {
        messages: Vec::new(),
        modems: vec![LocalModem {
            imei: "867018069509705".into(),
            family: "EC20".into(),
            iccid: None,
            state: "Registered".into(),
            last_seen: Some(1_700_000_000_000),
            mcc: None,
            mnc: None,
        home_mcc: None,
        home_mnc: None,
        imsi: None,
        }],
    });
    let app = router_with_actions(inbox, Some(Arc::new(Busy)));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .uri("/api/status")
                .body(axum::body::Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["modems"][0]["state"], "Busy");
}

#[tokio::test]
async fn panel_runs_a_ussd_session() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/ussd")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"code":"*100#"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let body: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(body["text"], "余额 12.30");
    assert_eq!(body["expects_reply"], false);
    assert_eq!(actions.ussd.lock().expect("ussd").as_slice(), &["*100#"]);
}

#[tokio::test]
async fn panel_rejects_an_empty_ussd_code() {
    let actions = Arc::new(RecordingActions::new());
    let app = router_with_actions(Arc::new(MemoryInbox::default()), Some(actions.clone()));
    let response = app
        .oneshot(
            axum::http::Request::builder()
                .method("POST")
                .uri("/api/ussd")
                .header("content-type", "application/json")
                .body(axum::body::Body::from(r#"{"code":"  "}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 400);
    assert!(actions.ussd.lock().expect("ussd").is_empty());
}
