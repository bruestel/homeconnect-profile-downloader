//! The sign-in window, in a process of its own.
//!
//! It opens Home Connect's sign-in page in a webview and catches the redirect
//! that carries the authorization code, then prints the code and ends.
//!
//! The Electron version did this with `session.webRequest.onBeforeRequest`,
//! which cancels the navigation to `hcauth://auth/prod?code=...` and reads the
//! code off the URL (`main.js:161`). There is no webRequest API outside
//! Electron; `with_navigation_handler` is the replacement, it sees every
//! navigation and `false` cancels it. Whether it is handed a URL whose scheme
//! the platform does not know was the question the whole port hung on, and it
//! is answered on all three systems: see `doc/oauth-webview.md`.
//!
//! A separate process on purpose: iced and tao each want to own the event loop,
//! and they cannot both have it. This one owns it for as long as a sign-in
//! takes, and the code goes back over stdout. A crash here therefore cannot
//! take the application with it.
//!
//!   hcpd-login <authorize-url>
//!   hcpd-login --selftest        no account needed, see below
//!
//!   stdout  exactly one JSON line: {"code":"..."} | {"error":"..."}
//!   stderr  the navigation trace
//!
//! `--selftest` loads a page of our own whose only job is to navigate to
//! `hcauth://auth/prod?code=SELFTEST`, so the unknown scheme reaches the handler
//! with no account, no network and nothing to type. It exits 0 or 1, which is
//! what makes it runnable over `windows/run.sh` and `macos/run.sh` in the VMs
//! rather than by hand.

// No console. Without this Windows gives a console application a window of its
// own, and a black box appearing beside the sign-in looks like something has
// gone wrong. The pipes the application reads are inherited either way, so
// nothing is lost; only a terminal running this by hand loses the printout,
// which is why a debug build keeps its console.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::{Arc, Mutex};
use tao::{
    event::{Event, StartCause, WindowEvent},
    event_loop::{ControlFlow, EventLoopBuilder},
    window::WindowBuilder,
};
use wry::WebViewBuilder;

// The same user agent Electron sets on the whole session (main.js:172). The
// login page serves its mobile layout on the strength of it, so whether it
// arrives is part of what this measures.
const USER_AGENT: &str = "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/131.0.0.0 Mobile Safari/537.36";

/// Sent from the navigation handler to the event loop, because the handler runs
/// on the webview's own thread and must not block it.
enum Signal {
    Done,
    Timeout,
}

/// Is this the redirect we are waiting for?
///
/// Deliberately wider than `hcauth://`: Electron filters on `*://*/auth/prod*`,
/// which says the scheme was never the identifying part. If a platform rewrites
/// or normalises the unknown scheme before we see it, this still catches the
/// URL, and the stderr trace then says which form actually arrived, which is
/// the more useful failure.
fn is_redirect(url: &url::Url) -> bool {
    let path = format!("{}{}", url.host_str().unwrap_or(""), url.path());
    url.scheme() == "hcauth" || path.contains("auth/prod")
}

const SELFTEST_PAGE: &str = r#"<!DOCTYPE html>
<html><body style="font:14px system-ui;padding:2rem">
<p>Self test: navigating to hcauth://auth/prod in a moment.</p>
<script>
  setTimeout(function () {
    location.href = "hcauth://auth/prod?code=SELFTEST&state=spike";
  }, 400);
</script>
</body></html>"#;

/// Tells macOS what to call this process.
///
/// The menu bar takes an application's name from the process, not from a
/// bundle: an `Info.plist` linked into the binary gives it an identifier and a
/// version but leaves the name alone, which is how "hcpd-login" ended up in the
/// menu. The main application escapes this by being a bundle; the helper is a
/// bare executable inside one and never will be.
///
/// `setProcessName:` is the documented setter for exactly this. It has to
/// happen before the menu is built, because the menu bar reads the name once.
#[cfg(target_os = "macos")]
fn set_process_name(name: &str) {
    use objc2::msg_send;
    use objc2_foundation::{NSProcessInfo, NSString};

    let info = NSProcessInfo::processInfo();
    let name = NSString::from_str(name);
    unsafe {
        let _: () = msg_send![&*info, setProcessName: &*name];
    }
}

/// Gives the application an Edit menu, on macOS, so the keyboard works.
///
/// Not decoration. On macOS a keyboard shortcut reaches a text field by way of
/// the application menu: `Cmd+V` is delivered to whichever menu item is bound
/// to the paste selector, and an application with no menu has no such item, so
/// the key does nothing at all. The right-click menu is the webview's own and
/// works either way, which is what makes this easy to miss.
///
/// The Electron version learnt this as issue #5, "can't paste password", and
/// fixed it the same way (`7d3e6c2`). Reproducing the bug in a rewrite would
/// have been a poor way to greet the people who reported it.
#[cfg(target_os = "macos")]
fn install_edit_menu() {
    use muda::{Menu, PredefinedMenuItem, Submenu};

    set_process_name("Home Connect Login");

    let menu = Menu::new();

    // The first submenu is the application menu whatever it is called, and
    // macOS expects Quit to live there.
    let app = Submenu::new("Home Connect Login", true);
    let _ = app.append_items(&[
        &PredefinedMenuItem::hide(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::quit(None),
    ]);

    let edit = Submenu::new("Edit", true);
    let _ = edit.append_items(&[
        &PredefinedMenuItem::undo(None),
        &PredefinedMenuItem::redo(None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::cut(None),
        &PredefinedMenuItem::copy(None),
        &PredefinedMenuItem::paste(None),
        &PredefinedMenuItem::select_all(None),
    ]);

    let _ = menu.append_items(&[&app, &edit]);
    menu.init_for_nsapp();
}

#[cfg(not(target_os = "macos"))]
fn install_edit_menu() {}

/// Where WebView2 keeps its profile.
///
/// Under `%LOCALAPPDATA%`, which is what that variable is for, and never beside
/// the executable. The fallback is the temporary directory: a cache that cannot
/// be kept is still a working sign-in, only a slower second one.
#[cfg(target_os = "windows")]
fn webview_directory() -> std::path::PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir)
        .join("hcpd")
        .join("webview")
}

fn main() {
    let Some(argument) = std::env::args().nth(1) else {
        println!(r#"{{"error":"no authorize URL was given"}}"#);
        std::process::exit(2);
    };
    let selftest = argument == "--selftest";

    // Holds whatever the handler found, read once the loop has stopped. A
    // channel would do as well; a mutex keeps the shutdown path to one branch.
    let outcome: Arc<Mutex<Option<Result<String, String>>>> = Arc::new(Mutex::new(None));

    let event_loop = EventLoopBuilder::<Signal>::with_user_event().build();
    let proxy = event_loop.create_proxy();

    let window = WindowBuilder::new()
        .with_title("Home Connect Login")
        .with_inner_size(tao::dpi::LogicalSize::new(480.0, 800.0))
        .build(&event_loop)
        .expect("the window builds");

    let handler_outcome = Arc::clone(&outcome);
    let handler = move |raw: String| -> bool {
        let parsed = url::Url::parse(&raw);
        let scheme = parsed.as_ref().map(|u| u.scheme().to_string()).unwrap_or_default();
        // Truncated: these carry a code and a state, and the trace is meant to
        // be pasted into a report.
        let shown: String = raw.chars().take(110).collect();
        eprintln!("nav [{scheme}] {shown}");

        let Ok(url) = parsed else { return true };
        if !is_redirect(&url) {
            return true;
        }

        eprintln!("=== redirect caught ===");

        let mut slot = handler_outcome.lock().unwrap();
        if slot.is_some() {
            // WebKitGTK asks about one navigation more than once.
            eprintln!("redirect seen again, ignored");
            return false;
        }

        *slot = match url.query_pairs().find(|(k, _)| k == "code") {
            Some((_, code)) => {
                eprintln!("code received, {} characters", code.len());
                Some(Ok(code.into_owned()))
            }
            None => {
                let error = url
                    .query_pairs()
                    .find(|(k, _)| k == "error")
                    .map(|(_, v)| v.into_owned())
                    .unwrap_or_else(|| "no code in the redirect URL".into());
                eprintln!("no code: {error}");
                Some(Err(error))
            }
        };
        drop(slot);

        let _ = proxy.send_event(Signal::Done);
        // The point of the exercise: the navigation never happens.
        false
    };

    // WebView2 puts its user data folder beside the executable that opened it,
    // which on Windows means inside the installation directory. The uninstaller
    // deletes the three files it wrote and then calls `RMDir`, which removes
    // only an empty directory, so a whole browser profile with its caches was
    // left behind with nothing pointing at it any more. Measured in the test
    // VM, not deduced. Naming the directory puts it where a cache belongs.
    //
    // Windows only. On Linux and macOS the builder without a context is not the
    // same as one with an empty context: it gets an ephemeral one, and for a
    // sign-in window that is the better default, so it stays.
    #[cfg(target_os = "windows")]
    let mut context = wry::WebContext::new(Some(webview_directory()));

    #[cfg(target_os = "windows")]
    let builder = WebViewBuilder::new_with_web_context(&mut context);
    #[cfg(not(target_os = "windows"))]
    let builder = WebViewBuilder::new();

    let builder = builder.with_user_agent(USER_AGENT).with_navigation_handler(handler);
    // A page of ours first, with the sign-in loaded over it afterwards.
    //
    // Measured on the way here: the window is up in a quarter of a second, and
    // Home Connect's redirect chain through SingleKey ID takes sixteen more
    // before anything is drawn. A blank white window standing there that long
    // does not look like waiting, it looks like a crash.
    // Only the self test gets a page of its own. There used to be a waiting
    // page here for the sign-in as well, with a bar on it, on the reasoning that
    // an empty window looks like a crash. It was not worth its keep: it stands
    // for the first hop of a chain that is seven pages long, so it vanishes long
    // before the waiting is over and buys nothing.
    let builder = if selftest { builder.with_html(SELFTEST_PAGE) } else { builder };

    #[cfg(not(target_os = "linux"))]
    let webview = builder.build(&window).expect("the webview builds");
    #[cfg(target_os = "linux")]
    let webview = {
        // On Linux a tao window is a GTK window, and wry attaches to its box
        // rather than to a raw handle.
        use tao::platform::unix::WindowExtUnix;
        use wry::WebViewBuilderExtUnix;
        builder
            .build_gtk(window.default_vbox().expect("the window has a GTK container"))
            .expect("the webview builds")
    };

    // After the event loop, because it needs the NSApplication that tao creates.
    install_edit_menu();

    if !selftest {
        webview.load_url(&argument).expect("the sign-in URL loads");
    }

    eprintln!("webview open, waiting for the sign-in");

    // Nothing here may hang a VM run. The handler normally ends this long
    // before the deadline; if it does not, that silence is itself the finding.
    {
        let proxy = event_loop.create_proxy();
        let limit = if selftest { 20 } else { 600 };
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_secs(limit));
            let _ = proxy.send_event(Signal::Timeout);
        });
    }

    event_loop.run(move |event, _, control_flow| {
        *control_flow = ControlFlow::Wait;
        match event {
            Event::NewEvents(StartCause::Init) => {}
            Event::UserEvent(Signal::Timeout) => {
                eprintln!("time limit reached without the handler seeing the redirect");
                // Said out loud, on stdout. Leaving only the trace on stderr
                // meant the caller saw an empty answer, and an empty answer is
                // how a closed window reports itself, so ten minutes of waiting
                // came back as "Sign-in cancelled." and blamed the user for it.
                println!("{}", serde_json::json!({ "error": "The sign-in window timed out." }));
                *control_flow = ControlFlow::Exit;
            }
            Event::UserEvent(Signal::Done)
            | Event::WindowEvent { event: WindowEvent::CloseRequested, .. } => {
                let found = outcome.lock().unwrap().take();
                // One of the two writers to stdout, the other being the
                // timeout above, and exactly one of them ever runs: the timeout
                // ends the loop, so this arm cannot follow it.
                let (line, ok) = match found {
                    Some(Ok(code)) => (serde_json::json!({ "code": code }), true),
                    Some(Err(error)) => (serde_json::json!({ "error": error }), false),
                    None => (serde_json::json!({ "error": "Sign-in cancelled." }), false),
                };
                println!("{line}");
                if selftest {
                    // An exit code, so a VM run needs no output parsing.
                    std::process::exit(if ok { 0 } else { 1 });
                }
                *control_flow = ControlFlow::Exit;
            }
            _ => {}
        }
    });
}
