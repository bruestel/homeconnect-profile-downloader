# Catching the OAuth redirect without Electron

The one question the Rust port hung on:

> Can the authorization code be taken out of the Home Connect sign-in without
> Electron's `session.webRequest.onBeforeRequest`?

Yes, on all three systems. wry's `with_navigation_handler` sees every
navigation the webview is about to make and cancels it by returning `false`,
which is what `login-helper/` does with `hcauth://auth/prod`.

## Measured

On 2026-09-01, with `--selftest`, which navigates to the redirect URI itself and
therefore needs no account. Windows and macOS in the VMs the prwatch project
builds.

| | Linux (WebKitGTK) | Windows (WebView2) | macOS (WKWebView) |
| --- | --- | --- | --- |
| The handler fires at all | yes | yes | yes |
| **It fires on `hcauth://`** | **yes** | **yes** | **yes** |
| The code is read from the URL | yes | yes | yes |

The trace is the same on all three:

```
webview open, waiting for the sign-in
nav [about] about:blank
nav [hcauth] hcauth://auth/prod?code=SELFTEST&state=spike
=== redirect caught ===
code received, 8 characters
{"code":"SELFTEST"}
```

Only the first line differs: WebView2 reports the self test page as
`nav [data] data:text/html;base64,…` where the other two say `about:blank`. That
is the test page, not the redirect.

Three things that came out of it sideways, all worth keeping:

- **Windows needs no interactive desktop for this.** The self test ran through
  `VBoxManage guestcontrol`, in session 0 with no visible desktop, and WebView2
  navigated anyway. No window appears there, but the navigation happens, so the
  self test is drivable entirely from the host. The application itself is not.
- **macOS the same over ssh**, without `launchctl asuser`, as long as the same
  user is logged in at the console.
- Windows prints `Failed to unregister class Chrome_WidgetWin_0. Error = 1412`
  after the redirect is caught, while tearing the window down, and exits 0. A
  cleanup warning, not a failure, noted here so the next run does not read it as
  one.

## What the real sign-in adds

The self test triggers the navigation itself. A real sign-in was run later, and
the chain is longer than the code suggests, seven documents before the form:

```
api.home-connect.com/security/oauth/authorize
  -> singlekey-id.com/auth/connect/authorize
  -> singlekey-id.com/auth/login
  -> singlekey-id.com/login
  -> singlekey-id.com/login?f=...
  -> singlekey-id.com/de-de/login
  -> newassets.hcaptcha.com/...  (in an iframe)
```

Two things follow. Home Connect hands the sign-in to SingleKey ID, so the page
in the webview belongs to a third party and can change without notice. And it
loads hCaptcha, which is worth knowing before someone reports that the login
window is asking them to pick out traffic lights.

The navigation handler sees every one of those and lets them through. It only
interferes at the end, when the scheme is one nothing on the system handles.

A waiting page of ours used to stand in front of this, with a progress bar on
it. It was removed: it belongs to the first of those seven documents and is gone
long before the waiting is over.

## Why iced, and not one of the others

No widely used Rust toolkit uses real system widgets on all three platforms.
They all draw their own, so the choice is about how well, and about the shape of
the code.

egui and iced were both built out with the same window, the same sections in the
same order and the same words, so that nothing stood between the two but the
toolkit. They look alike. The code does not: egui reads state directly and needs
a channel plus a requested repaint for the sign-in thread, hand-built, while
iced has a way meant for exactly that in `Task::run` with a stream. In exchange
every state change goes through a `Message` and `update`.

Two roads not taken, for the record. **Slint** does have per-platform styles
(`fluent`, `cupertino`), and a licence decision to go with them: GPLv3 or
commercial, which an MIT project has to make deliberately. **gtk4-rs** is the
only genuinely native option, and it is native on exactly one of the three.

Themes: iced ships 22, and all but `Light` and `Dark` are editor colour schemes,
Dracula and Nord and the rest. They look good and make a window look like a code
editor, which is the wrong target for a tool that should feel at home on the
system. `iced::system::theme()` and `theme_changes()` follow the system instead,
and that is what the application does.
