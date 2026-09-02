//! Home Connect Profile Downloader.
//!
//! Sign in, and every appliance on the account is pulled into memory. Nothing
//! is written until you ask for it, and then you say which of the three formats
//! you want. All three come out of the same material, so a second one costs
//! nothing and no second sign-in.
//!
//! The sign-in is the only web page in the whole application, it belongs to
//! Home Connect, and it lives in a second process that ends with it.
//! See `login-helper`.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod job;

use chrono::{DateTime, Local};
use hcpd_core::settings::Settings;
use hcpd_core::{Region, Target, naming};
use iced::theme::Palette;
use iced::widget::{button, column, container, pick_list, row, scrollable, text};
use iced::{Center, Color, Element, Fill, Font, Task, Theme, window};
use std::path::PathBuf;
use std::time::Instant;

// --- what the window is looking at ---------------------------------------

/// The lower half shows one of two things. They are wanted at different
/// moments, the steps while a fetch is going and the appliances afterwards, so
/// they take turns instead of splitting the window.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Panel {
    Activity,
    Downloads,
}

/// One entry in the activity list, in the shape a build log has: a heading that
/// says what is happening, and detail underneath that is usually not wanted.
struct Step {
    title: String,
    detail: Vec<String>,
    state: StepState,
    /// Raised by a warning while the step is still open, and read when it
    /// closes: a step cannot be marked warned before the warning arrives.
    warned: bool,
    started: Instant,
    took: Option<f32>,
    expanded: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum StepState {
    Running,
    Done,
    /// Finished, but with something the user should read. Stays expanded, for
    /// the same reason a failure does: folding it away is how a warning goes
    /// unread.
    Warned,
    Failed,
}

/// One fetch, held in memory. Any format can still be written from it.
struct Fetch {
    at: DateTime<Local>,
    items: Vec<job::Fetched>,
    saved: Option<Result<String, String>>,
    /// Where the last save went, so the folder button opens that one rather
    /// than wherever the next save happens to be pointed.
    last_destination: Option<PathBuf>,
}

/// The save dialog, which is a window of its own.
///
/// Inline in the list it read as part of the entry it belonged to, which it is
/// not: it asks two questions and then does something. A window is what that
/// is.
struct SaveDialog {
    window: window::Id,
    /// Which fetch it will write. Held by index, and the list only ever grows
    /// at the front, so the dialog is closed whenever a fetch is added.
    fetch: usize,
    target: Target,
    destination: PathBuf,
}

struct State {
    region: Region,
    panel: Panel,
    steps: Vec<Step>,
    fetches: Vec<Fetch>,
    running: bool,
    theme: Theme,
    /// The window everything but the save dialog is drawn in.
    main_window: Option<window::Id>,
    dialog: Option<SaveDialog>,
    /// The region and the last destination, remembered between runs.
    settings: Settings,
    /// Offered under a failed step when the token named a different region.
    suggested_region: Option<Region>,
}

#[derive(Clone, Debug)]
enum Message {
    RegionPicked(Region),
    PanelPicked(Panel),
    Start,
    Step(String),
    Detail(String),
    Warning(String),
    WrongRegion(Region),
    Finished(Result<Vec<job::Fetched>, String>),
    ToggleStep(usize),
    OpenDialog(usize),
    CloseDialog,
    DialogTarget(Target),
    ChooseDestination,
    DestinationChosen(Option<PathBuf>),
    Save,
    MainWindowOpened(window::Id),
    WindowClosed(window::Id),
    OpenFolder(PathBuf),
    RetryIn(Region),
    /// The system said light or dark, at boot and whenever it changes.
    SystemTheme(iced::theme::Mode),
}

impl Default for State {
    fn default() -> Self {
        let settings = Settings::load();
        Self {
            // Asked once and then remembered: the account does not move.
            region: settings.region,
            panel: Panel::Activity,
            steps: Vec::new(),
            fetches: Vec::new(),
            running: false,
            theme: theme(false),
            main_window: None,
            dialog: None,
            settings,
            suggested_region: None,
        }
    }
}

impl State {
    /// Where a save should go by default: wherever the last one went, if that
    /// folder is still there, and the download folder otherwise.
    fn destination(&self) -> PathBuf {
        self.settings.destination_or_default()
    }
}

impl State {
    fn open_step(&mut self, title: String) {
        self.close_step(StepState::Done);
        self.steps.push(Step {
            title,
            detail: Vec::new(),
            state: StepState::Running,
            warned: false,
            started: Instant::now(),
            took: None,
            // The step in progress is the one worth reading, so it is the one
            // left open. It closes itself when the next one starts.
            expanded: true,
        });
    }

    fn close_step(&mut self, state: StepState) {
        if let Some(step) = self.steps.last_mut()
            && step.state == StepState::Running
        {
            // A warning outranks a plain success, and a failure outranks both.
            step.state = match (state, step.warned) {
                (StepState::Done, true) => StepState::Warned,
                (state, _) => state,
            };
            step.took = Some(step.started.elapsed().as_secs_f32());
            // A step that failed or warned keeps its detail on screen, because
            // that is where the reason is.
            step.expanded = matches!(step.state, StepState::Failed | StepState::Warned);
        }
    }
}

// --- what happens ---------------------------------------------------------

/// Window defaults, with the application id set where a system has one.
///
/// On Linux the desktop matches a window to its launcher by this id, and the
/// match is what puts our icon on the task bar entry instead of a blank. It has
/// to be the basename of the `.desktop` file, which is why both say `hcpd`.
/// Everywhere else this is simply the default settings.
/// The icon the window carries, on the systems where a window carries one.
///
/// Raw pixels, decoded by the build script, so nothing here reads a PNG at
/// startup. On Wayland this is ignored and the desktop uses the application id
/// instead; see `linux_identity`.
fn window_icon() -> Option<window::Icon> {
    const PIXELS: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/icon.rgba"));
    let size: u32 = env!("HCPD_ICON_SIZE").parse().ok()?;
    window::icon::from_rgba(PIXELS.to_vec(), size, size).ok()
}

fn linux_identity() -> window::Settings {
    let base = window::Settings { icon: window_icon(), ..window::Settings::default() };

    #[cfg(target_os = "linux")]
    {
        window::Settings {
            platform_specific: window::settings::PlatformSpecific {
                application_id: "hcpd".to_owned(),
                ..Default::default()
            },
            ..base
        }
    }
    #[cfg(not(target_os = "linux"))]
    base
}

/// Gives the application a menu bar, on macOS.
///
/// Not decoration. On macOS every keyboard shortcut is delivered by way of the
/// menu, so an application without one has no Cmd+Q to quit with and no Cmd+C
/// anywhere. The sign-in window is a separate process and installs its own; this
/// is the one for the main window.
///
/// Edit is there even though this window has no text field of its own, because
/// it costs one submenu and its absence is the sort of thing that turns up
/// later, in a place nobody thought to check.
#[cfg(target_os = "macos")]
fn install_menu() {
    use muda::{Menu, PredefinedMenuItem, Submenu};

    // The menu bar takes the name from the process, not from a bundle, so a
    // binary run out of target/debug is called "hcpd" there. Inside the .app
    // the bundle already says the same thing, so this changes nothing that is
    // shipped and fixes what a developer sees.
    {
        use objc2::msg_send;
        use objc2_foundation::{NSProcessInfo, NSString};

        let info = NSProcessInfo::processInfo();
        let name = NSString::from_str("Home Connect Profile Downloader");
        unsafe {
            let _: () = msg_send![&*info, setProcessName: &*name];
        }
    }

    let menu = Menu::new();

    // The first submenu is the application menu, whatever it is called, and
    // macOS expects Quit to be in it.
    let app = Submenu::new("Home Connect Profile Downloader", true);
    let _ = app.append_items(&[
        &PredefinedMenuItem::about(None, None),
        &PredefinedMenuItem::separator(),
        &PredefinedMenuItem::hide(None),
        &PredefinedMenuItem::hide_others(None),
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

    let window = Submenu::new("Window", true);
    let _ = window.append_items(&[
        &PredefinedMenuItem::minimize(None),
        &PredefinedMenuItem::close_window(None),
    ]);

    let _ = menu.append_items(&[&app, &edit, &window]);
    menu.init_for_nsapp();
}

#[cfg(not(target_os = "macos"))]
fn install_menu() {}

fn boot() -> (State, Task<Message>) {
    // A daemon starts with no windows at all, so the main one is opened here
    // rather than described in a builder.
    let (_, opened) = window::open(window::Settings {
        size: iced::Size::new(780.0, 720.0),
        min_size: Some(iced::Size::new(560.0, 480.0)),
        position: window::Position::Centered,
        ..linux_identity()
    });

    (
        State::default(),
        Task::batch([
            opened.map(Message::MainWindowOpened),
            iced::system::theme().map(Message::SystemTheme),
        ]),
    )
}

fn update(state: &mut State, message: Message) -> Task<Message> {
    match message {
        Message::RegionPicked(region) => {
            state.region = region;
            state.settings.region = region;
            state.settings.store();
            Task::none()
        }
        Message::PanelPicked(panel) => {
            state.panel = panel;
            Task::none()
        }
        Message::Start => {
            state.running = true;
            state.steps.clear();
            state.suggested_region = None;
            state.panel = Panel::Activity;

            let region = state.region;
            // The fetch is blocking and belongs on a thread of its own; the
            // channel turns its progress back into messages. An unbounded
            // sender is what makes that possible: it can be called from that
            // thread without an executor.
            Task::run(
                iced::stream::channel(
                    64,
                    move |mut output: iced::futures::channel::mpsc::Sender<Message>| async move {
                        use iced::futures::{SinkExt, StreamExt};

                        let (sender, mut receiver) = iced::futures::channel::mpsc::unbounded();
                        std::thread::spawn(move || {
                            let report = |progress: job::Progress| {
                                let _ = sender.unbounded_send(match progress {
                                    job::Progress::Step(title) => Message::Step(title),
                                    job::Progress::Detail(line) => Message::Detail(line),
                                    job::Progress::Warning(line) => Message::Warning(line),
                                    job::Progress::WrongRegion(region) => {
                                        Message::WrongRegion(region)
                                    }
                                });
                            };
                            let _ = sender
                                .unbounded_send(Message::Finished(job::fetch(region, &report)));
                        });

                        while let Some(message) = receiver.next().await {
                            let _ = output.send(message).await;
                        }
                    },
                ),
                |message| message,
            )
        }
        Message::Step(title) => {
            state.open_step(title);
            Task::none()
        }
        Message::Detail(line) => {
            if let Some(step) = state.steps.last_mut() {
                step.detail.push(line);
            }
            Task::none()
        }
        Message::Warning(line) => {
            if let Some(step) = state.steps.last_mut() {
                step.detail.push(line);
                step.warned = true;
            }
            Task::none()
        }
        Message::WrongRegion(region) => {
            state.suggested_region = Some(region);
            Task::none()
        }
        Message::Finished(Ok(items)) => {
            state.close_step(StepState::Done);
            state.running = false;
            // The choice worked, whatever the token said about it.
            state.suggested_region = None;
            // The dialog holds an index into a list that is about to shift.
            let close = match state.dialog.take() {
                Some(dialog) => window::close(dialog.window),
                None => Task::none(),
            };
            state
                .fetches
                .insert(0, Fetch { at: Local::now(), items, saved: None, last_destination: None });
            // The appliances are the point of the exercise, so the window ends
            // on them rather than on steps that have all succeeded.
            state.panel = Panel::Downloads;
            close
        }
        Message::Finished(Err(error)) => {
            if let Some(step) = state.steps.last_mut() {
                step.detail.push(error);
            }
            state.close_step(StepState::Failed);
            state.running = false;
            Task::none()
        }
        Message::ToggleStep(index) => {
            if let Some(step) = state.steps.get_mut(index) {
                step.expanded = !step.expanded;
            }
            Task::none()
        }
        Message::OpenDialog(index) => {
            let destination = state.destination();
            if let Some(fetch) = state.fetches.get_mut(index) {
                fetch.saved = None;
            }
            // Only ever one at a time: a second would have to say which fetch
            // it belonged to, and the list already does.
            let close_previous = match state.dialog.take() {
                Some(previous) => window::close(previous.window),
                None => Task::none(),
            };

            let (id, opened) = window::open(window::Settings {
                size: iced::Size::new(560.0, 260.0),
                min_size: Some(iced::Size::new(460.0, 240.0)),
                position: window::Position::Centered,
                resizable: false,
                ..linux_identity()
            });
            state.dialog = Some(SaveDialog {
                window: id,
                fetch: index,
                target: Target::HomeConnectDirect,
                destination,
            });
            Task::batch([close_previous, opened.discard()])
        }
        Message::CloseDialog => match state.dialog.take() {
            Some(dialog) => window::close(dialog.window),
            None => Task::none(),
        },
        Message::DialogTarget(target) => {
            if let Some(dialog) = state.dialog.as_mut() {
                dialog.target = target;
            }
            Task::none()
        }
        Message::ChooseDestination => {
            let Some(start) = state.dialog.as_ref().map(|d| d.destination.clone()) else {
                return Task::none();
            };
            // The system's own chooser, asked for asynchronously: the blocking
            // form would hold the window still while the portal talks to the
            // desktop.
            Task::perform(
                async move {
                    rfd::AsyncFileDialog::new()
                        .set_title("Where should the profiles go?")
                        .set_directory(start)
                        .pick_folder()
                        .await
                        .map(|handle| handle.path().to_path_buf())
                },
                Message::DestinationChosen,
            )
        }
        Message::DestinationChosen(Some(folder)) => {
            if let Some(dialog) = state.dialog.as_mut() {
                dialog.destination = folder;
            }
            Task::none()
        }
        // The chooser was dismissed, which is not a decision to record.
        Message::DestinationChosen(None) => Task::none(),
        Message::Save => {
            let Some(dialog) = state.dialog.take() else { return Task::none() };
            let Some(fetch) = state.fetches.get_mut(dialog.fetch) else {
                return window::close(dialog.window);
            };

            // Writing a few megabytes and parsing the documents again takes
            // long enough to notice but not long enough to move off the main
            // thread and have to report on.
            fetch.saved =
                Some(job::save(&fetch.items, dialog.target, &dialog.destination).map(|written| {
                    format!(
                        "{} written to {}",
                        job::plural(written.len(), "file", "files"),
                        dialog.destination.display()
                    )
                }));

            if fetch.saved.as_ref().is_some_and(Result::is_ok) {
                fetch.last_destination = Some(dialog.destination.clone());
                state.settings.destination = Some(dialog.destination);
                state.settings.store();
            }
            window::close(dialog.window)
        }
        Message::MainWindowOpened(id) => {
            state.main_window = Some(id);
            // Here, and not in boot: the menu attaches to the NSApplication,
            // and boot runs before there is a window to prove one exists. Done
            // too early it is quietly replaced by the default menu, which is
            // the one that reads "hcpd".
            install_menu();
            Task::none()
        }
        Message::WindowClosed(id) => {
            if state.dialog.as_ref().is_some_and(|dialog| dialog.window == id) {
                // Closed from its own title bar rather than by a button.
                state.dialog = None;
                return Task::none();
            }
            if state.main_window == Some(id) {
                // A daemon outlives its windows, so the last one going has to
                // say so.
                return iced::exit();
            }
            Task::none()
        }
        Message::RetryIn(region) => {
            state.region = region;
            state.settings.region = region;
            state.settings.store();
            update(state, Message::Start)
        }
        Message::OpenFolder(folder) => {
            open_folder(&folder);
            Task::none()
        }
        Message::SystemTheme(mode) => {
            // `None` means the system has no opinion, and a light window is the
            // safer guess than a dark one on a light desktop.
            state.theme = theme(matches!(mode, iced::theme::Mode::Dark));
            Task::none()
        }
    }
}

// --- what it looks like ---------------------------------------------------

fn view(state: &State, window: window::Id) -> Element<'_, Message> {
    match &state.dialog {
        Some(dialog) if dialog.window == window => save_dialog(state, dialog),
        _ => main_window(state),
    }
}

/// The two questions a save asks, in a window of their own.
fn save_dialog<'a>(state: &'a State, dialog: &'a SaveDialog) -> Element<'a, Message> {
    let count = state.fetches.get(dialog.fetch).map(|fetch| fetch.items.len()).unwrap_or(0);

    let field = |label: &'static str, control: Element<'a, Message>| {
        row![text(label).size(FORM_TEXT).style(muted).width(84), control]
            .spacing(10)
            .align_y(Center)
    };

    container(
        column![
            column![
                text("Save profiles").size(17),
                text(format!(
                    "{} from this fetch, written in the format the target expects.",
                    job::plural(count, "appliance", "appliances")
                ))
                .size(FORM_TEXT)
                .style(muted),
            ]
            .spacing(4),
            field(
                "Variant",
                pick_list(Target::ALL, Some(dialog.target), Message::DialogTarget)
                    .width(Fill)
                    .text_size(FORM_TEXT)
                    .padding([FORM_PAD_Y, CONTROL_PAD_X_PICKER])
                    .into(),
            ),
            field(
                "Destination",
                row![
                    text(dialog.destination.display().to_string())
                        .size(12)
                        .font(Font::MONOSPACE)
                        .width(Fill),
                    button(text("Choose").size(FORM_TEXT))
                        .padding([FORM_PAD_Y, 13.0])
                        .style(button::secondary)
                        .on_press(Message::ChooseDestination),
                ]
                .spacing(10)
                .align_y(Center)
                .into(),
            ),
            // Pushed to the bottom, where a dialog's buttons belong.
            container(text("")).height(Fill),
            row![
                container(text("")).width(Fill),
                button(text("Cancel").size(CONTROL_TEXT))
                    .padding([CONTROL_PAD_Y, CONTROL_PAD_X_BUTTON])
                    .style(button::text)
                    .on_press(Message::CloseDialog),
                button(text("Save").size(CONTROL_TEXT))
                    .padding([CONTROL_PAD_Y, CONTROL_PAD_X_BUTTON])
                    .on_press(Message::Save),
            ]
            .spacing(9),
        ]
        .spacing(16),
    )
    .padding(22)
    .width(Fill)
    .height(Fill)
    .into()
}

fn main_window(state: &State) -> Element<'_, Message> {
    let head = column![
        text("Home Connect Profile Downloader").size(20),
        text(
            "Signing in collects every appliance on your account. Nothing is written \
             until you save it, and then you choose the format."
        )
        .size(13)
        .style(muted),
    ]
    .spacing(5);

    let controls = card(
        column![
            row![
                text("Region").size(14).width(70),
                // Fill rather than a fixed width: the longest label is
                // "North America cloud (USA, Canada, ...)" today and the next
                // one is a sentence away from being longer. A picker that grows
                // with the window cannot clip its own text.
                pick_list(Region::ALL, Some(state.region), Message::RegionPicked)
                    .width(Fill)
                    .text_size(CONTROL_TEXT)
                    .padding([CONTROL_PAD_Y, CONTROL_PAD_X_PICKER]),
                button(text("Sign in and fetch").size(CONTROL_TEXT))
                    .padding([CONTROL_PAD_Y, CONTROL_PAD_X_BUTTON])
                    .on_press_maybe((!state.running).then_some(Message::Start)),
            ]
            .spacing(12)
            .align_y(Center),
            text("Which of Home Connect's clouds holds the account. Not where the appliance stands: the European cloud serves Australia too.")
                .size(12)
                .style(muted),
        ]
        .spacing(7)
        .into(),
    );

    let body = match state.panel {
        Panel::Activity => activity(state),
        Panel::Downloads => downloads(state),
    };

    container(column![head, controls, tabs(state), card(body)].spacing(15))
        .padding(22)
        .width(Fill)
        .height(Fill)
        .into()
}

/// Two buttons that behave as one control: the selected one is filled, the
/// other is not.
fn tabs(state: &State) -> Element<'_, Message> {
    let tab = |label: String, panel: Panel| {
        button(text(label).size(13))
            .padding([6, 13])
            .style(if state.panel == panel { button::secondary } else { button::text })
            .on_press(Message::PanelPicked(panel))
    };

    row![
        tab("Activity".to_owned(), Panel::Activity),
        tab(
            match state.fetches.len() {
                0 => "Downloads".to_owned(),
                count => format!("Downloads ({count})"),
            },
            Panel::Downloads,
        ),
    ]
    .spacing(4)
    .into()
}

/// A picker and a button standing side by side have to be the same height, and
/// iced gives no `height` on a `pick_list`. Both work it out the same way
/// though, from the text line plus the vertical padding, so setting those equal
/// is what makes them equal. Named here so a change to one is a change to both.
const CONTROL_TEXT: f32 = 14.0;
const CONTROL_PAD_Y: f32 = 9.0;
/// The horizontal padding differs on purpose: a button wants air around a short
/// word, a picker wants its text near the left edge.
const CONTROL_PAD_X_BUTTON: f32 = 16.0;
const CONTROL_PAD_X_PICKER: f32 = 12.0;

/// The same idea one size down, for the save form.
const FORM_TEXT: f32 = 12.5;
const FORM_PAD_Y: f32 = 6.0;

/// The header lays out as: the button's own padding, the arrow, a gap, the
/// mark, a gap, then the title. `INDENT` is that sum, so the detail underneath
/// starts exactly under the first letter of the title.
const ARROW: f32 = 14.0;
const MARK: f32 = 14.0;
const HEADER_PADDING: f32 = 7.0;
const HEADER_SPACING: f32 = 7.0;
const INDENT: f32 = HEADER_PADDING + ARROW + HEADER_SPACING + MARK + HEADER_SPACING;
/// The hairline, and the space between it and the text.
const RULE: f32 = 1.0;
const GAP: f32 = 11.0;

fn activity(state: &State) -> Element<'_, Message> {
    if state.steps.is_empty() {
        return hint("Nothing yet. Press \u{201c}Sign in and fetch\u{201d} to start.");
    }

    let steps = column(state.steps.iter().enumerate().map(|(index, step)| {
        let (mark, tone) = match step.state {
            StepState::Running => ("\u{25cf}", Tone::Plain),
            StepState::Done => ("\u{2713}", Tone::Good),
            StepState::Warned => ("\u{26a0}", Tone::Warn),
            StepState::Failed => ("\u{2717}", Tone::Bad),
        };

        let arrow = if step.expanded { "\u{25be}" } else { "\u{25b8}" };
        let took = step.took.map(|s| format!("{s:.1}s")).unwrap_or_default();

        let header = button(
            row![
                text(arrow).size(11).style(muted).width(ARROW),
                text(mark)
                    .size(13)
                    .width(MARK)
                    .style(move |theme| text::Style { color: Some(accent(theme, tone)) }),
                text(&step.title).size(13.5).width(Fill),
                text(took).size(11.5).style(muted),
            ]
            .spacing(HEADER_SPACING)
            .align_y(Center),
        )
        .padding([5.0, HEADER_PADDING])
        .width(Fill)
        .style(button::text)
        .on_press(Message::ToggleStep(index));

        if !step.expanded || step.detail.is_empty() {
            return header.into();
        }

        let lines = column(
            step.detail
                .iter()
                .map(|line| text(line).size(12).font(Font::MONOSPACE).style(muted).into()),
        )
        .spacing(3);

        // Indented to sit under the title rather than under the arrow, with a
        // hairline down the left so a long step reads as one block. The line is
        // a thin filled container: a border in iced is the same width on every
        // side, so it cannot be asked for on one.
        let rule = container(text("")).width(1).height(Fill).style(|theme: &Theme| {
            container::Style::default().background(theme.extended_palette().background.strong.color)
        });

        column![
            header,
            row![
                // Lined up with the title above, not with the arrow, so the
                // detail reads as a continuation of the heading rather than as
                // a second column. The widths are named so the two stay in step.
                container(text("")).width(INDENT - RULE - GAP),
                rule,
                container(lines).padding(iced::padding::left(GAP).top(3).bottom(7)),
            ],
        ]
        .spacing(2)
        .into()
    }))
    .spacing(1);

    let Some(region) = state.suggested_region.filter(|_| !state.running) else {
        return scrollable(steps).width(Fill).height(Fill).anchor_bottom().into();
    };

    // Offered once the run has ended. A run that succeeded clears the
    // suggestion, so this only ever appears where the region really did get in
    // the way, whichever step it finally showed up in.
    column![
        scrollable(steps).width(Fill).height(Fill).anchor_bottom(),
        button(text(format!("Switch to {} and sign in again", region.label())).size(13))
            .padding([8, 14])
            .on_press(Message::RetryIn(region)),
    ]
    .spacing(11)
    .into()
}

fn downloads(state: &State) -> Element<'_, Message> {
    if state.fetches.is_empty() {
        return hint("No fetches yet. Everything stays in memory until you save it.");
    }

    let entries = column(state.fetches.iter().enumerate().map(|(index, fetch)| {
        let appliances = column(fetch.items.iter().map(|item| {
            // The name the account holds first, because that is what the user
            // calls it. The identifier is underneath for whoever needs it.
            row![
                column![
                    text(item.appliance.label()).size(13),
                    text(format!("{}  ·  {}", item.appliance.description(), item.appliance.ha_id))
                        .size(11)
                        .style(muted),
                ]
                .spacing(1)
                .width(Fill),
                text(item.encryption.label()).size(11.5).style(muted),
            ]
            .spacing(10)
            .into()
        }))
        .spacing(9);

        let heading = row![
            text(fetch.at.format("%Y-%m-%d %H:%M").to_string()).size(13.5).width(Fill),
            text(job::plural(fetch.items.len(), "appliance", "appliances")).size(12).style(muted),
        ]
        .spacing(10);

        column![heading, appliances, save_row(index, fetch)].spacing(9).into()
    }))
    .spacing(20);

    scrollable(entries).width(Fill).height(Fill).into()
}

/// The control that opens the save dialog, and what the last save had to say.
fn save_row(index: usize, fetch: &Fetch) -> Element<'_, Message> {
    let mut controls = row![
        button(text("Save profiles").size(13))
            .padding([8, 14])
            .on_press(Message::OpenDialog(index)),
    ]
    .spacing(9)
    .align_y(Center);

    match &fetch.saved {
        Some(Ok(done)) => {
            let folder = fetch.last_destination.clone().unwrap_or_else(naming::default_destination);
            controls = controls.push(
                button(text("Open folder").size(13))
                    .padding([8, 14])
                    .style(button::secondary)
                    .on_press(Message::OpenFolder(folder)),
            );
            column![
                controls,
                text(done)
                    .size(11.5)
                    .style(|theme| text::Style { color: Some(accent(theme, Tone::Good)) }),
            ]
            .spacing(7)
            .into()
        }
        Some(Err(error)) => column![
            controls,
            text(error)
                .size(11.5)
                .style(|theme| text::Style { color: Some(accent(theme, Tone::Bad)) }),
        ]
        .spacing(7)
        .into(),
        None => controls.into(),
    }
}

/// An empty panel still has to say something, and the same something each time.
fn hint(line: &str) -> Element<'_, Message> {
    container(text(line).size(13).style(muted)).width(Fill).height(Fill).into()
}

/// One surface, one hairline, one radius: the shape every section shares.
fn card(inner: Element<'_, Message>) -> Element<'_, Message> {
    container(inner)
        .padding(14)
        .width(Fill)
        .style(|theme: &Theme| {
            let palette = theme.extended_palette();
            container::Style::default()
                .background(palette.background.weakest.color)
                .border(iced::border::rounded(9).width(1).color(palette.background.strong.color))
        })
        .into()
}

// --- colour ----------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
enum Tone {
    Plain,
    Good,
    Warn,
    Bad,
}

/// The blue the Electron version used for every heading, link and button
/// (`style.css`), which is Home Connect's own. Carried over rather than picked
/// afresh, because people recognise the application by it.
const BRAND: Color = iced::color!(0x005daa);

/// The same blue lifted towards the light for a dark window. `#005daa` sits at
/// a third of full lightness and reads as almost black against a dark
/// background, so the hue is kept and the lightness raised.
const BRAND_ON_DARK: Color = iced::color!(0x4f9fd9);

/// Light and dark, both carrying the brand blue. Everything else is iced's own
/// palette, which is already tuned for contrast; only `primary` is ours.
fn theme(dark: bool) -> Theme {
    if dark {
        Theme::custom(
            "Home Connect Dark".to_owned(),
            Palette { primary: BRAND_ON_DARK, ..Palette::DARK },
        )
    } else {
        Theme::custom("Home Connect".to_owned(), Palette { primary: BRAND, ..Palette::LIGHT })
    }
}

fn muted(theme: &Theme) -> text::Style {
    // Dark needs more of the text colour than light does to read as the same
    // weight: grey on black loses contrast faster than grey on white.
    let alpha = if theme.extended_palette().is_dark { 0.75 } else { 0.65 };
    text::Style { color: Some(theme.extended_palette().background.base.text.scale_alpha(alpha)) }
}

/// The colour of a mark, and of the text that belongs to it.
///
/// Given per theme rather than taken from iced's generated palette. The
/// generated tones are mixed towards the background, which is right for a
/// button's fill and wrong for a tick five pixels wide: on a dark window they
/// came out too faint to read at a glance, which is the one thing a status mark
/// has to do.
///
/// The amber is the one the Electron version used for its link hover
/// (`style.css`), so the warning colour comes from the same place as the blue.
fn accent(theme: &Theme, tone: Tone) -> Color {
    if theme.extended_palette().is_dark {
        match tone {
            Tone::Plain => BRAND_ON_DARK,
            Tone::Good => iced::color!(0x52d17f),
            Tone::Warn => iced::color!(0xffba00),
            Tone::Bad => iced::color!(0xff7a70),
        }
    } else {
        match tone {
            Tone::Plain => BRAND,
            Tone::Good => iced::color!(0x1f7a3d),
            Tone::Warn => iced::color!(0xb06f00),
            Tone::Bad => iced::color!(0xa72d2d),
        }
    }
}

// --- the system -----------------------------------------------------------

/// Hands the folder to whatever the system uses to show one.
fn open_folder(folder: &std::path::Path) {
    let command = if cfg!(target_os = "windows") {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    // Nothing to do if it fails: the path is on screen either way.
    let _ = std::process::Command::new(command).arg(folder).spawn();
}

/// The system's UI font, named as each platform calls it. iced falls back to
/// its own default for a name it cannot find, so a wrong guess costs nothing.
fn ui_font() -> Font {
    #[cfg(target_os = "windows")]
    let name = "Segoe UI Variable Text";
    #[cfg(target_os = "macos")]
    let name = "SF Pro Text";
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let name = "Noto Sans";
    Font::with_name(name)
}

fn main() -> iced::Result {
    // A daemon rather than an application, because the save dialog is a window
    // of its own and an application has exactly one.
    iced::daemon(boot, update, view)
        .title(|state: &State, window| match &state.dialog {
            Some(dialog) if dialog.window == window => "Save profiles".to_owned(),
            _ => "Home Connect Profile Downloader".to_owned(),
        })
        .default_font(ui_font())
        // Light and dark are not a preference to store; they are the system's
        // answer, asked once at start and then listened for.
        .theme(|state: &State, _window| state.theme.clone())
        .subscription(|_| {
            iced::Subscription::batch([
                iced::system::theme_changes().map(Message::SystemTheme),
                window::close_events().map(Message::WindowClosed),
            ])
        })
        .run()
}
