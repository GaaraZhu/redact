/// Returns true if stdout supports ANSI color sequences.
/// On Windows, attempts to enable virtual terminal processing so cmd.exe renders
/// colors correctly. Falls back to no-color if the console API rejects it.
/// Respects the NO_COLOR env var (https://no-color.org/).
pub fn supports_color() -> bool {
    if std::env::var_os("NO_COLOR").is_some() {
        return false;
    }
    #[cfg(windows)]
    {
        return windows_try_enable_ansi();
    }
    #[cfg(not(windows))]
    {
        use std::io::IsTerminal;
        std::io::stdout().is_terminal()
    }
}

/// On Windows, try to enable ENABLE_VIRTUAL_TERMINAL_PROCESSING on stdout.
/// Returns true if ANSI sequences will be rendered (already enabled, or just enabled).
/// Returns false if stdout is not a console (pipe/file) or the API call fails.
#[cfg(windows)]
fn windows_try_enable_ansi() -> bool {
    use std::ffi::c_void;
    use std::os::windows::io::AsRawHandle;
    const ENABLE_VIRTUAL_TERMINAL_PROCESSING: u32 = 0x0004;
    extern "system" {
        fn GetConsoleMode(hConsoleHandle: *mut c_void, lpMode: *mut u32) -> i32;
        fn SetConsoleMode(hConsoleHandle: *mut c_void, dwMode: u32) -> i32;
    }
    unsafe {
        let handle = std::io::stdout().as_raw_handle();
        let mut mode: u32 = 0;
        if GetConsoleMode(handle, &mut mode) == 0 {
            return false; // not a console (pipe, file, Git Bash mintty)
        }
        if mode & ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
            return true; // already on (Windows Terminal, etc.)
        }
        SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0
    }
}
