#[cfg(target_os = "linux")]
mod linux;

#[cfg(target_os = "linux")]
fn main() -> std::process::ExitCode {
    let arguments = std::env::args_os().collect::<Vec<_>>();
    if arguments.len() == 2 && arguments[1] == "--security-probe" {
        return linux::security_probe_entry();
    }
    linux::entry()
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("cdm-guest-init: this binary can only run in a Linux guest");
    std::process::ExitCode::from(125)
}
