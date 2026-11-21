//! `snow-rs --show-completion` and `snow-rs --install-completion`.
//!
//! Where snow (typer) installs the script, for the shell it detects, is kept: `~/.bashrc` plus
//! `~/.bash_completions/snow-rs.sh`, `~/.zshrc` plus `~/.zfunc/_snow-rs`, `~/.config/fish/completions/
//! snow-rs.fish`, and the PowerShell profile. The script itself is generated from the clap
//! definitions (static, complete without calling back into the binary), not typer's callback one.
//! The shell is detected from `$SHELL` only (typer also walks the parent processes).

use crate::config::home_dir;
use crate::env::Env;
use crate::error::Result;
use clap::Command;
use clap_complete::Shell as ClapShell;
use std::io::Write;
use std::path::{Path, PathBuf};

const PROG: &str = "snow-rs";

/// A shell snow can complete for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shell {
    Bash,
    Zsh,
    Fish,
    /// `powershell` or `pwsh` (the program to run for the profile lookup).
    PowerShell(&'static str),
}

impl Shell {
    /// The shell named by `$SHELL` (its file name, `.exe` removed); `None` when unset or unknown.
    pub fn detect(env: &Env) -> std::result::Result<Self, String> {
        let path = env.get_non_empty("SHELL").unwrap_or("");
        let name = path.rsplit(['/', '\\']).next().unwrap_or("");
        let name = name.strip_suffix(".exe").unwrap_or(name).to_lowercase();
        match name.as_str() {
            "bash" => Ok(Shell::Bash),
            "zsh" => Ok(Shell::Zsh),
            "fish" => Ok(Shell::Fish),
            "powershell" => Ok(Shell::PowerShell("powershell")),
            "pwsh" => Ok(Shell::PowerShell("pwsh")),
            _ => Err(name),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Shell::Bash => "bash",
            Shell::Zsh => "zsh",
            Shell::Fish => "fish",
            Shell::PowerShell(program) => program,
        }
    }

    fn clap(self) -> ClapShell {
        match self {
            Shell::Bash => ClapShell::Bash,
            Shell::Zsh => ClapShell::Zsh,
            Shell::Fish => ClapShell::Fish,
            Shell::PowerShell(_) => ClapShell::PowerShell,
        }
    }
}

/// The completion script of `root` for `shell`, without trailing whitespace.
pub fn script(root: &Command, shell: Shell) -> String {
    let mut root = root.clone();
    let mut out = Vec::new();
    clap_complete::generate(shell.clap(), &mut root, PROG, &mut out);
    String::from_utf8_lossy(&out).trim().to_string()
}

/// `--show-completion`: prints the script (stdout) or `Shell X not supported.` (stderr) and
/// returns the exit code.
pub fn show(root: &Command, env: &Env, stdout: &mut dyn Write, stderr: &mut dyn Write) -> i32 {
    let written = match Shell::detect(env) {
        Ok(shell) => writeln!(stdout, "{}", script(root, shell)).map(|()| 0),
        Err(name) => writeln!(stderr, "Shell {name} not supported.").map(|()| 1),
    };
    written.unwrap_or(1)
}

/// `--install-completion`: installs the script and says where, or prints `Shell X is not
/// supported.` (stdout, as typer). Returns the exit code.
pub fn install(
    root: &Command,
    env: &Env,
    profile_of: &dyn Fn(&str) -> std::io::Result<PathBuf>,
    stdout: &mut dyn Write,
    stderr: &mut dyn Write,
) -> i32 {
    let shell = match Shell::detect(env) {
        Ok(shell) => shell,
        Err(name) => {
            let _ = writeln!(stdout, "Shell {name} is not supported.");
            return 1;
        }
    };
    match install_script(root, env, shell, profile_of) {
        Ok(path) => {
            let _ = writeln!(
                stdout,
                "{} completion installed in {}",
                shell.name(),
                path.display()
            );
            let _ = writeln!(
                stdout,
                "Completion will take effect once you restart the terminal"
            );
            0
        }
        Err(e) => {
            let _ = writeln!(stderr, "{e}");
            1
        }
    }
}

fn install_script(
    root: &Command,
    env: &Env,
    shell: Shell,
    profile_of: &dyn Fn(&str) -> std::io::Result<PathBuf>,
) -> Result<PathBuf> {
    let io = |e: std::io::Error| {
        crate::error::Error::new(
            crate::error::ErrorKind::Client,
            format!("Could not install the completion: {e}"),
        )
    };
    let home = home_dir(env)?;
    let script = script(root, shell);
    match shell {
        Shell::Bash => {
            let path = home.join(".bash_completions").join(format!("{PROG}.sh"));
            let line = format!("source '{}'", path.display());
            append_line_once(&home.join(".bashrc"), &line).map_err(io)?;
            write_file(&path, &script).map_err(io)?;
            Ok(path)
        }
        Shell::Zsh => {
            let zshrc = home.join(".zshrc");
            let mut content = std::fs::read_to_string(&zshrc).unwrap_or_default();
            let line = "fpath+=~/.zfunc; autoload -Uz compinit; compinit";
            if !content.contains(line) {
                content.push_str(&format!("\n{line}\n"));
            }
            if !content.contains("zstyle") {
                content.push_str("\nzstyle ':completion:*' menu select\n");
            }
            write_file(&zshrc, &format!("{}\n", content.trim())).map_err(io)?;
            let path = home.join(".zfunc").join(format!("_{PROG}"));
            write_file(&path, &script).map_err(io)?;
            Ok(path)
        }
        Shell::Fish => {
            let path = home
                .join(".config/fish/completions")
                .join(format!("{PROG}.fish"));
            write_file(&path, &format!("{script}\n")).map_err(io)?;
            Ok(path)
        }
        Shell::PowerShell(program) => {
            let path = profile_of(program).map_err(io)?;
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).map_err(io)?;
            }
            let mut file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .map_err(io)?;
            writeln!(file, "{script}").map_err(io)?;
            Ok(path)
        }
    }
}

/// Appends `line` to the file unless it already contains it (as typer does for `.bashrc`).
fn append_line_once(path: &Path, line: &str) -> std::io::Result<()> {
    let mut content = std::fs::read_to_string(path).unwrap_or_default();
    if !content.contains(line) {
        content.push('\n');
        content.push_str(line);
    }
    content.push('\n');
    write_file(path, &content)
}

fn write_file(path: &Path, content: &str) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, content)
}

/// The PowerShell profile path: runs `<program> -NoProfile -Command echo $profile`, after the
/// `Set-ExecutionPolicy Unrestricted` snow's installer (typer) runs for the current user.
pub fn powershell_profile(program: &str) -> std::io::Result<PathBuf> {
    let _ = std::process::Command::new(program)
        .args([
            "-Command",
            "Set-ExecutionPolicy",
            "Unrestricted",
            "-Scope",
            "CurrentUser",
        ])
        .status();
    let output = std::process::Command::new(program)
        .args(["-NoProfile", "-Command", "echo", "$profile"])
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other(
            "Couldn't get PowerShell user profile",
        ));
    }
    Ok(PathBuf::from(
        String::from_utf8_lossy(&output.stdout).trim(),
    ))
}
