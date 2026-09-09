//! Thin binary shell: parse args, dispatch to the library, map errors.
//!
//! Deliberately no anyhow: the library's single `askcodex::Error` enum already
//! renders every failure; a context-wrapping crate would add a dependency
//! to do what one eprintln does. All failures exit non-zero with a
//! `askcodex: error: ` prefix on stderr (stdout stays payload-only).
//!
//! Ctrl-C never prints a Rust panic, and that is a property of how this
//! shell is built rather than an accident:
//! - No SIGINT handler is installed, so Ctrl-C takes the default action and
//!   the process is terminated by the signal. Nothing unwinds, so nothing
//!   can panic on the way out, and the shell reports the usual 128+SIGINT.
//! - The panicking print macros (`print!`/`println!`, which abort the
//!   process on a closed stdout) are not used for payload anywhere in the
//!   crate. [`askcodex::run`] writes through `write_all` and returns the I/O
//!   error, so `askcodex ask … | head` reports a broken pipe on stderr and
//!   exits non-zero instead of aborting mid-write. Truncated output is a
//!   real failure and is reported as one — it is never quietly swallowed.

use clap::Parser;

fn main() {
    let cli = askcodex::Cli::parse();
    let machine = cli.json || cli.events;
    if let Err(e) = askcodex::run(cli) {
        let _ = e.write_diagnostic(&mut std::io::stderr().lock(), machine);
        std::process::exit(e.exit_code());
    }
}
