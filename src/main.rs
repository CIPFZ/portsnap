use anyhow::{bail, Context, Result};
use clap::{ArgGroup, Parser};
use portsnap::{
    killer::{KillError, KillOutcome, PreparedTarget},
    model::{AddressFamily, ProcessInfo, Protocol, ScanOptions, ScanReport},
    output, process,
    scanner::Scanner,
};
use std::{
    collections::BTreeMap,
    io::{self, BufRead, Write},
    process::ExitCode,
    time::Duration,
};

#[derive(Parser, Debug)]
#[command(
    name = "portsnap",
    version,
    about = "Inspect local TCP and UDP endpoints and their owners"
)]
#[command(group(ArgGroup::new("query").args(["ports", "list"]).required(true)))]
struct Args {
    /// Local ports to inspect, including non-listening TCP states
    #[arg(num_args=1.., value_parser=clap::value_parser!(u16).range(1..))]
    ports: Vec<u16>,
    /// List TCP listeners and bound UDP endpoints
    #[arg(short = 'l', long, conflicts_with = "ports")]
    list: bool,
    /// Restrict all scans and termination targets to TCP
    #[arg(long, conflicts_with = "udp")]
    tcp: bool,
    /// Restrict all scans and termination targets to UDP
    #[arg(long, conflicts_with = "tcp")]
    udp: bool,
    /// Restrict all scans to IPv4 sockets
    #[arg(short = '4', long, conflicts_with = "ipv6")]
    ipv4: bool,
    /// Restrict all scans to IPv6 sockets (including IPv4-mapped IPv6)
    #[arg(short = '6', long, conflicts_with = "ipv4")]
    ipv6: bool,
    /// Read executable, arguments, user, parent and start time for matching owners
    #[arg(long)]
    details: bool,
    /// Emit one versioned JSON scan report
    #[arg(long, conflicts_with = "kill")]
    json: bool,
    /// Interactively terminate owning processes (Windows: forced termination)
    #[arg(short='k', long="kill", requires="ports", conflicts_with_all=["list", "json"])]
    kill: bool,
    /// Force termination; required for macOS (subject to task-port permissions)
    #[arg(long, requires = "kill")]
    force: bool,
    /// Seconds to wait for each process to exit, without automatic escalation
    #[arg(long, default_value_t=3, value_parser=clap::value_parser!(u64).range(1..=60), requires="kill")]
    timeout: u64,
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            if error
                .downcast_ref::<io::Error>()
                .is_some_and(|e| e.kind() == io::ErrorKind::BrokenPipe)
                || error
                    .downcast_ref::<serde_json::Error>()
                    .is_some_and(|e| e.io_error_kind() == Some(io::ErrorKind::BrokenPipe))
            {
                return ExitCode::SUCCESS;
            }
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(args: Args) -> Result<u8> {
    #[cfg(target_os = "macos")]
    if args.kill && !args.force {
        bail!("safe termination on macOS requires --force and permission to acquire a Mach task port; ordinary PID-based signals are not used");
    }
    let options = ScanOptions {
        ports: args.ports,
        listening_only: args.list,
        protocol: if args.tcp {
            Some(Protocol::Tcp)
        } else if args.udp {
            Some(Protocol::Udp)
        } else {
            None
        },
        family: if args.ipv4 {
            Some(AddressFamily::Ipv4)
        } else if args.ipv6 {
            Some(AddressFamily::Ipv6)
        } else {
            None
        },
    };
    let mut report = Scanner::scan(&options).context("scan failed")?;
    if args.details {
        process::enrich_details(&mut report);
    }
    if args.json {
        let mut out = io::stdout().lock();
        serde_json::to_writer_pretty(&mut out, &report).context("write JSON report")?;
        writeln!(out)?;
    } else {
        output::write_text(io::stdout().lock(), &report)?;
    }
    output::write_warnings(io::stderr().lock(), &report)?;
    if args.kill && !report.sockets.is_empty() {
        return kill_interactively(
            &report,
            &options,
            args.force,
            Duration::from_secs(args.timeout),
            args.details,
        );
    }
    Ok(if report.complete { 0 } else { 3 })
}

fn targets(report: &ScanReport) -> Result<Vec<ProcessInfo>> {
    let mut owners = BTreeMap::<u32, ProcessInfo>::new();
    for owner in report.sockets.iter().flat_map(|socket| &socket.owners) {
        if let Some(previous) = owners.get(&owner.pid) {
            if previous.identity != owner.identity {
                bail!(
                    "process {} changed identity during the scan; run the query again",
                    owner.pid
                );
            }
        } else {
            owners.insert(owner.pid, owner.clone());
        }
    }
    Ok(owners.into_values().collect())
}

fn kill_interactively(
    report: &ScanReport,
    options: &ScanOptions,
    force: bool,
    timeout: Duration,
    details: bool,
) -> Result<u8> {
    let owners = targets(report)?;
    if owners.is_empty() {
        bail!("no safely identifiable process owns the observed endpoints; inspect ownership warnings or kernel-managed TCP states");
    }
    let mut failed = false;
    let mut attempted = false;
    let mut incomplete = !report.complete;
    let mut input = io::stdin().lock();
    for owner in owners {
        // Acquire a stable OS reference before allowing an unbounded confirmation delay.
        let mut target = match PreparedTarget::prepare(&owner) {
            Ok(target) => target,
            Err(KillError::AlreadyExited) => {
                eprintln!("PID {} already exited.", owner.pid);
                attempted = true;
                continue;
            }
            Err(error) => {
                eprintln!("Cannot prepare PID {}: {error}", owner.pid);
                failed = true;
                continue;
            }
        };
        let name = owner.name.as_deref().unwrap_or("name unavailable");
        eprint!(
            "{} process {:?} (PID {})? [y/N]: ",
            if force || cfg!(windows) {
                "Force terminate"
            } else {
                "Terminate"
            },
            name,
            owner.pid
        );
        io::stderr().flush()?;
        let mut answer = String::new();
        if input.read_line(&mut answer)? == 0 {
            bail!(
                "confirmation input ended; no signal sent to PID {}",
                owner.pid
            );
        }
        if !matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            eprintln!("Skipped PID {}.", owner.pid);
            continue;
        }
        attempted = true;
        // Process identity and port ownership are independent: verify both.
        let current =
            Scanner::scan(options).context("cannot recheck port ownership before termination")?;
        incomplete |= !current.complete;
        output::write_warnings(io::stderr().lock(), &current)?;
        let still_owns = current
            .sockets
            .iter()
            .flat_map(|socket| &socket.owners)
            .any(|candidate| {
                candidate.pid == owner.pid
                    && candidate.identity.is_some()
                    && candidate.identity == owner.identity
            });
        if !still_owns {
            if !current.complete {
                eprintln!(
                    "Cannot verify that PID {} still owns a requested endpoint; no signal sent.",
                    owner.pid
                );
                failed = true;
            } else {
                eprintln!(
                    "PID {} no longer owns a requested endpoint; no signal sent.",
                    owner.pid
                );
            }
            continue;
        }
        match target.terminate(force, timeout) {
            Ok(KillOutcome::Exited) => eprintln!("PID {} exited (verified).", owner.pid),
            Ok(KillOutcome::AlreadyExited) => eprintln!("PID {} already exited.", owner.pid),
            Err(error) => {
                eprintln!("Failed to terminate PID {}: {error}", owner.pid);
                failed = true;
            }
        }
    }
    if attempted {
        let mut remaining = Scanner::scan(options).context("cannot verify remaining endpoints")?;
        if details {
            process::enrich_details(&mut remaining);
        }
        incomplete |= !remaining.complete;
        output::write_warnings(io::stderr().lock(), &remaining)?;
        if remaining.sockets.is_empty() {
            if remaining.complete {
                eprintln!("No matching endpoints remain.");
            } else {
                eprintln!(
                    "No matching endpoints observed; the incomplete scan cannot confirm release."
                );
            }
        } else {
            eprintln!("Matching endpoints remain; review their current owners and TCP states:");
            output::write_text(io::stdout().lock(), &remaining)?;
            failed = true;
        }
    }
    Ok(if failed {
        1
    } else if incomplete {
        3
    } else {
        0
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn incompatible_and_incomplete_cli_requests_are_rejected() {
        for args in [
            vec!["portsnap"],
            vec!["portsnap", "--json"],
            vec!["portsnap", "--kill"],
            vec!["portsnap", "80", "--list"],
            vec!["portsnap", "80", "--kill", "--json"],
            vec!["portsnap", "80", "--force"],
            vec!["portsnap", "0"],
            vec!["portsnap", "65536"],
            vec!["portsnap", "80", "--timeout", "0"],
            vec!["portsnap", "80", "--tcp", "--udp"],
            vec!["portsnap", "--list", "-4", "-6"],
            vec!["portsnap", "--details"],
            vec!["portsnap", "--tcp"],
        ] {
            assert!(Args::try_parse_from(&args).is_err(), "{args:?}");
        }
    }
    #[test]
    fn queries_do_not_require_kill_despite_default_timeout() {
        for args in [
            vec!["portsnap", "80", "443"],
            vec!["portsnap", "-l", "--json"],
            vec!["portsnap", "80", "-k", "--force", "--timeout", "1"],
            vec!["portsnap", "80", "--tcp", "-4", "--details", "--json"],
            vec!["portsnap", "-l", "--udp", "--ipv6", "--details"],
            vec!["portsnap", "80", "--tcp", "-6", "--kill"],
        ] {
            assert!(Args::try_parse_from(&args).is_ok(), "{args:?}");
        }
    }
}
