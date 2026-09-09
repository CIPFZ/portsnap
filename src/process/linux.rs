use crate::model::{DetailField, ProcessDetails, ProcessIdentity, ProcessInfo};
use std::{fs, io};

pub fn inspect(pid: u32) -> io::Result<ProcessInfo> {
    parse_stat(pid, &fs::read(format!("/proc/{pid}/stat"))?)
}

fn parse_stat(pid: u32, stat: &[u8]) -> io::Result<ProcessInfo> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid /proc process stat");
    // comm may itself contain spaces, newlines, or parentheses.
    let left = stat.iter().position(|&c| c == b'(').ok_or_else(invalid)?;
    let right = stat.iter().rposition(|&c| c == b')').ok_or_else(invalid)?;
    if right <= left {
        return Err(invalid());
    }
    let actual_pid: u32 = std::str::from_utf8(&stat[..left])
        .map_err(|_| invalid())?
        .trim()
        .parse()
        .map_err(|_| invalid())?;
    if actual_pid != pid {
        return Err(invalid());
    }
    // The suffix begins at field 3; starttime is field 22.
    let start_time = std::str::from_utf8(&stat[right + 1..])
        .map_err(|_| invalid())?
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(invalid)?
        .parse()
        .map_err(|_| invalid())?;
    let name = String::from_utf8_lossy(&stat[left + 1..right]).into_owned();
    Ok(ProcessInfo {
        pid,
        name: (!name.is_empty()).then_some(name),
        identity: Some(ProcessIdentity { pid, start_time }),
        details: None,
    })
}

pub fn read_details(pid: u32) -> ProcessDetails {
    let mut details = ProcessDetails::empty();
    let base = format!("/proc/{pid}");
    match fs::read_link(format!("{base}/exe")) {
        Ok(path) => details.executable = Some(path.to_string_lossy().into_owned()),
        Err(error) => super::detail_error(&mut details, DetailField::Executable, error),
    }
    match read_bounded(&format!("{base}/cmdline")).and_then(|bytes| parse_command(&bytes)) {
        Ok(command) => details.command = Some(command),
        Err(error) => super::detail_error(&mut details, DetailField::Command, error),
    }
    match fs::read_to_string(format!("{base}/status")) {
        Ok(status) => {
            match status_number(&status, "Uid:", 1) {
                Ok(uid) => details.user = Some(super::unix_user(uid, &mut details)),
                Err(error) => super::detail_error(&mut details, DetailField::User, error),
            }
            match status_number(&status, "PPid:", 0) {
                Ok(parent) => details.parent_pid = Some(parent),
                Err(error) => super::detail_error(&mut details, DetailField::ParentPid, error),
            }
        }
        Err(error) => {
            let message = error.to_string();
            let kind = error.kind();
            super::detail_error(&mut details, DetailField::User, error);
            super::detail_error(
                &mut details,
                DetailField::ParentPid,
                io::Error::new(kind, message),
            );
        }
    }
    let timestamp = inspect(pid).and_then(|process| {
        let ticks = process
            .identity
            .ok_or_else(|| invalid("Missing process start identifier"))?
            .start_time;
        let stat = fs::read_to_string("/proc/stat")?;
        let boot = stat
            .lines()
            .find_map(|line| line.strip_prefix("btime "))
            .ok_or_else(|| invalid("Missing boot timestamp"))?
            .trim()
            .parse::<u64>()
            .map_err(|_| invalid("Invalid boot timestamp"))?;
        // SAFETY: sysconf requires no pointers and has no side effects for _SC_CLK_TCK.
        let frequency = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        let frequency = u64::try_from(frequency)
            .ok()
            .filter(|&value| value > 0)
            .ok_or_else(|| invalid("Invalid system clock tick frequency"))?;
        unix_start_ms(boot, ticks, frequency)
    });
    match timestamp {
        Ok(timestamp) => details.start_time_unix_ms = Some(timestamp),
        Err(error) => super::detail_error(&mut details, DetailField::StartTimeUnixMs, error),
    }
    details
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn read_bounded(path: &str) -> io::Result<Vec<u8>> {
    use io::Read;
    const LIMIT: u64 = 16 * 1024 * 1024;
    let mut bytes = Vec::new();
    fs::File::open(path)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(invalid("Process command exceeds the supported size"));
    }
    Ok(bytes)
}

fn parse_command(bytes: &[u8]) -> io::Result<Vec<String>> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let payload = bytes
        .strip_suffix(&[0])
        .ok_or_else(|| invalid("Process command is not NUL-terminated"))?;
    Ok(payload
        .split(|&byte| byte == 0)
        .map(|arg| String::from_utf8_lossy(arg).into_owned())
        .collect())
}

fn status_number(status: &str, key: &str, index: usize) -> io::Result<u32> {
    status
        .lines()
        .find_map(|line| line.strip_prefix(key))
        .and_then(|value| value.split_ascii_whitespace().nth(index))
        .and_then(|value| value.parse().ok())
        .ok_or_else(|| invalid("Missing or invalid process status field"))
}

fn unix_start_ms(boot: u64, ticks: u64, frequency: u64) -> io::Result<u64> {
    if frequency == 0 {
        return Err(invalid("Invalid clock tick frequency"));
    }
    // Intermediate u128 preserves subsecond ticks without multiplication overflow.
    u64::try_from(u128::from(boot) * 1000 + u128::from(ticks) * 1000 / u128::from(frequency))
        .map_err(|_| invalid("Process start timestamp is out of range"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_name_can_contain_parentheses_newlines_and_non_utf8() {
        let mut stat = b"123 (a ) name\n\xff) S ".to_vec();
        stat.extend_from_slice(format!("{}987654 0 0", "0 ".repeat(18)).as_bytes());
        let process = parse_stat(123, &stat).unwrap();
        assert_eq!(process.identity.unwrap().start_time, 987654);
        assert_eq!(process.name.as_deref(), Some("a ) name\n\u{fffd}"));
    }

    #[test]
    fn rejects_truncated_or_wrong_pid_stat() {
        assert!(parse_stat(123, b"123 (name) S 0").is_err());
        assert!(parse_stat(123, b"321 (name) S 0").is_err());
    }
    #[test]
    fn command_keeps_argument_boundaries_and_empty_values() {
        assert_eq!(
            parse_command(b"program\0two words\0\0last\0").unwrap(),
            ["program", "two words", "", "last"]
        );
        assert_eq!(parse_command(b"\0").unwrap(), [""]);
        assert!(parse_command(b"").unwrap().is_empty());
        assert!(parse_command(b"truncated").is_err());
    }
    #[test]
    fn status_uses_effective_uid_and_keeps_parent_independent() {
        let status = "Name:\ttest\nUid:\t1000\t1001\t1002\t1003\nPPid:\t123\n";
        assert_eq!(status_number(status, "Uid:", 1).unwrap(), 1001);
        assert_eq!(status_number(status, "PPid:", 0).unwrap(), 123);
        assert!(status_number("PPid: 7", "Uid:", 1).is_err());
        assert_eq!(status_number("PPid: 7", "PPid:", 0).unwrap(), 7);
    }
    #[test]
    fn timestamp_scales_ticks_without_overflow() {
        assert_eq!(
            unix_start_ms(1_700_000_000, 150, 100).unwrap(),
            1_700_000_001_500
        );
        assert!(unix_start_ms(u64::MAX, 0, 100).is_err());
        assert!(unix_start_ms(0, 0, 0).is_err());
        assert_eq!(unix_start_ms(0, u64::MAX, 1000).unwrap(), u64::MAX);
    }
}
