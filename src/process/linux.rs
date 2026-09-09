use crate::model::{ProcessIdentity, ProcessInfo};
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
    })
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
}
