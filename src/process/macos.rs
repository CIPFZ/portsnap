use crate::model::{DetailField, ProcessDetails, ProcessIdentity, ProcessInfo};
use std::{
    io,
    mem::{size_of, MaybeUninit},
};

pub(crate) fn bsd_info(pid: u32) -> io::Result<libc::proc_bsdinfo> {
    let pid = i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PID exceeds native range"))?;
    let mut info = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    // SAFETY: proc_pidinfo writes at most the supplied buffer length.
    let len = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            size_of::<libc::proc_bsdinfo>() as i32,
        )
    };
    if len <= 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<libc::proc_bsdinfo>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "truncated proc_bsdinfo",
        ));
    }
    // SAFETY: the kernel returned a complete initialized structure.
    Ok(unsafe { info.assume_init() })
}

pub(crate) fn identity(info: &libc::proc_bsdinfo) -> io::Result<ProcessIdentity> {
    if info.pbi_start_tvusec >= 1_000_000 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid process start microseconds",
        ));
    }
    let start_time = info
        .pbi_start_tvsec
        .checked_mul(1_000_000)
        .and_then(|seconds| seconds.checked_add(info.pbi_start_tvusec))
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid process start time"))?;
    Ok(ProcessIdentity {
        pid: info.pbi_pid,
        start_time,
    })
}

pub fn inspect(pid: u32) -> io::Result<ProcessInfo> {
    let info = bsd_info(pid)?;
    let identity = identity(&info)?;
    let bytes: Vec<u8> = info
        .pbi_name
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    let bytes = if bytes.is_empty() {
        info.pbi_comm
            .iter()
            .take_while(|&&c| c != 0)
            .map(|&c| c as u8)
            .collect()
    } else {
        bytes
    };
    let name = String::from_utf8_lossy(&bytes).into_owned();
    Ok(ProcessInfo {
        pid,
        name: (!name.is_empty()).then_some(name),
        identity: Some(identity),
        details: None,
    })
}

pub fn read_details(pid: u32) -> ProcessDetails {
    let mut details = ProcessDetails::empty();
    match executable(pid) {
        Ok(path) => details.executable = Some(path),
        Err(error) => super::detail_error(&mut details, DetailField::Executable, error),
    }
    match command(pid) {
        Ok(command) => details.command = Some(command),
        Err(error) => super::detail_error(&mut details, DetailField::Command, error),
    }
    match bsd_info(pid) {
        Ok(info) if info.pbi_pid == pid => {
            details.parent_pid = Some(info.pbi_ppid);
            details.user = Some(super::unix_user(info.pbi_uid, &mut details));
            match identity(&info) {
                Ok(identity) => details.start_time_unix_ms = Some(identity.start_time / 1000),
                Err(error) => {
                    super::detail_error(&mut details, DetailField::StartTimeUnixMs, error)
                }
            }
        }
        result => {
            let error = match result {
                Err(error) => error,
                Ok(_) => {
                    io::Error::new(io::ErrorKind::InvalidData, "Process metadata PID mismatch")
                }
            };
            let kind = error.kind();
            let message = error.to_string();
            for field in [
                DetailField::User,
                DetailField::ParentPid,
                DetailField::StartTimeUnixMs,
            ] {
                super::detail_error(&mut details, field, io::Error::new(kind, message.clone()));
            }
        }
    }
    details
}

fn native_pid(pid: u32) -> io::Result<i32> {
    i32::try_from(pid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "PID exceeds native range"))
}

fn executable(pid: u32) -> io::Result<String> {
    let pid = native_pid(pid)?;
    let mut buffer = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: proc_pidpath receives a writable buffer of the specified size.
    let length =
        unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if length <= 0 {
        return Err(io::Error::last_os_error());
    }
    let length = length as usize;
    if length >= buffer.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Truncated process executable path",
        ));
    }
    let end = buffer[..=length]
        .iter()
        .position(|&byte| byte == 0)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Process executable path is not NUL-terminated",
            )
        })?;
    if end == 0 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Process executable path is unavailable",
        ));
    }
    Ok(String::from_utf8_lossy(&buffer[..end]).into_owned())
}

fn command(pid: u32) -> io::Result<Vec<String>> {
    let pid = native_pid(pid)?;
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    let mut length = 0;
    // SAFETY: a null output buffer requests the required byte count only.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            std::ptr::null_mut(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if !(4..=16 * 1024 * 1024).contains(&length) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid process argument buffer size",
        ));
    }
    // A fresh exec can increase argslen between sysctl calls without changing the
    // process start identity. Reserve ARG_MAX plus room for the path and argc to
    // avoid Darwin's historical silent truncation for undersized buffers.
    let mut argmax = 0i32;
    let mut argmax_size = size_of::<i32>();
    let mut argmax_mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: sysctl receives a writable i32 and its exact size.
    let result = unsafe {
        libc::sysctl(
            argmax_mib.as_mut_ptr(),
            2,
            (&mut argmax as *mut i32).cast(),
            &mut argmax_size,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if argmax_size != size_of::<i32>() || !(1..=16 * 1024 * 1024).contains(&argmax) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid ARG_MAX",
        ));
    }
    length = length.max(argmax as usize + libc::PROC_PIDPATHINFO_MAXSIZE as usize + 4);
    let mut bytes = vec![0u8; length];
    // SAFETY: sysctl writes only within the supplied buffer and updates its length.
    let result = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            bytes.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    };
    if result != 0 {
        return Err(io::Error::last_os_error());
    }
    if length > bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Truncated process command",
        ));
    }
    // PROC_FLAG_LP64 is 0x10 in Darwin sys/proc_info.h. Use the target process's
    // width so empty argv[0] is preserved even when inspecting a 32-bit process.
    let pointer_size = if bsd_info(pid as u32)?.pbi_flags & 0x10 != 0 {
        8
    } else {
        4
    };
    super::parse_macos_command(&bytes[..length], pointer_size)
}
