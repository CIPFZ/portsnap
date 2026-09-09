use crate::model::{ProcessIdentity, ProcessInfo};
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
    })
}
