use crate::model::{ProcessIdentity, ProcessInfo};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
};
use windows_sys::Win32::{
    Foundation::{ERROR_INVALID_PARAMETER, FILETIME},
    System::Threading::{
        GetProcessTimes, OpenProcess, QueryFullProcessImageNameW, PROCESS_QUERY_LIMITED_INFORMATION,
    },
};

pub(crate) fn open(pid: u32, access: u32) -> io::Result<OwnedHandle> {
    // SAFETY: OpenProcess returns an owned handle or NULL; no pointers are passed.
    let handle = unsafe { OpenProcess(access, 0, pid) };
    if handle.is_null() {
        let error = io::Error::last_os_error();
        // OpenProcess reports a nonexistent nonzero PID as ERROR_INVALID_PARAMETER.
        return Err(
            if pid != 0 && error.raw_os_error() == Some(ERROR_INVALID_PARAMETER as i32) {
                io::Error::new(io::ErrorKind::NotFound, error)
            } else {
                error
            },
        );
    }
    // SAFETY: successful OpenProcess transfers one unique handle to this owner.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

pub(crate) fn identity(handle: &OwnedHandle, pid: u32) -> io::Result<ProcessIdentity> {
    let empty = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut creation, mut exit, mut kernel, mut user) = (empty, empty, empty, empty);
    // SAFETY: the handle stays open; all output pointers reference initialized FILETIMEs.
    if unsafe {
        GetProcessTimes(
            handle.as_raw_handle(),
            &mut creation,
            &mut exit,
            &mut kernel,
            &mut user,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(ProcessIdentity {
        pid,
        start_time: (u64::from(creation.dwHighDateTime) << 32) | u64::from(creation.dwLowDateTime),
    })
}

pub fn inspect(pid: u32) -> io::Result<ProcessInfo> {
    let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let identity = identity(&handle, pid)?;
    let mut buffer = vec![0u16; 32768];
    let mut len = buffer.len() as u32;
    // SAFETY: the writable buffer holds len UTF-16 code units and the handle stays open.
    let name = if unsafe {
        QueryFullProcessImageNameW(handle.as_raw_handle(), 0, buffer.as_mut_ptr(), &mut len)
    } != 0
    {
        let path = String::from_utf16_lossy(&buffer[..len as usize]);
        path.rsplit(['\\', '/'])
            .next()
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    } else {
        None
    };
    Ok(ProcessInfo {
        pid,
        name,
        identity: Some(identity),
    })
}
