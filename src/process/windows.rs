use crate::model::{DetailField, ProcessDetails, ProcessIdentity, ProcessInfo, ProcessUser};
use std::{
    io,
    os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle},
    ptr::{null, null_mut},
};
use windows_sys::Wdk::System::Threading::{
    NtQueryInformationProcess, ProcessCommandLineInformation,
};
use windows_sys::Win32::{
    Foundation::{
        LocalFree, RtlNtStatusToDosError, ERROR_INSUFFICIENT_BUFFER, ERROR_INVALID_PARAMETER,
        ERROR_NO_MORE_FILES, FILETIME, INVALID_HANDLE_VALUE, STATUS_INVALID_INFO_CLASS,
        STATUS_NOT_IMPLEMENTED, STATUS_NOT_SUPPORTED, UNICODE_STRING,
    },
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, LookupAccountSidW, TokenUser,
        PSID, SID_NAME_USE, TOKEN_QUERY, TOKEN_USER,
    },
    System::{
        Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        },
        Threading::{
            GetProcessTimes, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
            PROCESS_QUERY_LIMITED_INFORMATION,
        },
    },
    UI::Shell::CommandLineToArgvW,
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

fn executable(handle: &OwnedHandle) -> io::Result<String> {
    let mut buffer = vec![0u16; 32768];
    let mut len = buffer.len() as u32;
    // SAFETY: the writable buffer holds len UTF-16 code units and the handle stays open.
    if unsafe {
        QueryFullProcessImageNameW(handle.as_raw_handle(), 0, buffer.as_mut_ptr(), &mut len)
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    utf16(&buffer[..len as usize])
}

fn utf16(value: &[u16]) -> io::Result<String> {
    String::from_utf16(value).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

pub fn inspect(pid: u32) -> io::Result<ProcessInfo> {
    let handle = open(pid, PROCESS_QUERY_LIMITED_INFORMATION)?;
    let identity = identity(&handle, pid)?;
    let name = executable(&handle).ok().and_then(|path| {
        path.rsplit(['\\', '/'])
            .next()
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
    });
    Ok(ProcessInfo {
        pid,
        name,
        identity: Some(identity),
        details: None,
    })
}

/// Convert Windows 100 ns ticks since 1601 to the portable display timestamp.
fn unix_millis(filetime: u64) -> io::Result<u64> {
    const UNIX_EPOCH_TICKS: u64 = 116_444_736_000_000_000;
    filetime
        .checked_sub(UNIX_EPOCH_TICKS)
        .map(|ticks| ticks / 10_000)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "process start predates Unix epoch",
            )
        })
}

pub fn read_details(pid: u32) -> ProcessDetails {
    let mut details = ProcessDetails::empty();
    // Keep the same handle alive for all native reads. The common collector additionally
    // brackets this function with the expected identity to protect the parent snapshot.
    let handle = match open(pid, PROCESS_QUERY_LIMITED_INFORMATION) {
        Ok(handle) => handle,
        Err(error) => {
            super::detail_error(&mut details, DetailField::Identity, error);
            return details;
        }
    };
    match executable(&handle) {
        Ok(path) => details.executable = Some(path),
        Err(error) => super::detail_error(&mut details, DetailField::Executable, error),
    }
    match identity(&handle, pid).and_then(|identity| unix_millis(identity.start_time)) {
        Ok(time) => details.start_time_unix_ms = Some(time),
        Err(error) => super::detail_error(&mut details, DetailField::StartTimeUnixMs, error),
    }
    match process_user(&handle) {
        Ok((user, name_error)) => {
            details.user = Some(user);
            if let Some(error) = name_error {
                super::detail_error(&mut details, DetailField::User, error);
            }
        }
        Err(error) => super::detail_error(&mut details, DetailField::User, error),
    }

    match parent_pid(pid) {
        Ok(parent) => details.parent_pid = Some(parent),
        Err(error) => super::detail_error(&mut details, DetailField::ParentPid, error),
    }

    match command_line(&handle) {
        Ok(command) => details.command = Some(command),
        Err(error) => super::detail_error(&mut details, DetailField::Command, error),
    }
    details
}

/// Query a bounded, kernel-copied string on the held process handle. This uses no
/// PEB layout or remote-memory reads; unavailable information classes stay unavailable.
fn command_line(handle: &OwnedHandle) -> io::Result<Vec<String>> {
    // UNICODE_STRING's byte lengths are u16. Reserve its header, the largest
    // representable content and a trailing UTF-16 terminator, with pointer alignment.
    let size = size_of::<UNICODE_STRING>() + usize::from(u16::MAX) + 1;
    let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
    let mut written = 0;
    // SAFETY: live process handle, aligned writable buffer of at least size bytes,
    // and initialized output length. The OS copies the string into this local buffer.
    let status = unsafe {
        NtQueryInformationProcess(
            handle.as_raw_handle(),
            ProcessCommandLineInformation,
            buffer.as_mut_ptr().cast(),
            size as u32,
            &mut written,
        )
    };
    if status < 0 {
        if matches!(
            status,
            STATUS_INVALID_INFO_CLASS | STATUS_NOT_IMPLEMENTED | STATUS_NOT_SUPPORTED
        ) {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Windows command-line query is not supported",
            ));
        }
        // SAFETY: pure conversion of the returned NTSTATUS to a Win32 error code.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ));
    }
    let wide = command_buffer(&buffer, written as usize)?;
    command_arguments(wide)
}

/// Validate the returned local UNICODE_STRING before following its buffer pointer.
fn command_buffer(buffer: &[usize], written: usize) -> io::Result<Vec<u16>> {
    let invalid = || {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid Windows command-line buffer",
        )
    };
    if written < size_of::<UNICODE_STRING>() || written > std::mem::size_of_val(buffer) {
        return Err(invalid());
    }
    // SAFETY: usize storage meets UNICODE_STRING's pointer alignment and the checked
    // byte count contains its entire header; the header consists only of integers/pointer.
    let header = unsafe { &*buffer.as_ptr().cast::<UNICODE_STRING>() };
    let len = usize::from(header.Length);
    if len % 2 != 0 || header.Length > header.MaximumLength {
        return Err(invalid());
    }
    if len == 0 {
        return Ok(Vec::new());
    }
    let start = buffer.as_ptr() as usize;
    let offset = (header.Buffer as usize)
        .checked_sub(start)
        .ok_or_else(invalid)?;
    if offset < size_of::<UNICODE_STRING>()
        || offset % align_of::<u16>() != 0
        || offset.checked_add(len).is_none_or(|end| end > written)
    {
        return Err(invalid());
    }
    // SAFETY: offset and len are aligned and fully inside initialized local storage.
    // Derive the read pointer from that allocation, rather than trusting header provenance.
    let wide = unsafe {
        std::slice::from_raw_parts(
            buffer.as_ptr().cast::<u8>().add(offset).cast::<u16>(),
            len / 2,
        )
    };
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "embedded NUL in Windows command line",
        ));
    }
    utf16(wide)?;
    Ok(wide.to_vec())
}

/// Windows exposes a command-line string, parsed with the standard Shell conventions.
fn command_arguments(mut wide: Vec<u16>) -> io::Result<Vec<String>> {
    // CommandLineToArgvW("") substitutes THIS executable. Bypass that behavior so a
    // verified empty target command line stays an empty argument list.
    if wide.is_empty() {
        return Ok(Vec::new());
    }
    if wide.contains(&0) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "embedded NUL in Windows command line",
        ));
    }
    utf16(&wide)?;
    wide.push(0);
    let mut count = 0;
    // SAFETY: wide is a valid terminated UTF-16 string; count is writable. The returned
    // argument vector and all its terminated strings share one LocalFree allocation.
    let argv = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    if argv.is_null() {
        return Err(io::Error::last_os_error());
    }
    let result = (|| {
        if count <= 0 || count as usize > wide.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Windows argument count",
            ));
        }
        // SAFETY: the successful Shell API initialized count pointers to terminated strings.
        let args = unsafe { std::slice::from_raw_parts(argv, count as usize) };
        args.iter()
            .map(|arg| {
                let mut len = 0;
                // SAFETY: each pointer refers to a null-terminated string from the Shell API.
                unsafe {
                    while *arg.add(len) != 0 {
                        len += 1;
                    }
                    utf16(std::slice::from_raw_parts(*arg, len))
                }
            })
            .collect()
    })();
    // SAFETY: this is the single allocation returned by CommandLineToArgvW, freed once.
    unsafe { LocalFree(argv.cast()) };
    result
}

/// Toolhelp exposes the basic parent relation for native and WoW64 processes alike.
fn parent_pid(pid: u32) -> io::Result<u32> {
    // SAFETY: no pointers; TH32CS_SNAPPROCESS ignores the PID argument.
    let raw = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a successful snapshot returns one uniquely owned handle.
    let snapshot = unsafe { OwnedHandle::from_raw_handle(raw) };
    // SAFETY: PROCESSENTRY32W contains only integer fields and an integer array.
    let mut entry: PROCESSENTRY32W = unsafe { std::mem::zeroed() };
    entry.dwSize = size_of::<PROCESSENTRY32W>() as u32;
    // SAFETY: entry supplies the required size and writable initialized storage.
    let mut found = unsafe { Process32FirstW(snapshot.as_raw_handle(), &mut entry) };
    while found != 0 {
        if entry.th32ProcessID == pid {
            return Ok(entry.th32ParentProcessID);
        }
        // SAFETY: snapshot remains open and entry is writable with dwSize initialized.
        found = unsafe { Process32NextW(snapshot.as_raw_handle(), &mut entry) };
    }
    let error = io::Error::last_os_error();
    if error.raw_os_error() == Some(ERROR_NO_MORE_FILES as i32) {
        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "process absent from parent snapshot",
        ))
    } else {
        Err(error)
    }
}

/// Read the primary process token, preserving the SID when account-name lookup fails.
fn process_user(handle: &OwnedHandle) -> io::Result<(ProcessUser, Option<io::Error>)> {
    let mut raw_token = null_mut();
    // SAFETY: handle is live and raw_token is a writable HANDLE output.
    if unsafe { OpenProcessToken(handle.as_raw_handle(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: OpenProcessToken returned a uniquely owned token handle.
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut size = 0;
    // SAFETY: the first call requests the required byte count without an output buffer.
    let result =
        unsafe { GetTokenInformation(token.as_raw_handle(), TokenUser, null_mut(), 0, &mut size) };
    let error = io::Error::last_os_error();
    if result == 0 && error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if (size as usize) < size_of::<TOKEN_USER>() || size > 1024 * 1024 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid token user size",
        ));
    }
    // usize storage supplies TOKEN_USER's required pointer alignment, unlike Vec<u8>.
    let mut buffer = vec![0usize; (size as usize).div_ceil(size_of::<usize>())];
    // SAFETY: storage is aligned and contains at least size writable bytes.
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            buffer.as_mut_ptr().cast(),
            size,
            &mut size,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the successful query initialized a TOKEN_USER followed by the SID in buffer.
    let sid = unsafe { (*buffer.as_ptr().cast::<TOKEN_USER>()).User.Sid };
    let id = sid_string(sid)?;
    let (name, name_error) = match account_name(sid) {
        Ok(name) => (Some(name), None),
        Err(error) => (None, Some(error)),
    };
    Ok((ProcessUser { id, name }, name_error))
}

fn sid_string(sid: PSID) -> io::Result<String> {
    let mut string = null_mut();
    // SAFETY: sid is the valid SID within the live token buffer. On success Windows
    // allocates a null-terminated UTF-16 string, which must be freed with LocalFree.
    if unsafe { ConvertSidToStringSidW(sid, &mut string) } == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: Windows returned a valid, null-terminated allocated string.
    let result = unsafe {
        let mut len = 0;
        while *string.add(len) != 0 {
            len += 1;
        }
        utf16(std::slice::from_raw_parts(string, len))
    };
    // SAFETY: string is the allocation returned by ConvertSidToStringSidW, freed once.
    unsafe { LocalFree(string.cast()) };
    result
}

fn account_name(sid: PSID) -> io::Result<String> {
    let (mut name_len, mut domain_len) = (0, 0);
    let mut use_type: SID_NAME_USE = 0;
    // SAFETY: valid SID; null buffers request required UTF-16 lengths.
    let result = unsafe {
        LookupAccountSidW(
            null(),
            sid,
            null_mut(),
            &mut name_len,
            null_mut(),
            &mut domain_len,
            &mut use_type,
        )
    };
    let error = io::Error::last_os_error();
    if result == 0 && error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) {
        return Err(error);
    }
    if name_len == 0 || name_len > 32768 || domain_len > 32768 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid account name size",
        ));
    }
    let mut name = vec![0u16; name_len as usize];
    let mut domain = vec![0u16; domain_len as usize];
    // SAFETY: both buffers have the requested sizes and the SID buffer remains alive.
    if unsafe {
        LookupAccountSidW(
            null(),
            sid,
            name.as_mut_ptr(),
            &mut name_len,
            domain.as_mut_ptr(),
            &mut domain_len,
            &mut use_type,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    let name = utf16(&name[..name_len as usize])?;
    let domain = utf16(&domain[..domain_len as usize])?;
    Ok(if domain.is_empty() {
        name
    } else {
        format!("{domain}\\{name}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn command_fixture(wide: &[u16]) -> (Vec<usize>, usize) {
        let size = size_of::<UNICODE_STRING>() + std::mem::size_of_val(wide);
        let mut buffer = vec![0usize; size.div_ceil(size_of::<usize>())];
        // SAFETY: the buffer contains an aligned header followed by enough writable
        // UTF-16 space. The pointer stays valid until the returned buffer is dropped.
        unsafe {
            let content = buffer
                .as_mut_ptr()
                .cast::<u8>()
                .add(size_of::<UNICODE_STRING>())
                .cast::<u16>();
            std::ptr::copy_nonoverlapping(wide.as_ptr(), content, wide.len());
            buffer
                .as_mut_ptr()
                .cast::<UNICODE_STRING>()
                .write(UNICODE_STRING {
                    Length: std::mem::size_of_val(wide) as u16,
                    MaximumLength: std::mem::size_of_val(wide) as u16,
                    Buffer: content,
                });
        }
        (buffer, size)
    }

    #[test]
    fn empty_command_line_does_not_invent_inspector_argv() {
        let (mut buffer, size) = command_fixture(&[]);
        // SAFETY: the fixture supplies a complete aligned UNICODE_STRING header.
        unsafe {
            (*buffer.as_mut_ptr().cast::<UNICODE_STRING>()).Buffer = null_mut();
        }
        assert!(command_buffer(&buffer, size).unwrap().is_empty());
        assert!(command_arguments(Vec::new()).unwrap().is_empty());
    }

    #[test]
    fn command_buffer_checks_lengths_pointers_and_encoding() {
        let (mut buffer, size) = command_fixture(&[b'a' as u16, b'b' as u16]);
        assert_eq!(
            command_buffer(&buffer, size).unwrap(),
            [b'a' as u16, b'b' as u16]
        );
        assert!(command_buffer(&buffer, size_of::<UNICODE_STRING>() - 1).is_err());
        assert!(command_buffer(&buffer, std::mem::size_of_val(buffer.as_slice()) + 1).is_err());
        // SAFETY: these writes deliberately corrupt only header values in a valid
        // fixture; the parser must reject them before dereferencing the nested pointer.
        unsafe {
            (*buffer.as_mut_ptr().cast::<UNICODE_STRING>()).Length = 3;
        }
        assert!(command_buffer(&buffer, size).is_err());
        unsafe {
            let header = &mut *buffer.as_mut_ptr().cast::<UNICODE_STRING>();
            header.Length = 4;
            header.MaximumLength = 2;
        }
        assert!(command_buffer(&buffer, size).is_err());
        unsafe {
            let header = &mut *buffer.as_mut_ptr().cast::<UNICODE_STRING>();
            header.MaximumLength = 4;
            header.Buffer = null_mut();
        }
        assert!(command_buffer(&buffer, size).is_err());
        let base = buffer.as_mut_ptr().cast::<u16>();
        unsafe {
            (*buffer.as_mut_ptr().cast::<UNICODE_STRING>()).Buffer = base;
        }
        assert!(command_buffer(&buffer, size).is_err());
        let unaligned = (buffer.as_ptr() as usize + size_of::<UNICODE_STRING>() + 1) as *mut u16;
        // SAFETY: only the header pointer value is changed; the parser must not follow it.
        unsafe {
            (*buffer.as_mut_ptr().cast::<UNICODE_STRING>()).Buffer = unaligned;
        }
        assert!(command_buffer(&buffer, size).is_err());
        let end = (buffer.as_ptr() as usize + size) as *mut u16;
        unsafe {
            (*buffer.as_mut_ptr().cast::<UNICODE_STRING>()).Buffer = end;
        }
        assert!(command_buffer(&buffer, size).is_err());
        for wide in [vec![0xd800], vec![b'a' as u16, 0, b'b' as u16]] {
            let (buffer, size) = command_fixture(&wide);
            assert_eq!(
                command_buffer(&buffer, size).unwrap_err().kind(),
                io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn windows_command_parser_preserves_quoted_and_empty_arguments() {
        let input = r#""C:\Program Files\app.exe" "two words" "" 路径"#;
        assert_eq!(
            command_arguments(input.encode_utf16().collect()).unwrap(),
            [r"C:\Program Files\app.exe", "two words", "", "路径"]
        );
        assert_eq!(
            command_arguments(vec![0xd800]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn windows_epoch_is_converted_without_losing_milliseconds() {
        assert_eq!(unix_millis(116_444_736_000_000_000).unwrap(), 0);
        assert_eq!(unix_millis(116_444_736_012_349_999).unwrap(), 1234);
        assert_eq!(
            unix_millis(0).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn current_process_details_have_native_fields() {
        let details = read_details(std::process::id());
        assert_eq!(
            details.executable.unwrap(),
            std::env::current_exe().unwrap().to_str().unwrap()
        );
        assert_eq!(
            details.command.unwrap(),
            std::env::args().collect::<Vec<_>>()
        );
        assert!(details.user.unwrap().id.starts_with("S-1-"));
        assert!(details.parent_pid.unwrap() > 0);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis();
        assert!(u128::from(details.start_time_unix_ms.unwrap()) <= now);
        assert!(details.warnings.is_empty(), "{:?}", details.warnings);
    }

    #[test]
    fn inaccessible_process_has_no_invented_fields() {
        let details = read_details(0);
        assert!(details.executable.is_none());
        assert!(details.command.is_none());
        assert!(details.user.is_none());
        assert!(!details.warnings.is_empty());
    }

    #[test]
    fn malformed_utf16_is_reported() {
        assert_eq!(
            utf16(&[0xd800]).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
    }
}
