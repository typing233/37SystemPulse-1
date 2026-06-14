/// Zero-copy proc/sys reading via raw syscalls.
/// Avoids libc buffering and heap allocation by using pread into stack buffers.

#[cfg(target_os = "linux")]
pub mod syscall {
    use std::ffi::CString;

    const SYS_OPENAT: i64 = 257;
    const SYS_READ: i64 = 0;
    const SYS_CLOSE: i64 = 3;
    const SYS_PREAD64: i64 = 17;
    const SYS_GETDENTS64: i64 = 217;
    const AT_FDCWD: i64 = -100;
    const O_RDONLY: i64 = 0;

    #[inline(always)]
    unsafe fn syscall3(nr: i64, a1: i64, a2: i64, a3: i64) -> i64 {
        let ret: i64;
        std::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            out("rcx") _,
            out("r11") _,
            lateout("rax") ret,
        );
        ret
    }

    #[inline(always)]
    unsafe fn syscall4(nr: i64, a1: i64, a2: i64, a3: i64, a4: i64) -> i64 {
        let ret: i64;
        std::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") a1,
            in("rsi") a2,
            in("rdx") a3,
            in("r10") a4,
            out("rcx") _,
            out("r11") _,
            lateout("rax") ret,
        );
        ret
    }

    /// Open a file and read its full content into a stack buffer.
    /// Returns the number of bytes read, or negative on error.
    pub fn read_file_to_buf(path: &[u8], buf: &mut [u8]) -> isize {
        unsafe {
            // path must be null-terminated
            let fd = syscall4(
                SYS_OPENAT,
                AT_FDCWD,
                path.as_ptr() as i64,
                O_RDONLY,
                0,
            );
            if fd < 0 {
                return fd as isize;
            }
            let mut total: usize = 0;
            loop {
                let n = syscall3(
                    SYS_READ,
                    fd,
                    buf[total..].as_mut_ptr() as i64,
                    (buf.len() - total) as i64,
                );
                if n <= 0 {
                    break;
                }
                total += n as usize;
                if total >= buf.len() {
                    break;
                }
            }
            syscall3(SYS_CLOSE, fd, 0, 0);
            total as isize
        }
    }

    /// pread at offset - useful for re-reading without re-opening
    pub fn pread_file(fd: i32, buf: &mut [u8], offset: u64) -> isize {
        unsafe {
            syscall4(
                SYS_PREAD64,
                fd as i64,
                buf.as_mut_ptr() as i64,
                buf.len() as i64,
                offset as i64,
            ) as isize
        }
    }

    /// Open file, return fd
    pub fn open_readonly(path: &[u8]) -> i32 {
        unsafe {
            syscall4(
                SYS_OPENAT,
                AT_FDCWD,
                path.as_ptr() as i64,
                O_RDONLY,
                0,
            ) as i32
        }
    }

    pub fn close_fd(fd: i32) {
        unsafe {
            syscall3(SYS_CLOSE, fd as i64, 0, 0);
        }
    }

    /// Read directory entries (getdents64)
    #[repr(C)]
    pub struct LinuxDirent64 {
        pub d_ino: u64,
        pub d_off: i64,
        pub d_reclen: u16,
        pub d_type: u8,
        // d_name follows
    }

    pub fn getdents64(fd: i32, buf: &mut [u8]) -> isize {
        unsafe {
            syscall3(
                SYS_GETDENTS64,
                fd as i64,
                buf.as_mut_ptr() as i64,
                buf.len() as i64,
            ) as isize
        }
    }

    /// Count entries in a directory using raw getdents64
    pub fn count_dir_entries(path: &[u8]) -> u64 {
        let fd = open_readonly(path);
        if fd < 0 {
            return 0;
        }
        let mut buf = [0u8; 4096];
        let mut count: u64 = 0;
        loop {
            let n = getdents64(fd, &mut buf);
            if n <= 0 {
                break;
            }
            let mut offset = 0usize;
            while offset < n as usize {
                let ent = unsafe {
                    &*(buf.as_ptr().add(offset) as *const LinuxDirent64)
                };
                if ent.d_reclen == 0 {
                    break;
                }
                // Skip . and ..
                let name_ptr = unsafe { buf.as_ptr().add(offset + 19) };
                let first = unsafe { *name_ptr };
                if first != b'.' {
                    count += 1;
                } else {
                    let second = unsafe { *name_ptr.add(1) };
                    if second != 0 && !(second == b'.' && unsafe { *name_ptr.add(2) } == 0) {
                        count += 1;
                    }
                }
                offset += ent.d_reclen as usize;
            }
        }
        close_fd(fd);
        count
    }

    /// BPF syscall interface for eBPF-based IO latency tracing
    pub const SYS_BPF: i64 = 321;
    pub const BPF_MAP_CREATE: u32 = 0;
    pub const BPF_MAP_LOOKUP_ELEM: u32 = 1;
    pub const BPF_MAP_UPDATE_ELEM: u32 = 2;
    pub const BPF_PROG_LOAD: u32 = 5;
    pub const BPF_MAP_TYPE_HASH: u32 = 1;
    pub const BPF_MAP_TYPE_ARRAY: u32 = 2;
    pub const BPF_PROG_TYPE_KPROBE: u32 = 1;
    pub const BPF_PROG_TYPE_TRACEPOINT: u32 = 6;

    #[repr(C)]
    #[derive(Default)]
    pub struct BpfAttrMapCreate {
        pub map_type: u32,
        pub key_size: u32,
        pub value_size: u32,
        pub max_entries: u32,
        pub map_flags: u32,
    }

    #[repr(C)]
    pub struct BpfAttrMapElem {
        pub map_fd: u32,
        pub key: u64,
        pub value_or_next: u64,
        pub flags: u64,
    }

    pub fn bpf_syscall(cmd: u32, attr: *const u8, size: u32) -> i64 {
        unsafe {
            syscall3(SYS_BPF, cmd as i64, attr as i64, size as i64)
        }
    }

    pub fn bpf_map_create(map_type: u32, key_size: u32, value_size: u32, max_entries: u32) -> i32 {
        let attr = BpfAttrMapCreate {
            map_type,
            key_size,
            value_size,
            max_entries,
            map_flags: 0,
        };
        bpf_syscall(
            BPF_MAP_CREATE,
            &attr as *const _ as *const u8,
            std::mem::size_of::<BpfAttrMapCreate>() as u32,
        ) as i32
    }

    pub fn bpf_map_lookup(map_fd: i32, key: &[u8], value: &mut [u8]) -> i32 {
        let attr = BpfAttrMapElem {
            map_fd: map_fd as u32,
            key: key.as_ptr() as u64,
            value_or_next: value.as_mut_ptr() as u64,
            flags: 0,
        };
        bpf_syscall(
            BPF_MAP_LOOKUP_ELEM,
            &attr as *const _ as *const u8,
            std::mem::size_of::<BpfAttrMapElem>() as u32,
        ) as i32
    }
}

/// Helper to parse numbers from byte slices without String allocation
pub fn parse_u64_from_bytes(bytes: &[u8]) -> u64 {
    let mut result: u64 = 0;
    for &b in bytes {
        if b >= b'0' && b <= b'9' {
            result = result.wrapping_mul(10).wrapping_add((b - b'0') as u64);
        } else {
            break;
        }
    }
    result
}

/// Skip whitespace in a byte slice, return remaining
pub fn skip_whitespace(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < bytes.len() && (bytes[i] == b' ' || bytes[i] == b'\t') {
        i += 1;
    }
    &bytes[i..]
}

/// Find next whitespace or newline
pub fn next_field(bytes: &[u8]) -> (&[u8], &[u8]) {
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b' ' && bytes[i] != b'\t' && bytes[i] != b'\n' {
        i += 1;
    }
    (&bytes[..i], &bytes[i..])
}

/// Find next line
pub fn next_line(bytes: &[u8]) -> &[u8] {
    let mut i = 0;
    while i < bytes.len() && bytes[i] != b'\n' {
        i += 1;
    }
    if i < bytes.len() {
        &bytes[i + 1..]
    } else {
        &[]
    }
}
