#[cfg(target_os = "linux")]
pub mod syscall {

    const SYS_OPENAT: i64 = 257;
    const SYS_READ: i64 = 0;
    const SYS_CLOSE: i64 = 3;
    const SYS_PREAD64: i64 = 17;
    const SYS_LSEEK: i64 = 8;
    const SYS_GETDENTS64: i64 = 217;
    const SYS_PERF_EVENT_OPEN: i64 = 298;
    const SYS_IOCTL: i64 = 16;
    const AT_FDCWD: i64 = -100;
    const O_RDONLY: i64 = 0;
    const SEEK_SET: i64 = 0;

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

    pub fn lseek(fd: i32, offset: i64, whence: i32) -> i64 {
        unsafe {
            syscall3(SYS_LSEEK, fd as i64, offset, whence as i64)
        }
    }

    pub fn read_fd(fd: i32, buf: &mut [u8]) -> isize {
        unsafe {
            let mut total: usize = 0;
            loop {
                let n = syscall3(
                    SYS_READ,
                    fd as i64,
                    buf[total..].as_mut_ptr() as i64,
                    (buf.len() - total) as i64,
                );
                if n <= 0 { break; }
                total += n as usize;
                if total >= buf.len() { break; }
            }
            total as isize
        }
    }

    /// Persistent file descriptor — opened once, re-read via lseek(0)+read each cycle.
    /// This is true zero-copy: no open/close syscall overhead per collection.
    pub struct PersistentFd {
        fd: i32,
        path: [u8; 64],
        path_len: usize,
    }

    impl PersistentFd {
        pub fn open(path: &[u8]) -> Option<Self> {
            let fd = open_readonly(path);
            if fd < 0 { return None; }
            let mut p = [0u8; 64];
            let len = path.len().min(64);
            p[..len].copy_from_slice(&path[..len]);
            Some(Self { fd, path: p, path_len: len })
        }

        /// Re-read file from beginning into buf without reopening.
        /// Uses lseek(fd, 0, SEEK_SET) + read() — avoids open/close per cycle.
        /// Falls back to open/read/close if lseek+read returns 0 (some /proc/net files).
        pub fn reread(&self, buf: &mut [u8]) -> isize {
            let ret = lseek(self.fd, 0, SEEK_SET as i32);
            if ret >= 0 {
                let n = read_fd(self.fd, buf);
                if n > 0 {
                    return n;
                }
            }
            read_file_to_buf(&self.path[..self.path_len], buf)
        }

        /// pread at offset 0 — alternative zero-copy read without lseek.
        pub fn pread(&self, buf: &mut [u8]) -> isize {
            pread_file(self.fd, buf, 0)
        }

        pub fn fd(&self) -> i32 { self.fd }
    }

    impl Drop for PersistentFd {
        fn drop(&mut self) {
            close_fd(self.fd);
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

    pub fn bpf_map_update(map_fd: i32, key: &[u8], value: &[u8], flags: u64) -> i32 {
        let attr = BpfAttrMapElem {
            map_fd: map_fd as u32,
            key: key.as_ptr() as u64,
            value_or_next: value.as_ptr() as u64,
            flags,
        };
        bpf_syscall(
            BPF_MAP_UPDATE_ELEM,
            &attr as *const _ as *const u8,
            std::mem::size_of::<BpfAttrMapElem>() as u32,
        ) as i32
    }

    #[repr(C)]
    #[derive(Default)]
    pub struct BpfAttrProgLoad {
        pub prog_type: u32,
        pub insn_cnt: u32,
        pub insns: u64,
        pub license: u64,
        pub log_level: u32,
        pub log_size: u32,
        pub log_buf: u64,
        pub kern_version: u32,
        pub prog_flags: u32,
        pub prog_name: [u8; 16],
        pub prog_ifindex: u32,
        pub expected_attach_type: u32,
    }

    pub fn bpf_prog_load(prog_type: u32, insns: &[u64], license: &[u8]) -> i32 {
        let mut attr = BpfAttrProgLoad::default();
        attr.prog_type = prog_type;
        attr.insn_cnt = (insns.len() as u32) / 1; // each insn is 8 bytes = 1 u64
        attr.insns = insns.as_ptr() as u64;
        attr.license = license.as_ptr() as u64;
        attr.kern_version = 0;

        bpf_syscall(
            BPF_PROG_LOAD,
            &attr as *const _ as *const u8,
            std::mem::size_of::<BpfAttrProgLoad>() as u32,
        ) as i32
    }

    /// Attach a BPF program to a kprobe via perf_event_open + ioctl
    pub fn attach_kprobe(prog_fd: i32, func_name: &str, is_return: bool) -> i32 {
        // Write to /sys/kernel/debug/tracing/kprobe_events or use perf_event_open
        // We use the tracefs approach: create kprobe event, then perf_event_open
        let event_type = if is_return { "r" } else { "p" };
        let event_name = format!("syspulse_{}_{}", event_type, func_name.replace('.', "_"));

        // Write kprobe event definition
        let kprobe_str = format!("{}:{} {}\n", event_type, event_name, func_name);
        let kprobe_path = b"/sys/kernel/debug/tracing/kprobe_events\0";
        let kp_fd = unsafe {
            syscall4(SYS_OPENAT, AT_FDCWD, kprobe_path.as_ptr() as i64, 1 /* O_WRONLY */ | 1024 /* O_APPEND */, 0)
        };
        if kp_fd < 0 {
            return -1;
        }
        let write_ret = unsafe {
            syscall3(1 /* SYS_WRITE */, kp_fd, kprobe_str.as_ptr() as i64, kprobe_str.len() as i64)
        };
        close_fd(kp_fd as i32);
        if write_ret < 0 {
            return -1;
        }

        // Find the event ID from /sys/kernel/debug/tracing/events/kprobes/<event_name>/id
        let id_path = format!("/sys/kernel/debug/tracing/events/kprobes/{}/id\0", event_name);
        let mut id_buf = [0u8; 32];
        let n = read_file_to_buf(id_path.as_bytes(), &mut id_buf);
        if n <= 0 {
            return -1;
        }
        let event_id = crate::platform::linux::parse_u64_from_bytes(&id_buf[..n as usize]);

        // perf_event_open with the kprobe event
        #[repr(C)]
        #[derive(Default)]
        struct PerfEventAttr {
            type_: u32,
            size: u32,
            config: u64,
            sample_period: u64,
            sample_type: u64,
            read_format: u64,
            flags: u64,
            wakeup_events: u32,
            bp_type: u32,
            bp_addr_or_config1: u64,
            bp_len_or_config2: u64,
            branch_sample_type: u64,
            sample_regs_user: u64,
            sample_stack_user: u32,
            clockid: i32,
            sample_regs_intr: u64,
            aux_watermark: u32,
            sample_max_stack: u16,
            reserved_2: u16,
        }

        let mut attr = PerfEventAttr::default();
        attr.type_ = 6; // PERF_TYPE_TRACEPOINT
        attr.size = std::mem::size_of::<PerfEventAttr>() as u32;
        attr.config = event_id;
        attr.sample_period = 1;
        attr.flags = 0;

        let perf_fd = unsafe {
            // perf_event_open(attr, pid=-1, cpu=0, group_fd=-1, flags=PERF_FLAG_FD_CLOEXEC)
            let ret: i64;
            std::arch::asm!(
                "syscall",
                in("rax") SYS_PERF_EVENT_OPEN,
                in("rdi") &attr as *const _ as i64,
                in("rsi") -1i64, // pid
                in("rdx") 0i64,  // cpu
                in("r10") -1i64, // group_fd
                in("r8") 8i64,   // PERF_FLAG_FD_CLOEXEC
                out("rcx") _,
                out("r11") _,
                lateout("rax") ret,
            );
            ret
        };
        if perf_fd < 0 {
            return -1;
        }

        // IOCTL: PERF_EVENT_IOC_SET_BPF
        const PERF_EVENT_IOC_SET_BPF: i64 = 0x40042408;
        const PERF_EVENT_IOC_ENABLE: i64 = 0x00002400;
        let ret = unsafe {
            syscall3(SYS_IOCTL, perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd as i64)
        };
        if ret < 0 {
            close_fd(perf_fd as i32);
            return -1;
        }
        unsafe {
            syscall3(SYS_IOCTL, perf_fd, PERF_EVENT_IOC_ENABLE, 0);
        }
        perf_fd as i32
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
