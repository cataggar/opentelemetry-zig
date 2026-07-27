//! Minimal Linux `user_events` ABI.
//!
//! `user_events` lets a user-mode process create tracepoints that are only
//! materialized when a listener (ftrace, perf, or a local agent) enables them.
//! Registration happens through ioctls on `/sys/kernel/tracing/user_events_data`
//! and events are emitted with a single `writev` whose first vector carries the
//! kernel-assigned write index.
//!
//! see: https://docs.kernel.org/trace/user_events.html

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;

const is_linux = builtin.os.tag == .linux;

/// tracefs is normally mounted here; the debugfs path is the legacy location.
pub const default_data_file_path: [:0]const u8 = "/sys/kernel/tracing/user_events_data";
pub const legacy_data_file_path: [:0]const u8 = "/sys/kernel/debug/tracing/user_events_data";

/// The kernel writes the enable bits into a caller-owned word of this size.
pub const enable_word_size: u8 = @sizeOf(u32);

/// `writev` vector type used to submit an event without copying payload bytes.
pub const Iovec = std.posix.iovec_const;

/// Upper bound on the `name args` string accepted by `DIAG_IOCSREG`.
pub const max_name_args_len: usize = 511;

/// Upper bound on a tracepoint name accepted by the kernel.
pub const max_name_len: usize = 255;

pub const OpenError = error{
    /// tracefs is not mounted, or the kernel predates user_events (< 6.4).
    Unsupported,
    /// Opening `user_events_data` requires root or CAP_DAC_OVERRIDE.
    PermissionDenied,
    AlreadyOpen,
    SystemResources,
    Unexpected,
};

pub const RegisterError = error{
    AlreadyRegistered,
    DataFileClosed,
    /// The name or argument string is malformed or conflicts with an existing
    /// tracepoint that was registered with a different schema.
    InvalidRegistration,
    PermissionDenied,
    SystemResources,
    Unexpected,
};

pub const UnregisterError = error{
    InvalidRegistration,
    Unexpected,
};

pub const WriteError = error{
    NotRegistered,
    /// The tracepoint lost its last listener between the enablement check and
    /// the write. Callers normally treat this as a no-op rather than a failure.
    NoListener,
    /// The event exceeded the 64KiB user_events payload limit.
    PayloadTooLarge,
    Interrupted,
    Unexpected,
};

/// Linux UAPI `struct user_reg`.
pub const UserReg = extern struct {
    size: u32 align(1),
    enable_bit: u8 align(1),
    enable_size: u8 align(1),
    flags: u16 align(1),
    enable_addr: u64 align(1),
    name_args: u64 align(1),
    write_index: u32 align(1),
};

/// Linux UAPI `struct user_unreg`.
pub const UserUnreg = extern struct {
    size: u32 align(1),
    disable_bit: u8 align(1),
    reserved: u8 align(1),
    reserved2: u16 align(1),
    disable_addr: u64 align(1),
};

/// The kernel encodes the caller's pointer width into these ioctl numbers.
pub const DIAG_IOCSREG = linux.IOCTL.IOWR('*', 0, *UserReg);
pub const DIAG_IOCSDEL = linux.IOCTL.IOW('*', 1, [*:0]const u8);
pub const DIAG_IOCSUNREG = linux.IOCTL.IOW('*', 2, *UserUnreg);

comptime {
    if (@sizeOf(UserReg) != 28) @compileError("user_reg must be 28 bytes");
    if (@sizeOf(UserUnreg) != 16) @compileError("user_unreg must be 16 bytes");
}

/// Owns the `user_events_data` descriptor shared by every tracepoint of a
/// provider. Address-stable: initialize it in its final storage.
pub const DataFile = struct {
    fd: linux.fd_t = -1,

    const closed_fd: linux.fd_t = -1;

    /// Opens the default tracefs path, falling back to the legacy debugfs path.
    pub fn open(self: *DataFile) OpenError!void {
        self.openPath(default_data_file_path) catch |err| switch (err) {
            error.Unsupported => return self.openPath(legacy_data_file_path),
            else => return err,
        };
    }

    pub fn openPath(self: *DataFile, path: [:0]const u8) OpenError!void {
        if (!is_linux) return error.Unsupported;
        if (self.fd != closed_fd) return error.AlreadyOpen;

        const rc = linux.openat(linux.AT.FDCWD, path, .{ .ACCMODE = .RDWR, .CLOEXEC = true }, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                self.fd = @intCast(rc);
                return;
            },
            .NOENT, .NODEV, .NXIO => return error.Unsupported,
            .ACCES, .PERM => return error.PermissionDenied,
            .MFILE, .NFILE, .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
    }

    /// Closes the descriptor. Every tracepoint must be unregistered first.
    pub fn close(self: *DataFile) void {
        if (self.fd == closed_fd) return;
        _ = linux.close(self.fd);
        self.fd = closed_fd;
    }

    pub fn isOpen(self: *const DataFile) bool {
        return self.fd != closed_fd;
    }
};

/// A single registered tracepoint.
///
/// The kernel keeps a pointer to `enable_word` for the whole registration, so
/// this value must not be copied or moved while registered.
pub const Tracepoint = struct {
    /// Written by the kernel when a listener enables or disables the event.
    enable_word: u32 align(@sizeOf(u32)) = 0,
    write_index: u32 = 0,
    /// Captured at registration so writes do not need to reach the DataFile.
    write_fd: linux.fd_t = -1,
    registered: bool = false,

    /// Bit index within `enable_word`. Each tracepoint owns its own word, so
    /// bit 0 is always used.
    const enable_bit: u8 = 0;

    pub fn register(
        self: *Tracepoint,
        data_file: *const DataFile,
        name_args: [:0]const u8,
    ) RegisterError!void {
        if (self.registered) return error.AlreadyRegistered;
        if (!data_file.isOpen()) return error.DataFileClosed;
        if (name_args.len > max_name_args_len) return error.InvalidRegistration;

        @atomicStore(u32, &self.enable_word, 0, .monotonic);

        var reg = UserReg{
            .size = @sizeOf(UserReg),
            .enable_bit = enable_bit,
            .enable_size = enable_word_size,
            .flags = 0,
            .enable_addr = @intFromPtr(&self.enable_word),
            .name_args = @intFromPtr(name_args.ptr),
            .write_index = 0,
        };

        const rc = linux.ioctl(data_file.fd, DIAG_IOCSREG, @intFromPtr(&reg));
        switch (linux.errno(rc)) {
            .SUCCESS => {
                self.write_index = reg.write_index;
                self.write_fd = data_file.fd;
                self.registered = true;
            },
            .INVAL, .BADMSG, .BUSY => return error.InvalidRegistration,
            .ACCES, .PERM => return error.PermissionDenied,
            .NOMEM => return error.SystemResources,
            else => return error.Unexpected,
        }
    }

    pub fn unregister(
        self: *Tracepoint,
        data_file: *const DataFile,
    ) UnregisterError!void {
        if (!self.registered) return;

        var unreg = UserUnreg{
            .size = @sizeOf(UserUnreg),
            .disable_bit = enable_bit,
            .reserved = 0,
            .reserved2 = 0,
            .disable_addr = @intFromPtr(&self.enable_word),
        };

        // Stop emitting first: the kernel clears the enable word during
        // unregistration, but a concurrent writer must not observe it enabled.
        self.registered = false;
        @atomicStore(u32, &self.enable_word, 0, .monotonic);

        if (!data_file.isOpen()) return;

        const rc = linux.ioctl(data_file.fd, DIAG_IOCSUNREG, @intFromPtr(&unreg));
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INVAL => return error.InvalidRegistration,
            else => return error.Unexpected,
        }
    }

    pub fn isRegistered(self: *const Tracepoint) bool {
        return self.registered;
    }

    /// True when at least one listener has enabled this tracepoint. This is the
    /// cheap check that keeps instrumentation close to free when nobody is
    /// collecting.
    pub fn isEnabled(self: *const Tracepoint) bool {
        if (!self.registered) return false;
        return (@atomicLoad(u32, &self.enable_word, .monotonic) & (@as(u32, 1) << enable_bit)) != 0;
    }

    /// Submits one event. `vectors[0]` is reserved for the write index and is
    /// overwritten here; the remaining vectors are passed to the kernel as-is.
    pub fn writev(self: *const Tracepoint, vectors: []Iovec) WriteError!void {
        if (!self.registered) return error.NotRegistered;
        std.debug.assert(vectors.len >= 1);

        const index_bytes: [4]u8 = @bitCast(self.write_index);
        vectors[0] = .{ .base = &index_bytes, .len = index_bytes.len };

        while (true) {
            const rc = linux.writev(self.write_fd, vectors.ptr, vectors.len);
            switch (linux.errno(rc)) {
                .SUCCESS => return,
                .INTR => continue,
                // The kernel reports a vanished listener as EBADF.
                .BADF, .NOENT => return error.NoListener,
                .INVAL, .@"2BIG", .FAULT => return error.PayloadTooLarge,
                else => return error.Unexpected,
            }
        }
    }
};

test "ioctl numbers match the kernel UAPI on 64-bit x86" {
    if (builtin.cpu.arch != .x86_64 or @sizeOf(usize) != 8) return error.SkipZigTest;
    try std.testing.expectEqual(@as(u32, 0xc0082a00), DIAG_IOCSREG);
    try std.testing.expectEqual(@as(u32, 0x40082a01), DIAG_IOCSDEL);
    try std.testing.expectEqual(@as(u32, 0x40082a02), DIAG_IOCSUNREG);
}

test "user_reg field offsets match the kernel UAPI" {
    try std.testing.expectEqual(0, @offsetOf(UserReg, "size"));
    try std.testing.expectEqual(4, @offsetOf(UserReg, "enable_bit"));
    try std.testing.expectEqual(5, @offsetOf(UserReg, "enable_size"));
    try std.testing.expectEqual(6, @offsetOf(UserReg, "flags"));
    try std.testing.expectEqual(8, @offsetOf(UserReg, "enable_addr"));
    try std.testing.expectEqual(16, @offsetOf(UserReg, "name_args"));
    try std.testing.expectEqual(24, @offsetOf(UserReg, "write_index"));

    try std.testing.expectEqual(0, @offsetOf(UserUnreg, "size"));
    try std.testing.expectEqual(4, @offsetOf(UserUnreg, "disable_bit"));
    try std.testing.expectEqual(8, @offsetOf(UserUnreg, "disable_addr"));
}

test "an unregistered tracepoint is never enabled" {
    var tracepoint: Tracepoint = .{};
    try std.testing.expect(!tracepoint.isEnabled());
    try std.testing.expect(!tracepoint.isRegistered());

    var vectors = [_]Iovec{.{ .base = "", .len = 0 }};
    try std.testing.expectError(error.NotRegistered, tracepoint.writev(&vectors));
}

test "closing a never-opened data file is a no-op" {
    var data_file: DataFile = .{};
    try std.testing.expect(!data_file.isOpen());
    data_file.close();
    try std.testing.expect(!data_file.isOpen());
}
