//! The `user_events_data` connection shared by a process's tracepoints.
//!
//! The kernel has no notion of a provider; it only knows tracepoint names. This
//! type exists to own the single file descriptor that every registration and
//! write goes through, and to keep its lifetime tied to the events that use it.

const std = @import("std");

const abi = @import("abi.zig");

const log = std.log.scoped(.user_events);

/// Owns the `user_events_data` descriptor.
///
/// Address-stable while any event is registered: the kernel keeps a pointer to
/// each tracepoint's enable word, and writes use the descriptor held here.
pub const Provider = struct {
    data_file: abi.DataFile = .{},

    /// Opens the tracefs `user_events_data` device, falling back to the legacy
    /// debugfs path.
    pub fn open(self: *Provider) abi.OpenError!void {
        return self.data_file.open();
    }

    /// Opens a specific `user_events_data` path. Useful for tests and for
    /// systems that mount tracefs somewhere unusual.
    pub fn openPath(self: *Provider, path: [:0]const u8) abi.OpenError!void {
        return self.data_file.openPath(path);
    }

    /// Opens the device, reporting failure through the log instead of the
    /// return value, and returns whether tracing is available.
    ///
    /// `user_events_data` is normally root-only and absent before Linux 6.4, so
    /// most processes cannot open it. Tracing is an optional capability: prefer
    /// this over `open` so a missing device leaves events inert rather than
    /// keeping an application from starting.
    pub fn openBestEffort(self: *Provider) bool {
        self.open() catch |err| {
            switch (err) {
                error.Unsupported => log.info(
                    "user_events is unavailable; tracepoints will not be emitted",
                    .{},
                ),
                error.PermissionDenied => log.info(
                    "no permission to open user_events_data; tracepoints will not be emitted",
                    .{},
                ),
                else => log.warn("could not open user_events_data: {t}", .{err}),
            }
            return false;
        };
        return true;
    }

    /// Closes the descriptor. Unregister every event first, otherwise their
    /// registrations outlive the descriptor they were made through.
    pub fn close(self: *Provider) void {
        self.data_file.close();
    }

    pub fn isOpen(self: *const Provider) bool {
        return self.data_file.isOpen();
    }
};

const testing = std.testing;

/// A path that never exists, so tests exercise the "unavailable" path and stay
/// hermetic instead of touching the host's tracing subsystem.
const unavailable_path = "/nonexistent/opentelemetry-zig/user_events_data";

test "a provider that never opened reports itself closed" {
    var provider: Provider = .{};
    defer provider.close();

    try testing.expect(!provider.isOpen());
}

test "a missing device is reported as unsupported" {
    var provider: Provider = .{};
    defer provider.close();

    try testing.expectError(error.Unsupported, provider.openPath(unavailable_path));
    try testing.expect(!provider.isOpen());
}

test "best effort opening never fails, it reports availability" {
    var provider: Provider = .{};
    defer provider.close();

    // Deliberately not asserting the result: whether the host has a usable
    // user_events_data depends on the kernel and on privileges.
    _ = provider.openBestEffort();
}

test "closing is idempotent" {
    var provider: Provider = .{};
    provider.close();
    provider.close();
    try testing.expect(!provider.isOpen());
}
