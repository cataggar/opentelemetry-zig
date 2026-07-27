//! Linux `user_events` tracepoints for Zig.
//!
//! `user_events` is the Linux counterpart to ETW on Windows: a process declares
//! its tracepoints up front and the kernel only materializes events while a
//! listener (ftrace, `perf`, or a local agent) has them enabled. Emitting is
//! therefore nearly free when nothing is collecting.
//!
//! This module is standalone. It has no dependency on the OpenTelemetry SDK, so
//! a project that only wants Linux tracepoints can depend on it alone:
//!
//! ```zig
//! const otel = b.dependency("opentelemetry", .{ .target = target, .optimize = optimize });
//! exe.root_module.addImport("user_events", otel.module("user_events"));
//! ```
//!
//! Events are described by a Zig struct type at comptime, so the wire schema is
//! derived from the type system and `write` is checked by the compiler:
//!
//! ```zig
//! const user_events = @import("user_events");
//!
//! const Checkout = user_events.Event(.{ .name = "Checkout" }, struct {
//!     order_id: u64,
//!     path: []const u8,
//!     ok: bool,
//! });
//!
//! var provider = try user_events.Provider.init(allocator, "myapp");
//! defer provider.deinit();
//!
//! const checkout = try provider.register(Checkout);
//! if (checkout.isEnabled()) {
//!     try checkout.write(.{ .order_id = 42, .path = "/api/checkout", .ok = true });
//! }
//! ```
//!
//! Requires Linux 6.4 or newer. Registration needs access to
//! `/sys/kernel/tracing/user_events_data`, which is usually root-only.
//!
//! see: https://docs.kernel.org/trace/user_events.html

/// Raw kernel ABI: the `user_events_data` character device, the DIAG ioctls,
/// and the tracepoint registration/write primitives.
pub const abi = @import("user_events/abi.zig");

/// EventHeader encoding: the comptime schema description, its metadata
/// serialization, and the payload accounting that sizes the write buffers.
pub const eventheader = @import("user_events/eventheader.zig");

/// Comptime schema derivation, the payload encoder, and the tracepoint types.
pub const event = @import("user_events/event.zig");

const event_mod = event;

/// Declares a tracepoint from a `Config` and a struct type describing its
/// payload. This is the entry point for most callers.
pub const Event = event_mod.Event;
/// Declares one schema emitted at every level, with the level chosen per write.
pub const LeveledEvent = event_mod.LeveledEvent;
/// Identity of an event: provider, name, level, and keyword.
pub const Config = event_mod.Config;
/// Wraps an integer field so decoders render it as hexadecimal.
pub const Hex = event_mod.Hex;
/// Owns the `user_events_data` descriptor shared by a process's tracepoints.
pub const Provider = @import("user_events/provider.zig").Provider;

/// Severity of an event, used to pick which tracepoint carries it.
pub const Level = eventheader.Level;
/// How a field's bytes are laid out in the payload.
pub const Encoding = eventheader.Encoding;
/// Presentation hint applied on top of an `Encoding`.
pub const Format = eventheader.Format;

test {
    const builtin = @import("builtin");
    if (builtin.os.tag == .linux) {
        _ = @import("user_events/abi.zig");
        _ = @import("user_events/eventheader.zig");
        _ = @import("user_events/event.zig");
    }
}
