//! End-to-end check of the comptime-typed `user_events` API against a real
//! kernel, using the `user_events` module on its own.
//!
//! This test deliberately does not import `opentelemetry-sdk`. Besides
//! exercising the tracepoint layer, that makes it the standing proof that the
//! module is usable by a project that wants Linux tracepoints and nothing else.
//!
//! The unit tests decode the bytes an event would write, but they never reach
//! the kernel, so they cannot catch a wrong ioctl number, a malformed
//! registration string, or an enablement bit the kernel refuses to set. This
//! test closes that gap: it registers, has the kernel enable its own
//! tracepoint through tracefs, writes an event, and reads it back out of the
//! ftrace ring buffer.
//!
//! Registering needs write access to `/sys/kernel/tracing/user_events_data`,
//! which is normally root-only, so the test skips rather than fails when it
//! cannot get there.

const std = @import("std");
const builtin = @import("builtin");
const user_events = @import("user_events");

const tracefs = "/sys/kernel/tracing";

/// The whole schema: a Zig struct type. Field names, order, and encodings are
/// all derived from it at comptime.
const Checkout = user_events.Event(.{
    .provider = "otel_zig_tracepoint",
    .name = "Checkout",
    .level = .informational,
    .keyword = 1,
}, struct {
    order_id: u64,
    route: []const u8,
    attempts: i16,
    latency_ms: f64,
    cache_hit: bool,
    address: user_events.Hex(u64),
    region: enum(u8) { east, west },
    detail: struct {
        code: u32,
        message: []const u8,
    },
});

/// Registered but never enabled, so it proves an idle tracepoint stays idle.
const Debug = user_events.Event(.{
    .provider = "otel_zig_tracepoint",
    .name = "Debug",
    .level = .verbose,
    .keyword = 1,
}, struct { note: []const u8 });

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .linux) {
        std.debug.print("Skipping user_events tracepoint test: not Linux\n", .{});
        return;
    }

    const allocator = init.gpa;
    const io = init.io;

    std.debug.print("Running user_events tracepoint integration test...\n", .{});

    try std.testing.expectEqualStrings("otel_zig_tracepoint_L4K1", Checkout.tracepoint_name);
    try std.testing.expectEqualStrings("otel_zig_tracepoint_L5K1", Debug.tracepoint_name);

    var provider: user_events.Provider = .{};
    defer provider.close();

    if (!provider.openBestEffort()) {
        std.debug.print(
            "⊘ Skipped: could not open {s}/user_events_data (needs Linux 6.4+ and root)\n\n",
            .{tracefs},
        );
        return;
    }

    var checkout: Checkout = .{};
    var debug: Debug = .{};

    try checkout.register(&provider);
    defer checkout.unregister(&provider);
    try debug.register(&provider);
    defer debug.unregister(&provider);

    try expect(checkout.isRegistered(), "Checkout reported itself unregistered after registering");
    try expect(!checkout.isEnabled(), "Checkout was enabled before any listener asked for it");

    // The kernel exposes a registered tracepoint under tracefs, so its absence
    // means registration reported success without taking effect.
    var enable_path_buf: [256]u8 = undefined;
    const enable_path = try std.fmt.bufPrint(
        &enable_path_buf,
        tracefs ++ "/events/user_events/{s}/enable",
        .{Checkout.tracepoint_name},
    );

    std.Io.Dir.cwd().access(io, enable_path, .{}) catch {
        std.debug.print("✗ {s} was registered but does not appear under tracefs\n", .{Checkout.tracepoint_name});
        return error.TracepointMissing;
    };

    try writeFile(io, enable_path, "1");
    defer writeFile(io, enable_path, "0") catch {};
    try writeFile(io, tracefs ++ "/tracing_on", "1");
    try writeFile(io, tracefs ++ "/trace", "");

    // Enablement propagates to the process asynchronously, so poll rather than
    // assume the write above has already landed in our enable word.
    if (!try waitForEnabled(io, &checkout)) {
        std.debug.print("✗ tracepoint enabled in tracefs but the process never observed it\n", .{});
        return error.EnablementNotObserved;
    }

    // Only Checkout was enabled: enablement is per tracepoint, not per provider.
    try expect(!debug.isEnabled(), "Debug became enabled even though only Checkout was");

    try checkout.write(.{
        .order_id = 0x1122334455667788,
        .route = "/api/checkout",
        .attempts = -2,
        .latency_ms = 12.5,
        .cache_hit = true,
        .address = .{ .value = 0xdeadbeef },
        .region = .west,
        .detail = .{ .code = 200, .message = "ok" },
    });

    // A no-op rather than an error: nothing is collecting this one.
    try debug.write(.{ .note = "not collected" });

    // The per-CPU ring buffers are drained into `trace` lazily, so a read that
    // immediately follows the write can legitimately come back empty.
    const trace = try readTraceUntil(allocator, io, Checkout.tracepoint_name) orelse {
        std.debug.print("✗ no {s} event reached the ftrace ring buffer\n", .{Checkout.tracepoint_name});
        return error.EventNotRecorded;
    };
    defer allocator.free(trace);

    // ftrace only formats the eight declared header fields; the level proves
    // the event was routed to the tracepoint its config names.
    if (std.mem.indexOf(u8, trace, "level=(4)") == null) {
        std.debug.print("✗ event recorded but not at the informational level\n", .{});
        return error.WrongLevel;
    }
    if (std.mem.indexOf(u8, trace, Debug.tracepoint_name) != null) {
        std.debug.print("✗ a disabled tracepoint still reached the ring buffer\n", .{});
        return error.DisabledEventRecorded;
    }

    // Unregistering must stop emission even while tracefs still has the
    // tracepoint enabled.
    checkout.unregister(&provider);
    try expect(!checkout.isRegistered(), "Checkout still reported itself registered after unregistering");
    try expect(!checkout.isEnabled(), "an unregistered tracepoint still reported itself enabled");

    std.debug.print("✓ user_events tracepoint test passed\n\n", .{});
}

fn expect(condition: bool, message: []const u8) !void {
    if (condition) return;
    std.debug.print("✗ {s}\n", .{message});
    return error.AssertionFailed;
}

fn waitForEnabled(io: std.Io, event: *const Checkout) !bool {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        if (event.isEnabled()) return true;
        try io.sleep(.fromMilliseconds(20), .awake);
    }
    return false;
}

fn readTraceUntil(allocator: std.mem.Allocator, io: std.Io, needle: []const u8) !?[]u8 {
    var attempts: usize = 0;
    while (attempts < 50) : (attempts += 1) {
        const trace = try readFile(allocator, io, tracefs ++ "/trace");
        if (std.mem.indexOf(u8, trace, needle) != null) return trace;
        allocator.free(trace);
        try io.sleep(.fromMilliseconds(20), .awake);
    }
    return null;
}

fn writeFile(io: std.Io, path: []const u8, contents: []const u8) !void {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{ .mode = .write_only });
    defer file.close(io);
    var buffer: [64]u8 = undefined;
    var writer = file.writer(io, &buffer);
    try writer.interface.writeAll(contents);
    try writer.interface.flush();
}

/// Reads a tracefs file by streaming to EOF. `File.Reader` cannot be used here
/// because it sizes its read from `stat`, and tracefs reports 0 for files whose
/// contents are generated on demand.
fn readFile(allocator: std.mem.Allocator, io: std.Io, path: []const u8) ![]u8 {
    const file = try std.Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);

    var contents: std.ArrayList(u8) = .empty;
    errdefer contents.deinit(allocator);

    var chunk: [4096]u8 = undefined;
    while (contents.items.len < 1 << 20) {
        const n = file.readStreaming(io, &.{&chunk}) catch |err| switch (err) {
            error.EndOfStream => break,
            else => return err,
        };
        if (n == 0) break;
        try contents.appendSlice(allocator, chunk[0..n]);
    }
    return contents.toOwnedSlice(allocator);
}
