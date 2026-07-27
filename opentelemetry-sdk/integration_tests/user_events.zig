//! End-to-end check of the Linux `user_events` log exporter against a real
//! kernel.
//!
//! The unit tests decode the bytes the exporter would write, but they never
//! reach the kernel, so they cannot catch a wrong ioctl number, a malformed
//! registration string, or an enablement bit the kernel refuses to set. This
//! test closes that gap: it registers, has the kernel enable its own
//! tracepoint through tracefs, writes a record, and reads the event back out
//! of the ftrace ring buffer.
//!
//! Registering needs write access to `/sys/kernel/tracing/user_events_data`,
//! which is normally root-only, so the test skips rather than fails when it
//! cannot get there. That keeps it runnable in the same unprivileged
//! `sdk-integration` pass as the Docker-backed tests.

const std = @import("std");
const builtin = @import("builtin");
const sdk = @import("opentelemetry-sdk");

const tracefs = "/sys/kernel/tracing";
const provider_name = "otel_zig_integration";

/// Level 4 is `informational`, which is where severity 9 lands.
const tracepoint_name = provider_name ++ "_L4K1";

const Exporter = sdk.logs.UserEventsExporter(.{
    .provider_name = provider_name,
    .event_name = "IntegrationLog",
    .attributes = &.{
        .{ .key = "user.id", .type = .int },
        .{ .key = "http.route", .type = .string },
        .{ .key = "cache.hit", .type = .bool },
        .{ .key = "duration.ms", .type = .double },
    },
    .resource_attributes = &.{
        .{ .key = "deployment.environment", .type = .string },
    },
});

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .linux) {
        std.debug.print("Skipping user_events test: not Linux\n", .{});
        return;
    }

    const allocator = init.gpa;
    const io = init.io;

    std.debug.print("Running user_events integration test...\n", .{});

    const resource = [_]sdk.attributes.Attribute{
        .{ .key = "service.name", .value = .{ .string = "integration-test" } },
        .{ .key = "service.instance.id", .value = .{ .string = "instance-0" } },
        .{ .key = "deployment.environment", .value = .{ .string = "test" } },
    };

    const exporter = try Exporter.init(allocator, &resource);
    defer exporter.deinit();

    if (!exporter.isRegistered()) {
        std.debug.print(
            "⊘ Skipped: could not register with {s}/user_events_data (needs Linux 6.4+ and root)\n\n",
            .{tracefs},
        );
        return;
    }

    // The kernel exposes a registered tracepoint under tracefs, so its absence
    // means registration reported success without taking effect.
    var enable_path_buf: [256]u8 = undefined;
    const enable_path = try std.fmt.bufPrint(
        &enable_path_buf,
        tracefs ++ "/events/user_events/{s}/enable",
        .{tracepoint_name},
    );

    std.Io.Dir.cwd().access(io, enable_path, .{}) catch {
        std.debug.print("✗ {s} was registered but does not appear under tracefs\n", .{tracepoint_name});
        return error.TracepointMissing;
    };

    try writeFile(io, enable_path, "1");
    defer writeFile(io, enable_path, "0") catch {};
    try writeFile(io, tracefs ++ "/tracing_on", "1");
    try writeFile(io, tracefs ++ "/trace", "");

    // Enablement propagates to the process asynchronously, so poll rather than
    // assume the write above has already landed in our enable word.
    if (!try waitForEnabled(io, exporter)) {
        std.debug.print("✗ tracepoint enabled in tracefs but the process never observed it\n", .{});
        return error.EnablementNotObserved;
    }

    var simple_processor = sdk.logs.SimpleLogRecordProcessor.init(io, exporter.logRecordExporter());
    var provider = try sdk.logs.LoggerProvider.init(allocator, io, &resource);
    defer provider.deinit();
    try provider.addLogRecordProcessor(simple_processor.asLogRecordProcessor());

    const logger = try provider.getLogger(.{ .name = "integration.user_events", .version = "1.0.0" });

    // The kernel's enablement word must be visible through the API, not just
    // through the concrete exporter type.
    if (!logger.enabled(.{ .severity = 9, .context = sdk.api.context.Context.init() })) {
        std.debug.print("✗ tracepoint is enabled but Logger.enabled() reports false\n", .{});
        return error.EnabledNotPlumbed;
    }
    if (logger.enabled(.{ .severity = 1, .context = sdk.api.context.Context.init() })) {
        std.debug.print("✗ Logger.enabled() reports true for a level nothing is collecting\n", .{});
        return error.EnabledTooPermissive;
    }

    const attributes = [_]sdk.attributes.Attribute{
        .{ .key = "user.id", .value = .{ .int = 12345 } },
        .{ .key = "http.route", .value = .{ .string = "/api/checkout" } },
        .{ .key = "cache.hit", .value = .{ .bool = true } },
        .{ .key = "duration.ms", .value = .{ .double = 1.5 } },
    };
    logger.emit(.info, "integration test record", .{
        .attributes = &attributes,
        .severity_text = "INFO",
    });
    try provider.shutdown();

    // The per-CPU ring buffers are drained into `trace` lazily, so a read that
    // immediately follows the write can legitimately come back empty.
    const trace = try readTraceUntil(allocator, io, tracepoint_name) orelse {
        std.debug.print("✗ no {s} event reached the ftrace ring buffer\n", .{tracepoint_name});
        return error.EventNotRecorded;
    };
    defer allocator.free(trace);

    // ftrace only formats the eight declared header fields; the level proves
    // the record was routed to the tracepoint its severity maps to.
    if (std.mem.indexOf(u8, trace, "level=(4)") == null) {
        std.debug.print("✗ event recorded but not at the informational level\n", .{});
        return error.WrongLevel;
    }

    std.debug.print("✓ user_events test passed\n\n", .{});
}

fn waitForEnabled(io: std.Io, exporter: anytype) !bool {
    var attempts: usize = 0;
    while (attempts < 100) : (attempts += 1) {
        if (exporter.isEnabled(9)) return true;
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
