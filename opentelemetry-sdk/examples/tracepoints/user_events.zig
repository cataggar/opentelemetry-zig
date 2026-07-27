//! Linux `user_events` tracepoints without OpenTelemetry.
//!
//! This example imports only the `user_events` module. It is the shortest
//! demonstration that the tracepoint layer stands on its own: a project that
//! wants Linux tracepoints and nothing else needs no OpenTelemetry SDK, no
//! exporter, and no collector.
//!
//! Nothing is collected unless a listener enables the tracepoint, which needs
//! root. See the bottom of this file for how to do that.

const std = @import("std");
const builtin = @import("builtin");
const user_events = @import("user_events");

/// The whole schema is this struct type. Field names, order, and wire encodings
/// are derived from it at comptime, so a typo or a wrong type is a compile
/// error rather than a decoding surprise.
const Checkout = user_events.Event(.{
    .provider = "otel_zig_example_tp",
    .name = "Checkout",
    .level = .informational,
    .keyword = 1,
}, struct {
    order_id: u64,
    route: []const u8,
    latency_ms: f64,
    cache_hit: bool,
    /// Rendered as hex by decoders; the wire bytes are an ordinary `u64`.
    session: user_events.Hex(u64),
    region: enum(u8) { east, west },
    /// Nested structs are serialized inline behind a child count.
    result: struct {
        code: u32,
        message: []const u8,
    },
});

/// One schema emitted at several severities. Each level is its own tracepoint,
/// so a listener can collect warnings without also collecting the rest. The
/// keyword differs from `Checkout` only to keep the two apart here; sharing one
/// is fine, since the event name lives in the metadata rather than the name.
const Log = user_events.LeveledEvent(.{
    .provider = "otel_zig_example_tp",
    .name = "Log",
    .keyword = 2,
}, struct {
    body: []const u8,
});

pub fn main(init: std.process.Init) !void {
    _ = init;

    if (builtin.os.tag != .linux) {
        std.debug.print("user_events is a Linux kernel feature; nothing to do here.\n", .{});
        return;
    }

    std.debug.print("Linux user_events Tracepoints Example\n", .{});
    std.debug.print("=====================================\n\n", .{});

    // `user_events_data` is normally root-only, so opening it is best effort:
    // when it is unavailable the events simply stay inert and every write below
    // becomes a no-op. Tracing should never keep a program from starting.
    var provider: user_events.Provider = .{};
    defer provider.close();

    if (provider.openBestEffort()) {
        std.debug.print("Opened user_events_data.\n", .{});
    } else {
        std.debug.print(
            "user_events_data is unavailable (needs Linux 6.4+ and root).\n" ++
                "Continuing anyway: every write below is a no-op.\n",
            .{},
        );
    }

    var checkout: Checkout = .{};
    checkout.registerBestEffort(&provider);
    defer checkout.unregister(&provider);

    // A level the kernel rejects simply stays disabled, so the count is
    // informational rather than a failure to handle.
    var log_event: Log = .{};
    const registered_levels = log_event.register(&provider);
    defer log_event.unregister(&provider);

    std.debug.print("\nTracepoints:\n", .{});
    std.debug.print("  {s}\n", .{Checkout.tracepoint_name});
    for (Log.tracepoint_names) |name| std.debug.print("  {s}\n", .{name});
    std.debug.print("{d} of {d} Log levels registered.\n", .{ registered_levels, user_events.event.level_count });

    // The write itself already returns early when nothing is collecting, so
    // this guard is only worth it when building the values is expensive.
    if (checkout.isEnabled()) {
        std.debug.print("\nA listener is collecting Checkout.\n", .{});
    } else {
        std.debug.print("\nNothing is collecting Checkout; writes cost one relaxed load.\n", .{});
    }

    for (0..3) |index| {
        try checkout.write(.{
            .order_id = 1000 + index,
            .route = "/api/checkout",
            .latency_ms = 12.5 + @as(f64, @floatFromInt(index)),
            .cache_hit = index % 2 == 0,
            .session = .{ .value = 0xdeadbeef },
            .region = if (index % 2 == 0) .east else .west,
            .result = .{ .code = 200, .message = "ok" },
        });
    }

    try log_event.write(.informational, .{ .body = "checkout batch complete" });
    try log_event.write(.warning, .{ .body = "one order took longer than expected" });

    std.debug.print(
        \\
        \\Wrote 3 Checkout events and 2 Log events.
        \\
        \\To collect them, enable a tracepoint as root while this runs:
        \\  echo 1 > /sys/kernel/tracing/events/user_events/otel_zig_example_tp_L4K1/enable
        \\  cat /sys/kernel/tracing/trace_pipe
        \\
        \\ftrace only formats the header fields. To decode the payload, use a
        \\tool that understands EventHeader:
        \\  perf record -e user_events:otel_zig_example_tp_L4K1 -a
        \\
    , .{});
}
