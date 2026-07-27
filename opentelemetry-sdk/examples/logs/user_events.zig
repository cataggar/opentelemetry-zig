const std = @import("std");
const sdk = @import("opentelemetry-sdk");

/// The schema is declared at comptime: only these attributes are emitted, and
/// always with these types. One event name therefore maps to exactly one
/// EventHeader schema, which is what user_events decoders expect.
const CheckoutLogs = sdk.logs.UserEventsExporter(.{
    .provider_name = "otel_zig_example",
    .event_name = "CheckoutLog",
    .attributes = &.{
        .{ .key = "user.id", .type = .int },
        .{ .key = "http.route", .type = .string },
        .{ .key = "cache.hit", .type = .bool },
    },
    .resource_attributes = &.{
        .{ .key = "deployment.environment", .type = .string },
    },
});

pub fn main(init: std.process.Init) !void {
    const allocator = init.gpa;
    const io = init.io;

    std.debug.print("OpenTelemetry Linux user_events Logs Example\n", .{});
    std.debug.print("===========================================\n\n", .{});

    const resource = [_]sdk.attributes.Attribute{
        .{ .key = "service.name", .value = .{ .string = "checkout" } },
        .{ .key = "service.instance.id", .value = .{ .string = "checkout-0" } },
        .{ .key = "deployment.environment", .value = .{ .string = "production" } },
    };

    // Registration never fails the application: without Linux 6.4+, a mounted
    // tracefs, and permission to open user_events_data, the exporter simply
    // stays inert.
    const user_events_exporter = try CheckoutLogs.init(allocator, &resource);
    defer user_events_exporter.deinit();

    std.debug.print("Tracepoints registered by this provider:\n", .{});
    for (CheckoutLogs.registrations) |registration| {
        std.debug.print("  {s}\n", .{registration});
    }

    var simple_processor = sdk.logs.SimpleLogRecordProcessor.init(io, user_events_exporter.logRecordExporter());

    var provider = try sdk.logs.LoggerProvider.init(allocator, io, &resource);
    defer provider.deinit();
    try provider.addLogRecordProcessor(simple_processor.asLogRecordProcessor());

    const logger = try provider.getLogger(.{ .name = "example.user_events", .version = "1.0.0" });

    // Emitting is nearly free while nobody is collecting, so this check is only
    // needed to avoid building expensive attribute values.
    const info_enabled = user_events_exporter.isEnabled(9);
    std.debug.print("\nA listener has enabled the INFO tracepoint: {}\n", .{info_enabled});
    if (!info_enabled) {
        std.debug.print(
            \\
            \\Nothing is collecting these events. To see them, run as root:
            \\  echo 1 > /sys/kernel/tracing/events/user_events/otel_zig_example_L4K1/enable
            \\  cat /sys/kernel/tracing/trace_pipe
            \\
        , .{});
    }

    std.debug.print("\nEmitting log records...\n", .{});

    const attributes = [_]sdk.attributes.Attribute{
        .{ .key = "user.id", .value = .{ .int = 12345 } },
        .{ .key = "http.route", .value = .{ .string = "/api/checkout" } },
        .{ .key = "cache.hit", .value = .{ .bool = true } },
        // Not declared in the schema, so it is dropped rather than widening it.
        .{ .key = "internal.debug", .value = .{ .string = "ignored" } },
    };

    logger.emit(.info, "checkout started", .{ .attributes = &attributes, .severity_text = "INFO" });
    logger.emit(.warn, "inventory running low", .{ .severity_text = "WARN" });
    logger.emit(.err, "payment declined", .{ .severity_text = "ERROR" });

    try provider.shutdown();

    std.debug.print("Done!\n", .{});
}
