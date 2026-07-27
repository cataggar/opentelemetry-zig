//! OpenTelemetry log exporter for Linux `user_events`.
//!
//! `user_events` is the Linux counterpart to ETW on Windows: a process declares
//! tracepoints up front and the kernel only materializes events while a listener
//! (ftrace, `perf`, or a local agent) has them enabled. Emitting is therefore
//! nearly free when nothing is collecting.
//!
//! Records are encoded as EventHeader events using the Common Schema 4.0
//! `PartA` / `PartB` / `PartC` layout, matching the Rust
//! `opentelemetry-user-events-logs` exporter so the same collectors and decoders
//! work unchanged.
//!
//! The schema is declared at comptime. `UserEventsExporter` is a generic over
//! `Options`, which lists exactly which attributes are emitted and with which
//! types. That keeps one event name bound to one stable schema (what EventHeader
//! consumers expect), removes all per-record metadata construction, and lets the
//! encoder size its buffers exactly, so exporting never allocates.
//!
//! Requires Linux 6.4 or newer. Registration needs access to
//! `/sys/kernel/tracing/user_events_data`; when it is unavailable the exporter
//! stays inert instead of failing process startup.
//!
//! see: https://docs.kernel.org/trace/user_events.html

const std = @import("std");
const builtin = @import("builtin");

const ue = @import("user_events");
const abi = ue.abi;
const eh = ue.eventheader;

const logs = @import("../../../api/logs/logger_provider.zig");
const Attribute = @import("../../../attributes.zig").Attribute;
const AttributeValue = @import("../../../attributes.zig").AttributeValue;
const LogRecordExporter = @import("../log_record_exporter.zig").LogRecordExporter;
const EnabledParameters = @import("../../../api/logs/enabled_parameters.zig").EnabledParameters;

const log = std.log.scoped(.user_events_exporter);

/// Common Schema version emitted in `__csver__` (0x400).
const cs_version: u32 = 1024;

/// Resource attributes promoted into `PartA` rather than `PartC`.
const cloud_role_key = "service.name";
const cloud_role_instance_key = "service.instance.id";

const level_count = ue.event.level_count;

/// Registration schema shared by every EventHeader tracepoint.
const registration_schema = ue.event.registration_schema;

/// Type a declared attribute is emitted as. A record value of a different type
/// is emitted as this type's zero value, keeping the schema stable.
pub const AttributeType = enum {
    string,
    int,
    double,
    bool,

    fn encoding(self: AttributeType) eh.Encoding {
        return switch (self) {
            .string => .string_length16_char8,
            .int, .double => .value64,
            .bool => .value8,
        };
    }

    fn format(self: AttributeType) eh.Format {
        return switch (self) {
            .string => .default,
            .int => .signed_int,
            .double => .float,
            .bool => .boolean,
        };
    }
};

/// One attribute the exporter is allowed to emit.
pub const AttributeField = struct {
    /// OpenTelemetry attribute key to match on the log record or resource.
    key: []const u8,
    /// EventHeader field name. Defaults to `key`.
    name: ?[]const u8 = null,
    type: AttributeType = .string,

    fn fieldName(comptime self: AttributeField) []const u8 {
        return self.name orelse self.key;
    }
};

pub const Options = struct {
    /// Tracepoints are registered as `<provider_name>_L<level>K<keyword>`.
    provider_name: []const u8,

    /// EventHeader event name. One name should map to one schema, so change it
    /// alongside any change to the declared fields.
    event_name: []const u8 = "Log",

    /// Value of the `PartB._typeName` field.
    type_name: []const u8 = "Log",

    /// Keyword bits encoded in the tracepoint name; listeners filter on it.
    keyword: u64 = 1,

    /// Emit `PartA.ext_dt_traceId` and `PartA.ext_dt_spanId`.
    trace_context: bool = true,

    /// Emit `PartA.ext_cloud_role` and `PartA.ext_cloud_roleInstance` from the
    /// resource's `service.name` and `service.instance.id`.
    cloud_role: bool = true,

    /// Emit `PartB.body`.
    body: bool = true,

    /// Emit `PartB.severityText`.
    severity_text: bool = true,

    /// When set, the named integer attribute populates `PartB.eventId` and is
    /// excluded from `PartC`.
    event_id_attribute: ?[]const u8 = null,

    /// Log record attributes emitted in `PartC`. Attributes not declared here
    /// are dropped.
    attributes: []const AttributeField = &.{},

    /// Resource attributes emitted in `PartC`. Resolved once during `init`.
    resource_attributes: []const AttributeField = &.{},

    /// Severity used when a record carries none. 9 is OTel `INFO`.
    default_severity_number: u8 = 9,

    /// Overrides the tracefs `user_events_data` path. Intended for tests.
    data_file_path: ?[:0]const u8 = null,
};

/// Maps an OpenTelemetry severity number to an EventHeader level, which selects
/// the tracepoint the record is written to.
pub fn levelFromSeverity(severity_number: u8) eh.Level {
    return switch (severity_number) {
        // TRACE1-4 and DEBUG1-4. 0 is "unspecified" and is treated as verbose.
        0...8 => .verbose,
        9...12 => .informational,
        13...16 => .warning,
        17...20 => .err,
        // FATAL1-4, plus any out-of-range value.
        else => .critical_error,
    };
}

/// Builds a `user_events` log exporter for a comptime-declared schema.
///
/// The returned type is address-stable by contract: the kernel keeps pointers to
/// the enable words embedded in it, so `init` allocates it rather than returning
/// it by value.
pub fn UserEventsExporter(comptime options: Options) type {
    if (builtin.os.tag != .linux) {
        @compileError("UserEventsExporter requires Linux: user_events is a Linux kernel feature");
    }
    comptime validateOptions(options);

    // The Common Schema layout, expressed as a Zig type. Everything below
    // encodes values of this type, so the wire schema and the values the
    // exporter builds cannot drift apart.
    const Schema = CommonSchema(options);

    const Events = ue.LeveledEvent(.{
        .provider = options.provider_name,
        .name = options.event_name,
        .keyword = options.keyword,
    }, Schema);

    return struct {
        const Self = @This();

        /// The Common Schema layout as a Zig struct type.
        pub const Payload = Schema;

        /// The comptime EventHeader definition backing this exporter. Exposed
        /// for tests and for tooling that needs the schema bytes.
        pub const definition = Events.definition;

        /// Tracepoint registration strings, indexed by `level - 1`.
        pub const registrations = Events.name_args;

        allocator: std.mem.Allocator,
        arena: std.heap.ArenaAllocator,
        provider: ue.Provider,
        events: Events,
        cloud_role: []const u8,
        cloud_role_instance: []const u8,
        resource_values: [options.resource_attributes.len]Value,
        is_shutdown: bool,

        /// Creates the exporter and registers one tracepoint per level.
        ///
        /// `resource` supplies `PartA` cloud role fields and any declared
        /// resource attributes; its strings are copied. When tracefs is
        /// unavailable or the process lacks permission, this still succeeds and
        /// the exporter simply never emits, so a missing collector cannot take
        /// down an application.
        pub fn init(
            allocator: std.mem.Allocator,
            resource: ?[]const Attribute,
        ) std.mem.Allocator.Error!*Self {
            const self = try allocator.create(Self);
            errdefer allocator.destroy(self);

            self.* = .{
                .allocator = allocator,
                .arena = std.heap.ArenaAllocator.init(allocator),
                .provider = .{},
                .events = .{},
                .cloud_role = "",
                .cloud_role_instance = "",
                .resource_values = @splat(.{ .string = "" }),
                .is_shutdown = false,
            };
            errdefer self.arena.deinit();

            try self.resolveResource(resource);
            self.register();
            return self;
        }

        pub fn deinit(self: *Self) void {
            self.shutdownInternal();
            self.arena.deinit();
            self.allocator.destroy(self);
        }

        pub fn logRecordExporter(self: *Self) LogRecordExporter {
            return .{
                .ptr = self,
                .vtable = &.{
                    .exportLogsFn = exportLogsFn,
                    .shutdownFn = shutdownFn,
                    .enabledFn = enabledFn,
                },
            };
        }

        /// Reports the kernel's enablement state through `Logger.enabled`, so a
        /// caller can skip building a record no listener would collect without
        /// having to reach for the concrete exporter type.
        fn enabledFn(ctx: *anyopaque, params: EnabledParameters) bool {
            const self: *Self = @ptrCast(@alignCast(ctx));
            return self.isEnabled(params.severity orelse options.default_severity_number);
        }

        /// True when a listener has enabled the tracepoint this severity maps
        /// to. Callers can use it to skip building an expensive record.
        pub fn isEnabled(self: *const Self, severity_number: u8) bool {
            if (self.is_shutdown) return false;
            return self.events.isEnabled(levelFromSeverity(severity_number));
        }

        /// True when at least one tracepoint reached the kernel. Registration
        /// is best effort, so this reports whether the exporter can emit at
        /// all, independently of whether anything is currently listening.
        pub fn isRegistered(self: *const Self) bool {
            if (self.is_shutdown) return false;
            return self.events.isRegistered();
        }

        fn resolveResource(self: *Self, resource: ?[]const Attribute) std.mem.Allocator.Error!void {
            const arena = self.arena.allocator();

            inline for (options.resource_attributes, 0..) |declared, index| {
                self.resource_values[index] = Value.zeroOf(declared.type);
            }

            const attributes = resource orelse return;
            for (attributes) |attribute| {
                if (options.cloud_role) {
                    if (std.mem.eql(u8, attribute.key, cloud_role_key)) {
                        self.cloud_role = try dupeString(arena, attribute.value);
                        continue;
                    }
                    if (std.mem.eql(u8, attribute.key, cloud_role_instance_key)) {
                        self.cloud_role_instance = try dupeString(arena, attribute.value);
                        continue;
                    }
                }

                inline for (options.resource_attributes, 0..) |declared, index| {
                    if (std.mem.eql(u8, attribute.key, declared.key)) {
                        self.resource_values[index] = try Value.resolve(
                            arena,
                            declared.type,
                            attribute.value,
                        );
                    }
                }
            }
        }

        fn register(self: *Self) void {
            const path = options.data_file_path;
            const open_result = if (path) |p| self.provider.openPath(p) else self.provider.open();
            open_result catch |err| {
                switch (err) {
                    error.Unsupported => log.info(
                        "user_events unavailable (needs Linux 6.4+ with tracefs mounted); '{s}' events will not be emitted",
                        .{options.provider_name},
                    ),
                    error.PermissionDenied => log.info(
                        "no permission to open user_events_data; '{s}' events will not be emitted",
                        .{options.provider_name},
                    ),
                    else => log.warn(
                        "failed to open user_events_data for '{s}': {t}",
                        .{ options.provider_name, err },
                    ),
                }
                return;
            };

            // Registration is best effort: a level that failed simply stays
            // disabled. Only drop the descriptor if nothing registered at all.
            if (self.events.register(&self.provider) == 0) self.provider.close();
        }

        fn shutdownInternal(self: *Self) void {
            if (self.is_shutdown) return;
            self.is_shutdown = true;

            self.events.unregister(&self.provider);
            self.provider.close();
        }

        fn exportLogsFn(ctx: *anyopaque, log_records: []logs.ReadableLogRecord) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            if (self.is_shutdown) return;

            for (log_records) |record| {
                self.writeRecord(record) catch |err| switch (err) {
                    // The listener disappeared between the enablement check and
                    // the write. Nothing was lost that a collector was watching.
                    error.NoListener, error.NotRegistered => {},
                    else => log.warn("failed to write a '{s}' event: {t}", .{ options.provider_name, err }),
                };
            }
        }

        fn shutdownFn(ctx: *anyopaque) anyerror!void {
            const self: *Self = @ptrCast(@alignCast(ctx));
            self.shutdownInternal();
        }

        fn writeRecord(self: *const Self, record: logs.ReadableLogRecord) abi.WriteError!void {
            const level = levelFromSeverity(record.severity_number orelse options.default_severity_number);
            if (!self.events.isEnabled(level)) return;

            var strings: StringBuffers = .{};
            return self.events.write(level, self.buildPayload(record, &strings));
        }

        /// Scratch space for the values an event borrows.
        ///
        /// Formatted values must outlive the write because the encoder
        /// references them from iovecs instead of copying, so they live in one
        /// caller-owned struct rather than in a callee's frame.
        pub const StringBuffers = struct {
            time: [rfc3339_buffer_size]u8 = undefined,
            trace_id: [32]u8 = undefined,
            span_id: [16]u8 = undefined,
        };

        pub const EventBuffers = struct {
            strings: StringBuffers = .{},
            event: Events.Buffers = .{},
        };

        /// Encodes one record into `buffers` and returns the vectors to submit.
        ///
        /// `vectors[0]` is a placeholder that the tracepoint overwrites with its
        /// write index. Exposed so tests and tooling can inspect the exact bytes
        /// without a kernel.
        pub fn encodeEvent(
            self: *const Self,
            record: logs.ReadableLogRecord,
            level: eh.Level,
            buffers: *EventBuffers,
        ) []abi.Iovec {
            return Events.encode(
                level,
                self.buildPayload(record, &buffers.strings),
                &buffers.event,
            );
        }

        /// Projects a log record onto the fixed schema.
        ///
        /// Undeclared attributes are dropped and a declared attribute carrying
        /// the wrong type becomes that type's zero value, which is what keeps
        /// one event name bound to one layout.
        fn buildPayload(
            self: *const Self,
            record: logs.ReadableLogRecord,
            strings: *StringBuffers,
        ) Schema {
            var slots: [options.attributes.len]?AttributeValue = @splat(null);
            var event_id: i64 = 0;
            collectAttributes(record.attributes, &slots, &event_id);

            var payload: Schema = undefined;
            payload.@"__csver__" = cs_version;

            {
                var part: @FieldType(Schema, "PartA") = undefined;
                part.time = formatRfc3339(
                    record.timestamp orelse record.observed_timestamp,
                    &strings.time,
                );
                if (comptime options.trace_context) {
                    part.ext_dt_traceId = if (record.trace_id) |id|
                        formatHex(&id, &strings.trace_id)
                    else
                        "";
                    part.ext_dt_spanId = if (record.span_id) |id|
                        formatHex(&id, &strings.span_id)
                    else
                        "";
                }
                if (comptime options.cloud_role) {
                    part.ext_cloud_role = self.cloud_role;
                    part.ext_cloud_roleInstance = self.cloud_role_instance;
                }
                payload.PartA = part;
            }

            if (comptime has_part_c) {
                var part: @FieldType(Schema, "PartC") = undefined;
                inline for (options.attributes, 0..) |declared, index| {
                    @field(part, declared.fieldName()) =
                        Value.fromOptional(declared.type, slots[index]).unwrap(declared.type);
                }
                inline for (options.resource_attributes, 0..) |declared, index| {
                    @field(part, declared.fieldName()) =
                        self.resource_values[index].unwrap(declared.type);
                }
                payload.PartC = part;
            }

            {
                var part: @FieldType(Schema, "PartB") = undefined;
                part._typeName = options.type_name;
                if (comptime options.body) part.body = record.body orelse "";
                part.severityNumber = @intCast(@min(
                    record.severity_number orelse options.default_severity_number,
                    std.math.maxInt(i16),
                ));
                if (comptime options.severity_text) part.severityText = record.severity_text orelse "";
                if (comptime options.event_id_attribute != null) part.eventId = event_id;
                payload.PartB = part;
            }

            return payload;
        }

        const has_part_c = options.attributes.len + options.resource_attributes.len > 0;

        fn collectAttributes(
            attributes: []const Attribute,
            slots: *[options.attributes.len]?AttributeValue,
            event_id: *i64,
        ) void {
            for (attributes) |attribute| {
                if (options.event_id_attribute) |key| {
                    if (std.mem.eql(u8, attribute.key, key)) {
                        if (attribute.value == .int) event_id.* = attribute.value.int;
                        continue;
                    }
                }
                inline for (options.attributes, 0..) |declared, index| {
                    // First occurrence wins, matching attribute precedence
                    // elsewhere in the SDK.
                    if (slots[index] == null and std.mem.eql(u8, attribute.key, declared.key)) {
                        slots[index] = attribute.value;
                    }
                }
            }
        }
    };
}

/// Zig type a declared attribute is emitted as.
fn ZigType(comptime kind: AttributeType) type {
    return switch (kind) {
        .string => []const u8,
        .int => i64,
        .double => f64,
        .bool => bool,
    };
}

const FieldAttributes = std.builtin.Type.StructField.Attributes;

/// Builds the Common Schema layout as a Zig struct type.
///
/// Field order is `__csver__`, `PartA`, `PartC`, `PartB`, matching the Rust
/// exporter so existing decoders see the same layout.
fn CommonSchema(comptime options: Options) type {
    comptime {
        var names: [4][:0]const u8 = undefined;
        var types: [4]type = undefined;
        var count: usize = 0;

        names[count] = "__csver__";
        types[count] = u32;
        count += 1;

        names[count] = "PartA";
        types[count] = PartAType(options);
        count += 1;

        if (options.attributes.len + options.resource_attributes.len > 0) {
            names[count] = "PartC";
            types[count] = PartCType(options);
            count += 1;
        }

        names[count] = "PartB";
        types[count] = PartBType(options);
        count += 1;

        return buildStruct(names[0..count].*, types[0..count].*);
    }
}

fn PartAType(comptime options: Options) type {
    comptime {
        var names: [5][:0]const u8 = undefined;
        var count: usize = 0;

        names[count] = "time";
        count += 1;
        if (options.trace_context) {
            names[count] = "ext_dt_traceId";
            count += 1;
            names[count] = "ext_dt_spanId";
            count += 1;
        }
        if (options.cloud_role) {
            names[count] = "ext_cloud_role";
            count += 1;
            names[count] = "ext_cloud_roleInstance";
            count += 1;
        }

        return buildStruct(names[0..count].*, @as([count]type, @splat([]const u8)));
    }
}

fn PartBType(comptime options: Options) type {
    comptime {
        var names: [5][:0]const u8 = undefined;
        var types: [5]type = undefined;
        var count: usize = 0;

        names[count] = "_typeName";
        types[count] = []const u8;
        count += 1;

        if (options.body) {
            names[count] = "body";
            types[count] = []const u8;
            count += 1;
        }

        names[count] = "severityNumber";
        types[count] = i16;
        count += 1;

        if (options.severity_text) {
            names[count] = "severityText";
            types[count] = []const u8;
            count += 1;
        }
        if (options.event_id_attribute != null) {
            names[count] = "eventId";
            types[count] = i64;
            count += 1;
        }

        return buildStruct(names[0..count].*, types[0..count].*);
    }
}

fn PartCType(comptime options: Options) type {
    comptime {
        const total = options.attributes.len + options.resource_attributes.len;
        var names: [total][:0]const u8 = undefined;
        var types: [total]type = undefined;
        var count: usize = 0;

        for (options.attributes ++ options.resource_attributes) |declared| {
            names[count] = std.fmt.comptimePrint("{s}", .{declared.fieldName()});
            types[count] = ZigType(declared.type);
            count += 1;
        }

        return buildStruct(names, types);
    }
}

fn buildStruct(comptime names: anytype, comptime types: anytype) type {
    const attributes: [names.len]FieldAttributes = @splat(.{});
    return @Struct(.auto, null, &names, &types, &attributes);
}

/// A resolved attribute value, always matching its declared `AttributeType`.
const Value = union(enum) {
    string: []const u8,
    int: i64,
    double: f64,
    bool: bool,

    fn zeroOf(comptime kind: AttributeType) Value {
        return switch (kind) {
            .string => .{ .string = "" },
            .int => .{ .int = 0 },
            .double => .{ .double = 0 },
            .bool => .{ .bool = false },
        };
    }

    /// Values whose type does not match the declared type become the zero
    /// value, so the emitted schema never varies.
    fn fromOptional(comptime kind: AttributeType, value: ?AttributeValue) Value {
        const found = value orelse return zeroOf(kind);
        return switch (kind) {
            .string => if (found == .string) .{ .string = found.string } else zeroOf(kind),
            .int => if (found == .int) .{ .int = found.int } else zeroOf(kind),
            .double => if (found == .double) .{ .double = found.double } else zeroOf(kind),
            .bool => if (found == .bool) .{ .bool = found.bool } else zeroOf(kind),
        };
    }

    /// Narrows to the concrete Zig type the schema declares for `kind`.
    fn unwrap(self: Value, comptime kind: AttributeType) ZigType(kind) {
        return switch (kind) {
            .string => self.string,
            .int => self.int,
            .double => self.double,
            .bool => self.bool,
        };
    }

    fn resolve(
        allocator: std.mem.Allocator,
        comptime kind: AttributeType,
        value: AttributeValue,
    ) std.mem.Allocator.Error!Value {
        if (kind == .string) {
            if (value != .string) return zeroOf(kind);
            return .{ .string = try allocator.dupe(u8, value.string) };
        }
        return fromOptional(kind, value);
    }
};

fn dupeString(allocator: std.mem.Allocator, value: AttributeValue) std.mem.Allocator.Error![]const u8 {
    return switch (value) {
        .string => |text| allocator.dupe(u8, text),
        else => "",
    };
}

fn formatHex(bytes: []const u8, buffer: []u8) []const u8 {
    const alphabet = "0123456789abcdef";
    for (bytes, 0..) |byte, index| {
        buffer[index * 2] = alphabet[byte >> 4];
        buffer[index * 2 + 1] = alphabet[byte & 0x0f];
    }
    return buffer[0 .. bytes.len * 2];
}

/// Longest RFC 3339 rendering: `-YYYYY-MM-DDTHH:MM:SS.123456789Z`.
const rfc3339_buffer_size = 40;

/// Formats nanoseconds since the Unix epoch as RFC 3339 in UTC, using 0, 3, 6,
/// or 9 fractional digits depending on the precision actually present. This
/// matches the `chrono` `AutoSi` rendering used by the Rust exporter.
fn formatRfc3339(nanoseconds: u64, buffer: *[rfc3339_buffer_size]u8) []const u8 {
    const seconds = nanoseconds / std.time.ns_per_s;
    const fraction: u32 = @intCast(nanoseconds % std.time.ns_per_s);

    const epoch = std.time.epoch.EpochSeconds{ .secs = seconds };
    const year_day = epoch.getEpochDay().calculateYearDay();
    const month_day = year_day.calculateMonthDay();
    const day_seconds = epoch.getDaySeconds();

    const date = .{
        year_day.year,
        month_day.month.numeric(),
        @as(u16, month_day.day_index) + 1,
        day_seconds.getHoursIntoDay(),
        day_seconds.getMinutesIntoHour(),
        day_seconds.getSecondsIntoMinute(),
    };
    const format = "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}";

    const result = if (fraction == 0)
        std.fmt.bufPrint(buffer, format ++ "Z", date)
    else if (fraction % std.time.ns_per_ms == 0)
        std.fmt.bufPrint(buffer, format ++ ".{d:0>3}Z", date ++ .{fraction / std.time.ns_per_ms})
    else if (fraction % std.time.ns_per_us == 0)
        std.fmt.bufPrint(buffer, format ++ ".{d:0>6}Z", date ++ .{fraction / std.time.ns_per_us})
    else
        std.fmt.bufPrint(buffer, format ++ ".{d:0>9}Z", date ++ .{fraction});

    return result catch unreachable;
}

fn validateOptions(comptime options: Options) void {
    if (options.provider_name.len == 0) {
        @compileError("user_events provider_name must not be empty");
    }
    for (options.provider_name) |byte| {
        // The kernel parses the registration string by splitting on spaces, and
        // ':' / ';' are reserved by the tracepoint name grammar.
        if (byte <= ' ' or byte >= 0x7f or byte == ':' or byte == ';' or byte == '*') {
            @compileError("user_events provider_name must be printable ASCII without spaces, ':', ';', or '*'");
        }
    }

    if (options.attributes.len + options.resource_attributes.len > 127) {
        @compileError("PartC cannot hold more than 127 attributes");
    }
    if (options.default_severity_number == 0 or options.default_severity_number > 24) {
        @compileError("default_severity_number must be an OTel severity number in 1..24");
    }
}

/// A path that never exists, so tests exercise the "tracefs unavailable" path
/// and stay hermetic instead of touching the host's tracing subsystem.
const unavailable_data_file = "/nonexistent/opentelemetry-zig/user_events_data";

const TestExporter = UserEventsExporter(.{
    .provider_name = "otel_zig_test",
    .event_name = "TestLog",
    .attributes = &.{
        .{ .key = "user.id", .type = .int },
        .{ .key = "http.route", .type = .string },
        .{ .key = "cache.hit", .type = .bool },
        .{ .key = "duration.ms", .type = .double },
    },
    .resource_attributes = &.{
        .{ .key = "deployment.environment", .type = .string },
    },
    .event_id_attribute = "event_id",
    .data_file_path = unavailable_data_file,
});

/// Test-only EventHeader decoder.
///
/// Walking the metadata and the payload together is what proves the comptime
/// schema and the runtime encoder stay in sync: any drift shows up as a missing
/// field, a wrong value, or leftover bytes.
const TestDecoder = struct {
    arena: std.mem.Allocator,
    metadata: []const u8,
    payload: []const u8,
    metadata_position: usize = 0,
    payload_position: usize = 0,
    lines: std.ArrayListUnmanaged([]const u8) = .empty,

    fn decode(self: *TestDecoder) ![]const u8 {
        _ = self.readName(); // event name
        while (self.metadata_position < self.metadata.len) try self.decodeField("");

        if (self.payload_position != self.payload.len) return error.PayloadNotFullyConsumed;
        return std.mem.join(self.arena, "\n", self.lines.items);
    }

    fn decodeField(self: *TestDecoder, prefix: []const u8) !void {
        const name = self.readName();

        const encoding_byte = self.metadata[self.metadata_position];
        self.metadata_position += 1;
        const has_format = (encoding_byte & 0x80) != 0;
        const encoding: eh.Encoding = @enumFromInt(encoding_byte & 0x1f);

        var format_byte: u8 = 0;
        if (has_format) {
            format_byte = self.metadata[self.metadata_position];
            self.metadata_position += 1;
        }

        if (encoding == .structure) {
            const child_prefix = try std.fmt.allocPrint(self.arena, "{s}{s}.", .{ prefix, name });
            for (0..format_byte) |_| try self.decodeField(child_prefix);
            return;
        }

        const format: eh.Format = @enumFromInt(format_byte);
        const value = try self.readValue(encoding, format);
        try self.lines.append(self.arena, try std.fmt.allocPrint(
            self.arena,
            "{s}{s}={s}",
            .{ prefix, name, value },
        ));
    }

    fn readValue(self: *TestDecoder, encoding: eh.Encoding, format: eh.Format) ![]const u8 {
        return switch (encoding) {
            .structure => unreachable,
            .value8 => blk: {
                const raw = self.take(1)[0];
                break :blk if (format == .boolean)
                    if (raw != 0) "true" else "false"
                else
                    try std.fmt.allocPrint(self.arena, "{d}", .{raw});
            },
            .value16 => blk: {
                const raw = std.mem.readInt(u16, self.take(2)[0..2], .little);
                break :blk if (format == .signed_int)
                    try std.fmt.allocPrint(self.arena, "{d}", .{@as(i16, @bitCast(raw))})
                else
                    try std.fmt.allocPrint(self.arena, "{d}", .{raw});
            },
            .value32 => blk: {
                const raw = std.mem.readInt(u32, self.take(4)[0..4], .little);
                break :blk try std.fmt.allocPrint(self.arena, "{d}", .{raw});
            },
            .value64 => blk: {
                const raw = std.mem.readInt(u64, self.take(8)[0..8], .little);
                break :blk switch (format) {
                    .float => try std.fmt.allocPrint(self.arena, "{d}", .{@as(f64, @bitCast(raw))}),
                    else => try std.fmt.allocPrint(self.arena, "{d}", .{@as(i64, @bitCast(raw))}),
                };
            },
            .string_length16_char8 => blk: {
                const length = std.mem.readInt(u16, self.take(2)[0..2], .little);
                break :blk self.take(length);
            },
        };
    }

    fn readName(self: *TestDecoder) []const u8 {
        const start = self.metadata_position;
        while (self.metadata[self.metadata_position] != 0) self.metadata_position += 1;
        const name = self.metadata[start..self.metadata_position];
        self.metadata_position += 1;
        return name;
    }

    fn take(self: *TestDecoder, count: usize) []const u8 {
        const bytes = self.payload[self.payload_position..][0..count];
        self.payload_position += count;
        return bytes;
    }
};

/// Flattens the encoded vectors and decodes them back into `name=value` lines.
fn decodeEncodedEvent(arena: std.mem.Allocator, vectors: []abi.Iovec) ![]const u8 {
    var bytes: std.ArrayListUnmanaged(u8) = .empty;
    // Vector 0 is the write-index placeholder the kernel fills in.
    for (vectors[1..]) |vector| {
        try bytes.appendSlice(arena, vector.base[0..vector.len]);
    }
    const event = bytes.items;

    const metadata_length = std.mem.readInt(u16, event[eh.header_size..][0..2], .little);
    const metadata_start = eh.header_size + eh.extension_prefix_size;

    var decoder = TestDecoder{
        .arena = arena,
        .metadata = event[metadata_start..][0..metadata_length],
        .payload = event[metadata_start + metadata_length ..],
    };
    return decoder.decode();
}

test "severity numbers map onto EventHeader levels" {
    try std.testing.expectEqual(eh.Level.verbose, levelFromSeverity(0));
    try std.testing.expectEqual(eh.Level.verbose, levelFromSeverity(1)); // TRACE
    try std.testing.expectEqual(eh.Level.verbose, levelFromSeverity(5)); // DEBUG
    try std.testing.expectEqual(eh.Level.verbose, levelFromSeverity(8));
    try std.testing.expectEqual(eh.Level.informational, levelFromSeverity(9)); // INFO
    try std.testing.expectEqual(eh.Level.informational, levelFromSeverity(12));
    try std.testing.expectEqual(eh.Level.warning, levelFromSeverity(13)); // WARN
    try std.testing.expectEqual(eh.Level.warning, levelFromSeverity(16));
    try std.testing.expectEqual(eh.Level.err, levelFromSeverity(17)); // ERROR
    try std.testing.expectEqual(eh.Level.err, levelFromSeverity(20));
    try std.testing.expectEqual(eh.Level.critical_error, levelFromSeverity(21)); // FATAL
    try std.testing.expectEqual(eh.Level.critical_error, levelFromSeverity(24));
    try std.testing.expectEqual(eh.Level.critical_error, levelFromSeverity(255));
}

test "one tracepoint is registered per level" {
    const registrations = TestExporter.registrations;
    const schema = " " ++ registration_schema;

    try std.testing.expectEqualStrings("otel_zig_test_L1K1" ++ schema, registrations[0]);
    try std.testing.expectEqualStrings("otel_zig_test_L2K1" ++ schema, registrations[1]);
    try std.testing.expectEqualStrings("otel_zig_test_L3K1" ++ schema, registrations[2]);
    try std.testing.expectEqualStrings("otel_zig_test_L4K1" ++ schema, registrations[3]);
    try std.testing.expectEqualStrings("otel_zig_test_L5K1" ++ schema, registrations[4]);
}

test "keywords are encoded as hex in the tracepoint name" {
    const Exporter = UserEventsExporter(.{
        .provider_name = "myprovider",
        .keyword = 0x2a,
        .data_file_path = unavailable_data_file,
    });
    try std.testing.expectEqualStrings(
        "myprovider_L4K2a " ++ registration_schema,
        Exporter.registrations[3],
    );
}

test "an encoded event round-trips through its own metadata" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const resource = [_]Attribute{
        .{ .key = "service.name", .value = .{ .string = "checkout" } },
        .{ .key = "service.instance.id", .value = .{ .string = "pod-7" } },
        .{ .key = "deployment.environment", .value = .{ .string = "prod" } },
        .{ .key = "ignored.attribute", .value = .{ .string = "dropped" } },
    };

    const exporter = try TestExporter.init(std.testing.allocator, &resource);
    defer exporter.deinit();

    const attributes = [_]Attribute{
        .{ .key = "user.id", .value = .{ .int = 42 } },
        .{ .key = "http.route", .value = .{ .string = "/api/orders" } },
        .{ .key = "cache.hit", .value = .{ .bool = true } },
        .{ .key = "duration.ms", .value = .{ .double = 1.5 } },
        .{ .key = "event_id", .value = .{ .int = 7 } },
        .{ .key = "undeclared", .value = .{ .string = "dropped" } },
    };

    const record = logs.ReadableLogRecord{
        .timestamp = 1_704_112_496_789_000_000,
        .observed_timestamp = 0,
        .trace_id = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
        .span_id = .{ 1, 2, 3, 4, 5, 6, 7, 8 },
        .trace_flags = 1,
        .severity_number = 9,
        .severity_text = "INFO",
        .body = "order placed",
        .attributes = &attributes,
        .resource = &resource,
        .scope = .{ .name = "test" },
    };

    var buffers: TestExporter.EventBuffers = undefined;
    const vectors = exporter.encodeEvent(record, .informational, &buffers);

    try std.testing.expectEqualStrings(
        \\__csver__=1024
        \\PartA.time=2024-01-01T12:34:56.789Z
        \\PartA.ext_dt_traceId=000102030405060708090a0b0c0d0e0f
        \\PartA.ext_dt_spanId=0102030405060708
        \\PartA.ext_cloud_role=checkout
        \\PartA.ext_cloud_roleInstance=pod-7
        \\PartC.user.id=42
        \\PartC.http.route=/api/orders
        \\PartC.cache.hit=true
        \\PartC.duration.ms=1.5
        \\PartC.deployment.environment=prod
        \\PartB._typeName=Log
        \\PartB.body=order placed
        \\PartB.severityNumber=9
        \\PartB.severityText=INFO
        \\PartB.eventId=7
    , try decodeEncodedEvent(arena, vectors));
}

test "the encoded event starts with the header and metadata extension" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    const exporter = try TestExporter.init(std.testing.allocator, null);
    defer exporter.deinit();

    const record = logs.ReadableLogRecord{
        .timestamp = null,
        .observed_timestamp = 0,
        .trace_id = null,
        .span_id = null,
        .trace_flags = null,
        .severity_number = 17,
        .severity_text = null,
        .body = null,
        .attributes = &.{},
        .resource = null,
        .scope = .{ .name = "test" },
    };

    var buffers: TestExporter.EventBuffers = undefined;
    const vectors = exporter.encodeEvent(record, .err, &buffers);

    // Vector 0 is the write-index placeholder.
    try std.testing.expectEqual(@as(usize, 0), vectors[0].len);
    try std.testing.expectEqualSlices(u8, &eh.headerBytes(.err), vectors[1].base[0..vectors[1].len]);
    try std.testing.expectEqualSlices(
        u8,
        &TestExporter.definition.metadata_extension,
        vectors[2].base[0..vectors[2].len],
    );
}

test "absent values are emitted as their declared type's zero value" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const exporter = try TestExporter.init(std.testing.allocator, null);
    defer exporter.deinit();

    // `user.id` is declared as an int, so a string value is not emitted as-is.
    const attributes = [_]Attribute{
        .{ .key = "user.id", .value = .{ .string = "not-an-int" } },
    };

    const record = logs.ReadableLogRecord{
        .timestamp = null,
        .observed_timestamp = 0,
        .trace_id = null,
        .span_id = null,
        .trace_flags = null,
        .severity_number = null,
        .severity_text = null,
        .body = null,
        .attributes = &attributes,
        .resource = null,
        .scope = .{ .name = "test" },
    };

    var buffers: TestExporter.EventBuffers = undefined;
    const vectors = exporter.encodeEvent(record, .informational, &buffers);

    try std.testing.expectEqualStrings(
        \\__csver__=1024
        \\PartA.time=1970-01-01T00:00:00Z
        \\PartA.ext_dt_traceId=
        \\PartA.ext_dt_spanId=
        \\PartA.ext_cloud_role=
        \\PartA.ext_cloud_roleInstance=
        \\PartC.user.id=0
        \\PartC.http.route=
        \\PartC.cache.hit=false
        \\PartC.duration.ms=0
        \\PartC.deployment.environment=
        \\PartB._typeName=Log
        \\PartB.body=
        \\PartB.severityNumber=9
        \\PartB.severityText=
        \\PartB.eventId=0
    , try decodeEncodedEvent(arena, vectors));
}

test "optional parts are dropped from the schema when disabled" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const Minimal = UserEventsExporter(.{
        .provider_name = "minimal",
        .trace_context = false,
        .cloud_role = false,
        .body = false,
        .severity_text = false,
        .data_file_path = unavailable_data_file,
    });

    const exporter = try Minimal.init(std.testing.allocator, null);
    defer exporter.deinit();

    const record = logs.ReadableLogRecord{
        .timestamp = 1_000_000_000,
        .observed_timestamp = 0,
        .trace_id = .{0xaa} ** 16,
        .span_id = .{0xbb} ** 8,
        .trace_flags = null,
        .severity_number = 21,
        .severity_text = "FATAL",
        .body = "dropped",
        .attributes = &.{},
        .resource = null,
        .scope = .{ .name = "test" },
    };

    var buffers: Minimal.EventBuffers = undefined;
    const vectors = exporter.encodeEvent(record, .critical_error, &buffers);

    // No PartC struct is emitted when no attributes are declared.
    try std.testing.expectEqualStrings(
        \\__csver__=1024
        \\PartA.time=1970-01-01T00:00:01Z
        \\PartB._typeName=Log
        \\PartB.severityNumber=21
    , try decodeEncodedEvent(arena, vectors));
}

test "the exporter stays inert when user_events is unavailable" {
    const exporter = try TestExporter.init(std.testing.allocator, null);
    defer exporter.deinit();

    try std.testing.expect(!exporter.provider.isOpen());
    for (1..25) |severity| {
        try std.testing.expect(!exporter.isEnabled(@intCast(severity)));
    }

    // Exporting must remain a silent no-op rather than failing the batch.
    const record = logs.ReadableLogRecord{
        .timestamp = null,
        .observed_timestamp = 0,
        .trace_id = null,
        .span_id = null,
        .trace_flags = null,
        .severity_number = 9,
        .severity_text = null,
        .body = "ignored",
        .attributes = &.{},
        .resource = null,
        .scope = .{ .name = "test" },
    };
    var records = [_]logs.ReadableLogRecord{record};

    const interface = exporter.logRecordExporter();
    try interface.exportLogs(&records);
    try interface.shutdown();
    // Shutdown is idempotent.
    try interface.shutdown();
    try std.testing.expect(!exporter.isEnabled(9));
}

test "RFC 3339 timestamps use only the fractional digits that are present" {
    var buffer: [rfc3339_buffer_size]u8 = undefined;

    try std.testing.expectEqualStrings("1970-01-01T00:00:00Z", formatRfc3339(0, &buffer));
    try std.testing.expectEqualStrings(
        "2024-01-01T12:34:56Z",
        formatRfc3339(1_704_112_496_000_000_000, &buffer),
    );
    try std.testing.expectEqualStrings(
        "2024-01-01T12:34:56.789Z",
        formatRfc3339(1_704_112_496_789_000_000, &buffer),
    );
    try std.testing.expectEqualStrings(
        "2024-01-01T12:34:56.789123Z",
        formatRfc3339(1_704_112_496_789_123_000, &buffer),
    );
    try std.testing.expectEqualStrings(
        "2024-01-01T12:34:56.789123456Z",
        formatRfc3339(1_704_112_496_789_123_456, &buffer),
    );
}

test "oversized strings are truncated on a UTF-8 boundary" {
    try std.testing.expectEqualStrings("abc", ue.event.truncateUtf8("abc", 8));
    try std.testing.expectEqualStrings("abc", ue.event.truncateUtf8("abc", 3));
    try std.testing.expectEqualStrings("ab", ue.event.truncateUtf8("abc", 2));

    // "é" is two bytes, so a limit that would split it drops the whole sequence.
    try std.testing.expectEqualStrings("a", ue.event.truncateUtf8("aé", 2));
    try std.testing.expectEqualStrings("aé", ue.event.truncateUtf8("aé", 3));
    // "€" is three bytes.
    try std.testing.expectEqualStrings("", ue.event.truncateUtf8("€", 2));
}

test "a string longer than the payload budget is truncated rather than dropped" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const Simple = UserEventsExporter(.{
        .provider_name = "budget",
        .trace_context = false,
        .cloud_role = false,
        .severity_text = false,
        .data_file_path = unavailable_data_file,
    });
    const exporter = try Simple.init(std.testing.allocator, null);
    defer exporter.deinit();

    const body = try arena.alloc(u8, eh.max_event_size * 2);
    @memset(body, 'x');

    const record = logs.ReadableLogRecord{
        .timestamp = 0,
        .observed_timestamp = 0,
        .trace_id = null,
        .span_id = null,
        .trace_flags = null,
        .severity_number = 9,
        .severity_text = null,
        .body = body,
        .attributes = &.{},
        .resource = null,
        .scope = .{ .name = "test" },
    };

    var buffers: Simple.EventBuffers = undefined;
    const vectors = exporter.encodeEvent(record, .informational, &buffers);

    var total: usize = 0;
    for (vectors) |vector| total += vector.len;
    try std.testing.expect(total <= eh.max_event_size);

    const decoded = try decodeEncodedEvent(arena, vectors);
    try std.testing.expect(std.mem.indexOf(u8, decoded, "PartB.body=xxx") != null);
}

test "exporter reports disabled through the LogRecordExporter interface when unregistered" {
    const exporter = try TestExporter.init(std.testing.allocator, null);
    defer exporter.deinit();

    // Registration cannot succeed against a nonexistent data file, so nothing
    // is listening and Logger.enabled() must be able to see that.
    try std.testing.expect(!exporter.isRegistered());

    const interface = exporter.logRecordExporter();
    try std.testing.expect(!interface.enabled(.{
        .scope = .{ .name = "test" },
        .severity = 9,
        .context = @import("../../../api/context.zig").Context.init(),
    }));
}

test "exporter enablement falls back to the default severity" {
    const exporter = try TestExporter.init(std.testing.allocator, null);
    defer exporter.deinit();

    const interface = exporter.logRecordExporter();

    // A missing severity must not be read as "enabled"; it resolves to the
    // configured default and is answered from that level's tracepoint.
    try std.testing.expect(!interface.enabled(.{
        .scope = .{ .name = "test" },
        .context = @import("../../../api/context.zig").Context.init(),
    }));
}
