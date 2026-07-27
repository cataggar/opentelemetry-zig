//! Comptime-typed `user_events` tracepoints.
//!
//! An event is declared by pairing a `Config` with a Zig struct type. The wire
//! schema is derived from the struct's fields, so the EventHeader metadata is a
//! compile-time constant and `write` is checked by the compiler:
//!
//! ```zig
//! const Checkout = Event(.{ .provider = "myapp", .name = "Checkout" }, struct {
//!     order_id: u64,
//!     path: []const u8,
//!     ok: bool,
//! });
//!
//! var provider: Provider = .{};
//! provider.openBestEffort();
//! defer provider.close();
//!
//! var checkout: Checkout = .{};
//! checkout.registerBestEffort(&provider);
//! defer checkout.unregister(&provider);
//!
//! if (checkout.isEnabled()) {
//!     try checkout.write(.{ .order_id = 42, .path = "/api/checkout", .ok = true });
//! }
//! ```
//!
//! Writing never allocates: scalars accumulate into a stack scratch buffer
//! sized at comptime, and string bytes are handed to the kernel by reference.

const std = @import("std");
const builtin = @import("builtin");

const abi = @import("abi.zig");
const eh = @import("eventheader.zig");
const Provider = @import("provider.zig").Provider;

const log = std.log.scoped(.user_events);

/// Appended to every tracepoint registration. It describes the 8 header bytes
/// that precede the metadata extension, which is what tells the kernel this is
/// an EventHeader event rather than an ad-hoc payload.
pub const registration_schema =
    "u8 eventheader_flags; u8 version; u16 id; u16 tag; u8 opcode; u8 level";

/// Identity of an event. Everything here is comptime because it determines the
/// tracepoint name and the metadata bytes.
pub const Config = struct {
    /// Groups related events under a common tracepoint prefix. Printable ASCII
    /// without spaces, `:`, `;`, or `*`.
    provider: []const u8,
    /// Event name recorded in the EventHeader metadata.
    name: []const u8,
    /// Severity. Together with `keyword` it selects the tracepoint, so
    /// listeners can enable one level without enabling the rest.
    level: eh.Level = .informational,
    /// Category bitmask. Listeners filter on it; `0` is reserved by the
    /// EventHeader convention, so the default is bit 0.
    keyword: u64 = 1,
};

/// Marks an integer field to be rendered as hexadecimal by decoders. The wire
/// bytes are unchanged; only the format hint differs.
pub fn Hex(comptime T: type) type {
    if (@typeInfo(T) != .int) @compileError("user_events.Hex requires an integer type");
    return struct {
        pub const user_events_hex_value = true;
        value: T,
    };
}

/// Declares a tracepoint whose payload is described by the struct type `Fields`.
///
/// Field types map onto EventHeader encodings as follows:
///
/// | Zig type              | encoding                | format        |
/// |-----------------------|-------------------------|---------------|
/// | `bool`                | `value8`                | `boolean`     |
/// | `u8`..`u64`           | `value8`..`value64`     | `unsigned_int`|
/// | `i8`..`i64`           | `value8`..`value64`     | `signed_int`  |
/// | `f32`, `f64`          | `value32`, `value64`    | `float`       |
/// | `[]const u8`          | `string_length16_char8` | `default`     |
/// | `Hex(T)`              | width of `T`            | `hex_int`     |
/// | `enum`                | width of the tag type   | int format    |
/// | `struct`              | `structure`             | child count   |
///
/// The returned type owns its `abi.Tracepoint`, which the kernel holds a
/// pointer to. Store it somewhere stable (a global, or a field of a
/// heap-allocated struct) and do not copy or move it while registered.
pub fn Event(comptime config: Config, comptime Fields: type) type {
    if (builtin.os.tag != .linux) {
        @compileError("user_events.Event requires Linux: user_events is a Linux kernel feature");
    }

    comptime validateConfig(config);

    const schema = eh.Event{ .name = config.name, .fields = comptime deriveFields(Fields) };
    const Def = eh.Definition(schema);

    if (Def.fixed_payload_bytes > Def.max_payload_bytes) {
        @compileError("user_events event '" ++ config.name ++
            "' declares more fixed payload bytes than an event can carry");
    }

    return struct {
        const Self = @This();

        tracepoint: abi.Tracepoint = .{},

        /// The struct type describing this event's payload.
        pub const Payload = Fields;
        /// EventHeader metadata and payload accounting for this schema.
        pub const definition = Def;
        /// Tracepoint name as it appears under
        /// `/sys/kernel/tracing/events/user_events/`.
        pub const tracepoint_name: [:0]const u8 = tracepointName(config);
        /// Tracepoint name plus the field declaration passed to the kernel at
        /// registration.
        pub const name_args: [:0]const u8 = tracepoint_name ++ " " ++ registration_schema;

        /// Scratch space one `write` needs. Exposed so callers that encode
        /// without emitting can supply their own.
        pub const Buffers = struct {
            header: [eh.header_size]u8 = undefined,
            scratch: [Def.fixed_payload_bytes]u8 = undefined,
            vectors: [Def.max_iovecs]abi.Iovec = undefined,
        };

        /// Registers the tracepoint with the kernel. The event stays inert
        /// until a listener enables it.
        pub fn register(self: *Self, provider: *const Provider) abi.RegisterError!void {
            try self.tracepoint.register(&provider.data_file, name_args);
        }

        /// Registers, reporting failure through the log instead of the return
        /// value. Use this when tracing is optional and must never keep an
        /// application from starting.
        pub fn registerBestEffort(self: *Self, provider: *const Provider) void {
            self.register(provider) catch |err| {
                log.info(
                    "could not register tracepoint '{s}' ({t}); its events will not be emitted",
                    .{ tracepoint_name, err },
                );
            };
        }

        /// Unregisters the tracepoint. Safe to call when never registered.
        pub fn unregister(self: *Self, provider: *const Provider) void {
            self.tracepoint.unregister(&provider.data_file) catch |err| {
                log.warn("could not unregister tracepoint '{s}': {t}", .{ tracepoint_name, err });
            };
        }

        pub fn isRegistered(self: *const Self) bool {
            return self.tracepoint.isRegistered();
        }

        /// True when a listener is collecting this tracepoint. Reads one
        /// relaxed word, so it is cheap enough to guard every call site.
        pub fn isEnabled(self: *const Self) bool {
            return self.tracepoint.isEnabled();
        }

        /// Emits one event.
        ///
        /// Returns without touching the kernel when nothing is collecting, so
        /// callers only need `isEnabled` to skip building `values` itself.
        /// Strings longer than the remaining payload budget are truncated on a
        /// UTF-8 boundary rather than dropping the event.
        pub fn write(self: *const Self, values: Fields) abi.WriteError!void {
            if (!self.isEnabled()) return;

            var buffers: Buffers = .{};
            const vectors = encode(values, &buffers);
            self.tracepoint.writev(vectors) catch |err| switch (err) {
                // The listener vanished between the enable check and the write.
                error.NoListener, error.NotRegistered => return,
                else => return err,
            };
        }

        /// Encodes `values` into `buffers` and returns the vectors to submit.
        ///
        /// `vectors[0]` is reserved for the kernel's write index and is filled
        /// in by the write itself. Exposed so tests and tooling can inspect the
        /// exact bytes without a kernel.
        pub fn encode(values: Fields, buffers: *Buffers) []abi.Iovec {
            buffers.header = eh.headerBytes(config.level);

            var writer = Writer(Def){
                .scratch = &buffers.scratch,
                .vectors = &buffers.vectors,
                .string_budget = Def.max_payload_bytes - Def.fixed_payload_bytes,
            };

            writer.reserveWriteIndex();
            writer.putStatic(&buffers.header);
            writer.putStatic(&Def.metadata_extension);
            writer.putStruct(Fields, values);

            return writer.finish();
        }
    };
}

/// Encodes a payload into a scratch buffer and a vector list.
///
/// Scalars accumulate into `scratch` and are emitted as one vector per run;
/// string bytes are referenced in place. Because `scratch` is a fixed array
/// owned by the caller, vectors pointing into it stay valid as later fields are
/// appended.
pub fn Writer(comptime Def: type) type {
    return struct {
        const Self = @This();

        scratch: *[Def.fixed_payload_bytes]u8,
        scratch_len: usize = 0,
        run_start: usize = 0,
        vectors: *[Def.max_iovecs]abi.Iovec,
        vector_count: usize = 0,
        /// Bytes still available for string contents. Fixed-width fields and
        /// length prefixes are already reserved out of this budget.
        string_budget: usize,

        /// Reserves `vectors[0]`; `abi.Tracepoint.writev` fills it with the
        /// write index.
        pub fn reserveWriteIndex(self: *Self) void {
            self.vectors[self.vector_count] = .{ .base = "", .len = 0 };
            self.vector_count += 1;
        }

        /// Appends bytes that are already laid out, such as the header and the
        /// metadata extension.
        pub fn putStatic(self: *Self, bytes: []const u8) void {
            self.pushVector(bytes);
        }

        /// Appends every field of `T` in declaration order, which is the order
        /// the metadata declares them.
        pub fn putStruct(self: *Self, comptime T: type, value: T) void {
            inline for (@typeInfo(T).@"struct".fields) |field| {
                self.put(field.type, @field(value, field.name));
            }
        }

        pub fn put(self: *Self, comptime T: type, value: T) void {
            if (comptime isHex(T)) return self.putInt(@TypeOf(value.value), value.value);

            switch (@typeInfo(T)) {
                .bool => self.putScalar(u8, @intFromBool(value)),
                .int => self.putInt(T, value),
                .float => |info| switch (info.bits) {
                    32 => self.putScalar(u32, @bitCast(value)),
                    64 => self.putScalar(u64, @bitCast(value)),
                    else => comptime unreachable,
                },
                .@"enum" => |info| self.putInt(info.tag_type, @intFromEnum(value)),
                .@"struct" => self.putStruct(T, value),
                .pointer => self.putString(value),
                else => comptime unreachable,
            }
        }

        fn putInt(self: *Self, comptime T: type, value: T) void {
            // Values narrower than their wire slot are widened, preserving sign.
            const Wire = std.meta.Int(.unsigned, @as(u16, valueBytes(T)) * 8);
            const Same = std.meta.Int(@typeInfo(T).int.signedness, @as(u16, valueBytes(T)) * 8);
            self.putScalar(Wire, @bitCast(@as(Same, value)));
        }

        /// `T` is the unsigned integer of the field's wire width; signed and
        /// floating point values are bit-cast by the caller.
        pub fn putScalar(self: *Self, comptime T: type, value: T) void {
            const size = @sizeOf(T);
            std.mem.writeInt(T, self.scratch[self.scratch_len..][0..size], value, .little);
            self.scratch_len += size;
        }

        pub fn putString(self: *Self, value: []const u8) void {
            const limit = @min(self.string_budget, std.math.maxInt(u16));
            const bytes = truncateUtf8(value, limit);
            self.string_budget -= bytes.len;

            self.putScalar(u16, @intCast(bytes.len));
            if (bytes.len == 0) return;

            self.flushRun();
            self.pushVector(bytes);
        }

        fn flushRun(self: *Self) void {
            if (self.scratch_len == self.run_start) return;
            self.pushVector(self.scratch[self.run_start..self.scratch_len]);
            self.run_start = self.scratch_len;
        }

        fn pushVector(self: *Self, bytes: []const u8) void {
            self.vectors[self.vector_count] = .{ .base = bytes.ptr, .len = bytes.len };
            self.vector_count += 1;
        }

        pub fn finish(self: *Self) []abi.Iovec {
            self.flushRun();
            return self.vectors[0..self.vector_count];
        }
    };
}

/// Truncates on a UTF-8 boundary so a decoder never sees a split code point.
pub fn truncateUtf8(value: []const u8, limit: usize) []const u8 {
    if (value.len <= limit) return value;

    var end = limit;
    // Continuation bytes are 0b10xxxxxx; walk back to the leading byte.
    while (end > 0 and value[end] & 0xc0 == 0x80) end -= 1;
    return value[0..end];
}

// -- Schema derivation ------------------------------------------------------

/// Translates a struct type into the EventHeader fields describing it.
fn deriveFields(comptime T: type) []const eh.Field {
    comptime {
        const info = switch (@typeInfo(T)) {
            .@"struct" => |s| s,
            else => @compileError("user_events payload must be a struct type, found " ++ @typeName(T)),
        };
        if (info.is_tuple) @compileError("user_events payload must be a named struct, not a tuple");
        if (info.fields.len == 0) @compileError("user_events payload must declare at least one field");

        var fields: [info.fields.len]eh.Field = undefined;
        for (info.fields, 0..) |field, index| fields[index] = deriveField(field.name, field.type);

        const result = fields;
        return &result;
    }
}

fn deriveField(comptime name: []const u8, comptime T: type) eh.Field {
    comptime {
        if (isHex(T)) {
            const Int = @FieldType(T, "value");
            return .{ .name = name, .encoding = valueEncoding(Int), .format = .hex_int };
        }

        return switch (@typeInfo(T)) {
            .bool => .{ .name = name, .encoding = .value8, .format = .boolean },
            .int => .{ .name = name, .encoding = valueEncoding(T), .format = intFormat(T) },
            .float => |info| switch (info.bits) {
                32 => .{ .name = name, .encoding = .value32, .format = .float },
                64 => .{ .name = name, .encoding = .value64, .format = .float },
                else => @compileError("user_events field '" ++ name ++
                    "' must be f32 or f64, found " ++ @typeName(T)),
            },
            .@"enum" => |info| .{
                .name = name,
                .encoding = valueEncoding(info.tag_type),
                .format = intFormat(info.tag_type),
            },
            .@"struct" => .{ .name = name, .encoding = .structure, .children = deriveFields(T) },
            .pointer => |info| blk: {
                if (info.size != .slice or info.child != u8 or !info.is_const) {
                    @compileError("user_events field '" ++ name ++
                        "' must be []const u8 to be encoded as a string, found " ++ @typeName(T));
                }
                // Matches how the Rust exporter emits strings: for a char8
                // encoding, `default` already means UTF-8.
                break :blk .{ .name = name, .encoding = .string_length16_char8, .format = .default };
            },
            .optional => @compileError("user_events field '" ++ name ++
                "' cannot be optional: every declared field is always emitted, " ++
                "so give it an explicit empty or zero value instead"),
            else => @compileError("user_events field '" ++ name ++
                "' has an unsupported type: " ++ @typeName(T)),
        };
    }
}

fn isHex(comptime T: type) bool {
    return @typeInfo(T) == .@"struct" and @hasDecl(T, "user_events_hex_value");
}

/// Rounds an integer up to the next EventHeader value width.
fn valueBytes(comptime T: type) u8 {
    const bits = @typeInfo(T).int.bits;
    return switch (bits) {
        0...8 => 1,
        9...16 => 2,
        17...32 => 4,
        33...64 => 8,
        else => @compileError("user_events integers may be at most 64 bits, found " ++ @typeName(T)),
    };
}

fn valueEncoding(comptime T: type) eh.Encoding {
    return switch (valueBytes(T)) {
        1 => .value8,
        2 => .value16,
        4 => .value32,
        8 => .value64,
        else => comptime unreachable,
    };
}

fn intFormat(comptime T: type) eh.Format {
    return switch (@typeInfo(T).int.signedness) {
        .signed => .signed_int,
        .unsigned => .unsigned_int,
    };
}

// -- Naming -----------------------------------------------------------------

fn validateConfig(comptime config: Config) void {
    comptime {
        if (config.provider.len == 0) @compileError("user_events provider must not be empty");
        for (config.provider) |byte| {
            if (byte <= ' ' or byte > '~' or byte == ':' or byte == ';' or byte == '*') {
                @compileError("user_events provider must be printable ASCII without spaces, " ++
                    "':', ';', or '*': '" ++ config.provider ++ "'");
            }
        }

        const name = tracepointName(config);
        if (name.len > abi.max_name_len) {
            @compileError("user_events tracepoint name exceeds the kernel limit: '" ++ name ++ "'");
        }
        if (name.len + 1 + registration_schema.len > abi.max_name_args_len) {
            @compileError("user_events registration string exceeds the kernel limit: '" ++ name ++ "'");
        }
    }
}

/// Builds the `<provider>_L<level>K<keyword>` name the kernel knows the
/// tracepoint by. Levels and keywords are lowercase hex without padding, which
/// is the convention EventHeader decoders expect.
pub fn tracepointName(comptime config: Config) [:0]const u8 {
    comptime {
        return std.fmt.comptimePrint("{s}_L{x}K{x}", .{
            config.provider,
            config.level.toInt(),
            config.keyword,
        });
    }
}

test {
    _ = @import("provider.zig");
}

const testing = std.testing;

fn expectSchema(comptime T: type, comptime expected: []const eh.Field) !void {
    const actual = comptime deriveFields(T);
    try testing.expectEqual(expected.len, actual.len);
    inline for (expected, actual) |want, got| {
        try testing.expectEqualStrings(want.name, got.name);
        try testing.expectEqual(want.encoding, got.encoding);
        try testing.expectEqual(want.format, got.format);
        try testing.expectEqual(want.children.len, got.children.len);
    }
}

test "scalar field types map onto EventHeader encodings" {
    try expectSchema(struct {
        flag: bool,
        small: u8,
        medium: u16,
        wide: u32,
        widest: u64,
        signed: i16,
        ratio: f64,
        single: f32,
        text: []const u8,
    }, &.{
        .{ .name = "flag", .encoding = .value8, .format = .boolean },
        .{ .name = "small", .encoding = .value8, .format = .unsigned_int },
        .{ .name = "medium", .encoding = .value16, .format = .unsigned_int },
        .{ .name = "wide", .encoding = .value32, .format = .unsigned_int },
        .{ .name = "widest", .encoding = .value64, .format = .unsigned_int },
        .{ .name = "signed", .encoding = .value16, .format = .signed_int },
        .{ .name = "ratio", .encoding = .value64, .format = .float },
        .{ .name = "single", .encoding = .value32, .format = .float },
        .{ .name = "text", .encoding = .string_length16_char8, .format = .default },
    });
}

test "narrow integers widen to the next value slot" {
    try expectSchema(struct { bits: u3, nibble: i12, big: u48 }, &.{
        .{ .name = "bits", .encoding = .value8, .format = .unsigned_int },
        .{ .name = "nibble", .encoding = .value16, .format = .signed_int },
        .{ .name = "big", .encoding = .value64, .format = .unsigned_int },
    });
}

test "enums encode as their tag type and Hex only changes the format" {
    const Color = enum(u16) { red, green };
    try expectSchema(struct { color: Color, addr: Hex(u64) }, &.{
        .{ .name = "color", .encoding = .value16, .format = .unsigned_int },
        .{ .name = "addr", .encoding = .value64, .format = .hex_int },
    });
}

test "nested structs become EventHeader structures" {
    const Inner = struct { a: u8, b: []const u8 };
    try expectSchema(struct { part: Inner, tail: u8 }, &.{
        .{ .name = "part", .encoding = .structure, .format = .default, .children = &.{
            .{ .name = "a", .encoding = .value8 },
            .{ .name = "b", .encoding = .string_length16_char8 },
        } },
        .{ .name = "tail", .encoding = .value8, .format = .unsigned_int },
    });
}

test "tracepoint names embed the level and keyword as hex" {
    const Warn = Event(.{
        .provider = "myapp",
        .name = "Warn",
        .level = .warning,
        .keyword = 0x2a,
    }, struct { a: u8 });

    try testing.expectEqualStrings("myapp_L3K2a", Warn.tracepoint_name);
    try testing.expectEqualStrings(
        "myapp_L3K2a " ++ registration_schema,
        Warn.name_args,
    );
}

test "metadata is a comptime constant derived from the struct type" {
    const Checkout = Event(.{ .provider = "myapp", .name = "Checkout" }, struct {
        order_id: u64,
        path: []const u8,
        ok: bool,
    });

    // Event name and each field name are NUL terminated; a field's encoding
    // byte carries 0x80 when a format byte follows it.
    try testing.expectEqualSlices(u8, &.{
        'C', 'h', 'e', 'c', 'k', 'o', 'u', 't', 0,
        'o', 'r', 'd', 'e', 'r', '_', 'i', 'd', 0, 0x85, 1,
        'p', 'a', 't', 'h',                        0, 10,
        'o', 'k',                                  0, 0x82, 7,
    }, &Checkout.definition.metadata_data);

    try testing.expectEqual(@as(usize, 8 + 2 + 1), Checkout.definition.fixed_payload_bytes);
    try testing.expectEqual(@as(usize, 1), Checkout.definition.string_field_count);
}

test "encoding lays out scalars and strings in declaration order" {
    const Checkout = Event(.{ .provider = "myapp", .name = "Checkout" }, struct {
        order_id: u64,
        path: []const u8,
        ok: bool,
    });

    var buffers: Checkout.Buffers = .{};
    const vectors = Checkout.encode(
        .{ .order_id = 0x1122334455667788, .path = "/api", .ok = true },
        &buffers,
    );

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(testing.allocator);
    // Skip the reserved write index, the header, and the metadata extension.
    for (vectors[3..]) |vector| {
        try payload.appendSlice(testing.allocator, vector.base[0..vector.len]);
    }

    try testing.expectEqualSlices(u8, &.{
        0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, // order_id, little endian
        4,    0, // path length
        '/',  'a', 'p', 'i',
        1, // ok
    }, payload.items);

    try testing.expectEqual(eh.headerBytes(.informational), buffers.header);
}

test "narrow integers are sign extended into their wire slot" {
    const Narrow = Event(.{ .provider = "myapp", .name = "Narrow" }, struct {
        negative: i12,
        positive: u3,
    });

    var buffers: Narrow.Buffers = .{};
    const vectors = Narrow.encode(.{ .negative = -2, .positive = 5 }, &buffers);

    try testing.expectEqual(@as(usize, 4), vectors.len);
    const payload = vectors[3].base[0..vectors[3].len];
    try testing.expectEqualSlices(u8, &.{ 0xfe, 0xff, 5 }, payload);
}

test "nested structs are serialized inline with no framing of their own" {
    const Nested = Event(.{ .provider = "myapp", .name = "Nested" }, struct {
        part: struct { a: u16, b: []const u8 },
        tail: u8,
    });

    var buffers: Nested.Buffers = .{};
    const vectors = Nested.encode(.{ .part = .{ .a = 0x0201, .b = "hi" }, .tail = 9 }, &buffers);

    var payload: std.ArrayList(u8) = .empty;
    defer payload.deinit(testing.allocator);
    for (vectors[3..]) |vector| {
        try payload.appendSlice(testing.allocator, vector.base[0..vector.len]);
    }

    try testing.expectEqualSlices(u8, &.{ 0x01, 0x02, 2, 0, 'h', 'i', 9 }, payload.items);
}

test "strings truncate on a UTF-8 boundary rather than dropping the event" {
    // Two bytes of budget, but the second code point needs three.
    try testing.expectEqualStrings("a", truncateUtf8("a€", 2));
    try testing.expectEqualStrings("a€", truncateUtf8("a€", 4));
    try testing.expectEqualStrings("", truncateUtf8("€", 2));
}

test "an unregistered event neither writes nor reports itself enabled" {
    const Quiet = Event(.{ .provider = "myapp", .name = "Quiet" }, struct { a: u8 });

    var quiet: Quiet = .{};
    try testing.expect(!quiet.isRegistered());
    try testing.expect(!quiet.isEnabled());
    // No listener, so this is a no-op rather than a failure.
    try quiet.write(.{ .a = 1 });
}
