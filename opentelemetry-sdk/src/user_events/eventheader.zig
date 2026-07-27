//! Comptime EventHeader schema encoding.
//!
//! EventHeader is the self-describing envelope that `user_events` consumers
//! (`perf`, `decode-perf`, and local agents) expect on top of a raw tracepoint
//! payload. Every event carries an 8-byte header plus a metadata extension that
//! names and types each payload field, so a decoder can render the event
//! without out-of-band schema knowledge.
//!
//! This module deliberately supports only the subset needed by the Common
//! Schema log encoding: structs, fixed-width scalars, and length-prefixed UTF-8
//! strings. Arrays, zero-terminated strings, and UTF-16/32 are omitted.
//!
//! Schemas are validated and serialized entirely at comptime, so emitting an
//! event never builds metadata at runtime.
//!
//! see: https://github.com/microsoft/LinuxTracepoints/blob/main/libeventheader-tracepoint/include/eventheader/eventheader.h

const std = @import("std");
const builtin = @import("builtin");

pub const header_size = 8;
pub const extension_prefix_size = 4;

/// Maximum bytes the kernel accepts for a single user_events write.
pub const max_event_size = 65535;

/// Bytes reserved for the write index, header, and metadata prefix before the
/// payload budget is computed. Microsoft's implementations reserve 52 bytes plus
/// margin; matching them keeps events decodable by the same tooling.
pub const event_overhead = 52 + 16;

pub const HeaderFlags = struct {
    pub const pointer64: u8 = 0x01;
    pub const little_endian: u8 = 0x02;
    pub const extension: u8 = 0x04;
};

pub const ExtensionKind = struct {
    pub const metadata: u16 = 1;
    pub const activity: u16 = 2;
};

const format_present_flag: u8 = 0x80;

/// EventHeader levels, ordered by the integer values the kernel and decoders
/// use. Tracepoint names embed this value, so one tracepoint exists per level.
pub const Level = enum(u8) {
    critical_error = 1,
    err = 2,
    warning = 3,
    informational = 4,
    verbose = 5,

    pub fn toInt(self: Level) u8 {
        return @intFromEnum(self);
    }
};

/// Field encodings supported by this module.
pub const Encoding = enum(u8) {
    structure = 1,
    value8 = 2,
    value16 = 3,
    value32 = 4,
    value64 = 5,
    /// UTF-8 bytes preceded by a `u16` byte count.
    string_length16_char8 = 10,

    /// Payload bytes contributed by the field itself. Strings add their content
    /// on top of this length prefix; structs contribute nothing because their
    /// children are serialized inline.
    pub fn fixedPayloadBytes(self: Encoding) usize {
        return switch (self) {
            .structure => 0,
            .value8 => 1,
            .value16 => 2,
            .value32 => 4,
            .value64 => 8,
            .string_length16_char8 => 2,
        };
    }
};

/// Presentation hints applied on top of an encoding.
pub const Format = enum(u8) {
    default = 0,
    unsigned_int = 1,
    signed_int = 2,
    hex_int = 3,
    boolean = 7,
    float = 8,
    string_utf = 11,
    string_json = 14,
};

pub const Field = struct {
    name: []const u8,
    encoding: Encoding,
    format: Format = .default,
    /// Only valid when `encoding` is `.structure`.
    children: []const Field = &.{},
};

pub const Event = struct {
    name: []const u8,
    fields: []const Field = &.{},
};

/// Returns the 8 header bytes for `level`.
///
/// Only the level byte varies between the tracepoints of one provider, so this
/// is cheap enough to call per event rather than caching a table.
pub fn headerBytes(level: Level) [header_size]u8 {
    return .{
        target_flags,
        0, // version
        0, 0, // id
        0, 0, // tag
        0, // opcode
        level.toInt(),
    };
}

const target_flags: u8 = (if (@sizeOf(usize) == 8) HeaderFlags.pointer64 else 0) |
    (if (builtin.cpu.arch.endian() == .little) HeaderFlags.little_endian else 0) |
    HeaderFlags.extension;

/// Validates `event` and exposes its encoded metadata plus payload accounting.
pub fn Definition(comptime event: Event) type {
    @setEvalBranchQuota(100_000);
    validateEvent(event);

    const data_length = metadataDataLength(event);
    if (data_length > std.math.maxInt(u16)) {
        @compileError("EventHeader metadata exceeds 65535 bytes");
    }
    if (data_length + event_overhead >= max_event_size) {
        @compileError("EventHeader metadata leaves no room for a payload");
    }

    return struct {
        /// `u16` length, `u16` kind, then the metadata bytes.
        pub const metadata_extension: [extension_prefix_size + data_length]u8 =
            encodeMetadataExtension(event);

        /// Metadata bytes without the extension prefix. Useful for tests and
        /// for callers that assemble their own extension chain.
        pub const metadata_data: [data_length]u8 = encodeMetadataData(event);

        /// Payload bytes contributed by fixed-width fields and string length
        /// prefixes, i.e. the payload size when every string is empty.
        pub const fixed_payload_bytes: usize = fixedPayloadBytes(event.fields);

        /// Number of length-prefixed string fields in the schema.
        pub const string_field_count: usize = stringFieldCount(event.fields);

        /// Largest payload this event may carry while staying decodable.
        pub const max_payload_bytes: usize = max_event_size - event_overhead - data_length;

        /// Upper bound on the `writev` vectors one event needs: the write
        /// index, the header, the metadata extension, and, for each string, one
        /// vector for the accumulated scalar run plus one for its bytes.
        pub const max_iovecs: usize = 3 + 2 * string_field_count + 1;
    };
}

fn validateEvent(comptime event: Event) void {
    validateName("event", event.name);
    if (event.fields.len == 0) @compileError("EventHeader event must declare at least one field");
    for (event.fields) |field| validateField(field);
}

fn validateField(comptime field: Field) void {
    validateName("field", field.name);

    if (field.encoding == .structure) {
        if (field.children.len == 0 or field.children.len > 127) {
            @compileError("EventHeader struct '" ++ field.name ++ "' must have 1 to 127 children");
        }
        if (field.format != .default) {
            // The format byte of a struct carries its child count.
            @compileError("EventHeader struct '" ++ field.name ++ "' cannot declare a format");
        }
        for (field.children) |child| validateField(child);
        return;
    }

    if (field.children.len != 0) {
        @compileError("only EventHeader struct fields may have children");
    }
    if (!formatCompatible(field.encoding, field.format)) {
        @compileError("EventHeader field '" ++ field.name ++ "' format is incompatible with its encoding");
    }
}

fn validateName(comptime kind: []const u8, comptime name: []const u8) void {
    if (name.len == 0) @compileError("EventHeader " ++ kind ++ " name must not be empty");
    if (!std.unicode.utf8ValidateSlice(name)) {
        @compileError("EventHeader " ++ kind ++ " name must be valid UTF-8: '" ++ name ++ "'");
    }
    for (name) |byte| {
        // NUL terminates a name and ';' introduces a field attribute.
        if (byte == 0) @compileError("EventHeader " ++ kind ++ " name must not contain NUL");
        if (byte == ';') @compileError("EventHeader " ++ kind ++ " name must not contain ';': '" ++ name ++ "'");
    }
}

fn formatCompatible(comptime encoding: Encoding, comptime format: Format) bool {
    if (format == .default) return true;
    // The length-prefixed char8 encoding accepts every format.
    if (encoding == .string_length16_char8) return true;

    return switch (format) {
        .default => true,
        .unsigned_int, .signed_int, .hex_int => isValue(encoding),
        .boolean => encoding == .value8 or encoding == .value16 or encoding == .value32,
        .float => encoding == .value32 or encoding == .value64,
        .string_utf => encoding == .value16 or encoding == .value32,
        .string_json => false,
    };
}

fn isValue(comptime encoding: Encoding) bool {
    return switch (encoding) {
        .value8, .value16, .value32, .value64 => true,
        else => false,
    };
}

fn metadataDataLength(comptime event: Event) usize {
    var length = event.name.len + 1;
    for (event.fields) |field| length += fieldMetadataLength(field);
    return length;
}

fn fieldMetadataLength(comptime field: Field) usize {
    var length = field.name.len + 1 + 1;
    if (needsFormatByte(field)) length += 1;
    for (field.children) |child| length += fieldMetadataLength(child);
    return length;
}

fn needsFormatByte(comptime field: Field) bool {
    return field.encoding == .structure or field.format != .default;
}

fn encodeMetadataData(comptime event: Event) [metadataDataLength(event)]u8 {
    var result: [metadataDataLength(event)]u8 = undefined;
    var position: usize = 0;
    putName(result[0..], &position, event.name);
    for (event.fields) |field| putField(result[0..], &position, field);
    std.debug.assert(position == result.len);
    return result;
}

fn encodeMetadataExtension(comptime event: Event) [extension_prefix_size + metadataDataLength(event)]u8 {
    const data_length = metadataDataLength(event);
    var result: [extension_prefix_size + data_length]u8 = undefined;
    std.mem.writeInt(u16, result[0..2], @intCast(data_length), .little);
    std.mem.writeInt(u16, result[2..4], ExtensionKind.metadata, .little);
    @memcpy(result[extension_prefix_size..], &encodeMetadataData(event));
    return result;
}

fn putField(output: []u8, position: *usize, comptime field: Field) void {
    putName(output, position, field.name);

    var encoding = @intFromEnum(field.encoding);
    if (needsFormatByte(field)) encoding |= format_present_flag;
    output[position.*] = encoding;
    position.* += 1;

    if (needsFormatByte(field)) {
        // A struct reuses the format byte to declare how many of the following
        // fields are its children.
        output[position.*] = if (field.encoding == .structure)
            @intCast(field.children.len)
        else
            @intFromEnum(field.format);
        position.* += 1;
    }

    for (field.children) |child| putField(output, position, child);
}

fn putName(output: []u8, position: *usize, comptime name: []const u8) void {
    @memcpy(output[position.* .. position.* + name.len], name);
    position.* += name.len;
    output[position.* + 0] = 0;
    position.* += 1;
}

fn fixedPayloadBytes(comptime fields: []const Field) usize {
    var total: usize = 0;
    for (fields) |field| {
        total += field.encoding.fixedPayloadBytes();
        total += fixedPayloadBytes(field.children);
    }
    return total;
}

fn stringFieldCount(comptime fields: []const Field) usize {
    var total: usize = 0;
    for (fields) |field| {
        if (field.encoding == .string_length16_char8) total += 1;
        total += stringFieldCount(field.children);
    }
    return total;
}

const test_event = Event{
    .name = "Log",
    .fields = &.{
        .{ .name = "__csver__", .encoding = .value32, .format = .unsigned_int },
        .{
            .name = "PartA",
            .encoding = .structure,
            .children = &.{
                .{ .name = "time", .encoding = .string_length16_char8 },
            },
        },
    },
};

test "metadata encodes names, encodings, and struct child counts" {
    const Def = Definition(test_event);

    const expected_data = "Log\x00" ++
        "__csver__\x00" ++ "\x84\x01" ++
        "PartA\x00" ++ "\x81\x01" ++
        "time\x00" ++ "\x0a";

    try std.testing.expectEqualSlices(u8, expected_data, &Def.metadata_data);
    try std.testing.expectEqual(@as(usize, 30), Def.metadata_data.len);
}

test "metadata extension prefixes the data with its length and kind" {
    const Def = Definition(test_event);

    try std.testing.expectEqual(@as(u16, 30), std.mem.readInt(u16, Def.metadata_extension[0..2], .little));
    try std.testing.expectEqual(ExtensionKind.metadata, std.mem.readInt(u16, Def.metadata_extension[2..4], .little));
    try std.testing.expectEqualSlices(u8, &Def.metadata_data, Def.metadata_extension[4..]);
}

test "payload accounting counts scalars, length prefixes, and strings" {
    const Def = Definition(test_event);

    // 4 bytes for the u32 plus the 2-byte length prefix of `time`.
    try std.testing.expectEqual(@as(usize, 6), Def.fixed_payload_bytes);
    try std.testing.expectEqual(@as(usize, 1), Def.string_field_count);
    try std.testing.expectEqual(@as(usize, 6), Def.max_iovecs);
    try std.testing.expectEqual(max_event_size - event_overhead - 30, Def.max_payload_bytes);
}

test "header bytes carry the level and the target's flags" {
    const header = headerBytes(.warning);

    try std.testing.expectEqual(target_flags, header[0]);
    try std.testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0, 0, 0 }, header[1..7]);
    try std.testing.expectEqual(@as(u8, 3), header[7]);

    if (@sizeOf(usize) == 8 and builtin.cpu.arch.endian() == .little) {
        try std.testing.expectEqual(@as(u8, 0x07), target_flags);
    }
}

test "levels use the integer values embedded in tracepoint names" {
    try std.testing.expectEqual(@as(u8, 1), Level.critical_error.toInt());
    try std.testing.expectEqual(@as(u8, 2), Level.err.toInt());
    try std.testing.expectEqual(@as(u8, 3), Level.warning.toInt());
    try std.testing.expectEqual(@as(u8, 4), Level.informational.toInt());
    try std.testing.expectEqual(@as(u8, 5), Level.verbose.toInt());
}

test "nested structs are encoded depth-first" {
    const Def = Definition(.{
        .name = "N",
        .fields = &.{
            .{
                .name = "outer",
                .encoding = .structure,
                .children = &.{
                    .{
                        .name = "inner",
                        .encoding = .structure,
                        .children = &.{
                            .{ .name = "v", .encoding = .value64, .format = .signed_int },
                        },
                    },
                    .{ .name = "flag", .encoding = .value8, .format = .boolean },
                },
            },
        },
    });

    const expected = "N\x00" ++
        "outer\x00" ++ "\x81\x02" ++
        "inner\x00" ++ "\x81\x01" ++
        "v\x00" ++ "\x85\x02" ++
        "flag\x00" ++ "\x82\x07";

    try std.testing.expectEqualSlices(u8, expected, &Def.metadata_data);
    try std.testing.expectEqual(@as(usize, 9), Def.fixed_payload_bytes);
    try std.testing.expectEqual(@as(usize, 0), Def.string_field_count);
}

test "fields without a format omit the format byte" {
    const Def = Definition(.{
        .name = "E",
        .fields = &.{.{ .name = "raw", .encoding = .value64 }},
    });

    try std.testing.expectEqualSlices(u8, "E\x00" ++ "raw\x00" ++ "\x05", &Def.metadata_data);
}
