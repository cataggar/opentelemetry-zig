# Linux `user_events` log exporter

`sdk.logs.UserEventsExporter` writes log records to Linux
[`user_events`](https://docs.kernel.org/trace/user_events.html) tracepoints
using the [EventHeader](https://github.com/microsoft/LinuxTracepoints) encoding
and the Common Schema 4.0 field layout. It is the Zig counterpart of the Rust
[`opentelemetry-user-events-logs`](https://github.com/open-telemetry/opentelemetry-rust-contrib/tree/main/opentelemetry-user-events-logs)
crate, and the two produce byte-compatible events, so the same collectors
decode both.

`user_events` is a kernel facility, not a network protocol. The process writes
into a kernel ring buffer and an out-of-band agent — `perf`, ftrace, or a
collector — reads it. There is no exporter thread, no batching, no serialisation
to protobuf, and no socket. When nobody is listening, emitting a record costs a
single relaxed load of the enablement word.

Requires Linux 6.4 or newer with `CONFIG_USER_EVENTS=y` and a mounted tracefs.

The exporter is a thin adapter: it maps a log record onto the Common Schema
field layout and hands it to `user_events.LeveledEvent` from the standalone
[`user_events` module](./user-events.md), which owns the tracepoint registration
and the EventHeader encoding. If you want Linux tracepoints without
OpenTelemetry, depend on that module directly.

## Declaring the schema

The schema is comptime. `UserEventsExporter` is a generic whose argument names
the provider, the event, and every attribute that may appear on the wire:

```zig
const CheckoutLogs = sdk.logs.UserEventsExporter(.{
    .provider_name = "myapp_checkout",
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
```

An attribute a record carries but the schema does not declare is dropped. A
declared attribute whose runtime value has a different type is emitted as that
type's zero value. Both rules exist so the wire layout is a function of the
type alone.

That is what makes the exporter cheap. Because the field set cannot change, the
EventHeader metadata block is a compile-time constant, the payload size is known
before the first record, and the encoder needs no allocator and no dynamic field
table. It is also what decoders want: one event name maps to exactly one schema,
so a decoder never has to reconcile two shapes carrying the same name.

The cost is that a schema change is a recompile. If your attributes genuinely
vary per call site, declare a separate exporter per call site rather than
widening one schema to the union of everything.

## Wiring it up

```zig
const resource = [_]sdk.attributes.Attribute{
    .{ .key = "service.name", .value = .{ .string = "checkout" } },
    .{ .key = "service.instance.id", .value = .{ .string = "checkout-0" } },
    .{ .key = "deployment.environment", .value = .{ .string = "production" } },
};

const exporter = try CheckoutLogs.init(allocator, &resource);
defer exporter.deinit();

var processor = sdk.logs.SimpleLogRecordProcessor.init(io, exporter.logRecordExporter());

var provider = try sdk.logs.LoggerProvider.init(allocator, io, &resource);
defer provider.deinit();
try provider.addLogRecordProcessor(processor.asLogRecordProcessor());
```

Pair it with `SimpleLogRecordProcessor`, not `BatchingLogRecordProcessor`.
Batching exists to amortise network round trips; a `user_events` write is a
`writev` into a ring buffer, so batching only adds latency and a copy.

`init` returns a pointer rather than a value because the kernel stores the
address of the exporter's enablement word at registration time. Moving the
struct would leave the kernel writing into freed memory, so the exporter owns a
stable allocation and `deinit` unregisters before freeing it.

## Registration is best effort

`user_events_data` is typically root-only, and tracefs may not be mounted at
all. Neither condition fails `init`. The exporter logs at `info` and stays
inert, dropping every record until the process is restarted somewhere it can
register:

```
info(user_events_exporter): no permission to open user_events_data; 'myapp_checkout' events will not be emitted
```

An application should not refuse to start because a diagnostic channel is
unavailable. For the same reason, a listener that disappears between the
enablement check and the write is not reported as an error — nothing was lost
that anyone was watching.

## Levels and tracepoints

One provider registers five tracepoints, one per EventHeader level, because
listeners enable levels independently. The name encodes the level and keyword:

| Tracepoint | Level | Severity numbers |
| --- | --- | --- |
| `myapp_checkout_L1K1` | critical | 21-24 (FATAL) |
| `myapp_checkout_L2K1` | error | 17-20 (ERROR) |
| `myapp_checkout_L3K1` | warning | 13-16 (WARN) |
| `myapp_checkout_L4K1` | informational | 9-12 (INFO) |
| `myapp_checkout_L5K1` | verbose | 0-8 (TRACE, DEBUG) |

`CheckoutLogs.registrations` is the comptime array of registration strings, so
you can print exactly what the process will register without registering it.

`exporter.isEnabled(severity_number)` reports whether anything is collecting the
level a given severity maps to. The same answer is available through the API as
`logger.enabled(.{ .severity = 9, .context = ctx })`, which is usually the better
call because it does not tie the call site to a concrete exporter type and also
accounts for scope filtering and provider shutdown.

Emitting while disabled is already nearly free, so this check is only worth
making when building the attribute values themselves is expensive.

## Multiple event schemas

One exporter is one provider and one event name. To emit different attribute
sets, declare a separate exporter per call site rather than widening a single
schema to the union of everything:

```zig
const CheckoutLogs = sdk.logs.UserEventsExporter(.{
    .provider_name = "myapp_checkout",
    .event_name = "CheckoutLog",
    .attributes = &.{.{ .key = "user.id", .type = .int }},
});

const DbLogs = sdk.logs.UserEventsExporter(.{
    .provider_name = "myapp_db",
    .event_name = "DbLog",
    .attributes = &.{.{ .key = "db.statement", .type = .string }},
});
```

`LoggerProvider` hands every record to every registered processor, so attaching
both exporters directly would make each encode every record and drop the
attributes it did not declare. Wrap them in `ScopeFilterProcessor` to route by
instrumentation scope:

```zig
var checkout_simple = sdk.logs.SimpleLogRecordProcessor.init(io, checkout_exporter.logRecordExporter());
var checkout_filtered = sdk.logs.ScopeFilterProcessor.init(
    checkout_simple.asLogRecordProcessor(),
    .{ .names = &.{"checkout"} },
);
try provider.addLogRecordProcessor(checkout_filtered.asLogRecordProcessor());
```

Records emitted through `provider.getLogger(.{ .name = "checkout" })` then reach
only `CheckoutLogs`. `ScopeFilterProcessor` also matches on a name prefix or an
arbitrary predicate.

## Wire format

Fields are emitted in the order `__csver__`, PartA, PartC, PartB. PartC comes
before PartB because the Rust exporter emits it that way and decoders key off
the order.

| | Field | Encoding |
| --- | --- | --- |
| | `__csver__` | u32, always 1024 |
| PartA | `time` | RFC3339 UTC, 0/3/6/9 fractional digits |
| PartA | `ext_dt_traceId` | 32 lowercase hex chars, empty when unset |
| PartA | `ext_dt_spanId` | 16 lowercase hex chars, empty when unset |
| PartA | `ext_cloud_role` | resource `service.name` |
| PartA | `ext_cloud_roleInstance` | resource `service.instance.id` |
| PartC | declared attributes | as declared |
| PartC | declared resource attributes | as declared |
| PartB | `_typeName` | `"Log"` |
| PartB | `body` | string |
| PartB | `severityNumber` | i16 |
| PartB | `severityText` | string |
| PartB | `eventId` | i64, present only when `event_id_attribute` is set |

Each PartA/PartB group can be switched off individually through `Options`
(`.trace_context`, `.cloud_role`, `.body`, `.severity_text`), which shrinks both
the metadata block and the payload.

## Encoding

Encoding does not allocate and does not copy strings. Scalars accumulate into a
fixed-size scratch array sized by the comptime schema, strings are referenced in
place, and the whole event goes out as one `writev`. Both buffers live in a
caller-owned `EventBuffers` struct because the iovecs point into them and must
outlive the function that fills them.

The Common Schema layout above is synthesized at comptime into a plain Zig
struct type, and the encoding is then derived from that type by the
[`user_events` module](./user-events.md). The per-type encodings are documented
there; the mapping from `AttributeType` is `.string` → `[]const u8`, `.int` →
`i64`, `.double` → `f64`, `.bool` → `bool`.

A `user_events` event cannot exceed 64 KiB. Rather than drop an oversized
record, the encoder gives strings a shared budget and truncates on a UTF-8
boundary, so a long body degrades instead of vanishing.

`encodeEvent` is public. It produces the exact iovecs that would be written, so
tests and tooling can inspect the bytes without a kernel, which is how the unit
tests run unprivileged.

## Collecting events

As root:

```sh
echo 1 > /sys/kernel/tracing/events/user_events/myapp_checkout_L4K1/enable
cat /sys/kernel/tracing/trace_pipe
```

ftrace's text output only formats the eight declared header fields:

```
myapp-971609 [002] ..... 973149.187770: myapp_checkout_L4K1: eventheader_flags=(7) version=(0) id=0x0 (0) tag=0x0 (0) opcode=(0) level=(4)
```

The schema and the values live in the bytes after those fields, so a text dump
is only useful for confirming that events are arriving. To read the payload, use
a decoder that understands EventHeader — `perf-decode` from
[LinuxTracepoints](https://github.com/microsoft/LinuxTracepoints), or the
OpenTelemetry Collector's `user_events` receiver.

## Example

See [`examples/logs/user_events.zig`](../examples/logs/user_events.zig). It runs
unprivileged and reports that it could not register, which is the behaviour
worth seeing.

[`examples/tracepoints/user_events.zig`](../examples/tracepoints/user_events.zig)
is the same idea one layer down, using only the `user_events` module.
