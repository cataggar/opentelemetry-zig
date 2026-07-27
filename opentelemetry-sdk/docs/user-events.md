# Linux `user_events` tracepoints

The `user_events` module writes
[EventHeader](https://github.com/microsoft/LinuxTracepoints) events to Linux
[`user_events`](https://docs.kernel.org/trace/user_events.html) tracepoints. It
is standalone: nothing in it depends on OpenTelemetry, so a project that wants
Linux tracepoints and nothing else can depend on it alone.

`user_events` is a kernel facility, not a network protocol. The process writes
into a kernel ring buffer and an out-of-band agent — `perf`, ftrace, or a
collector — reads it. There is no exporter thread, no batching, and no socket.
When nobody is listening, emitting an event costs a single relaxed load.

Requires Linux 6.4 or newer with `CONFIG_USER_EVENTS=y` and a mounted tracefs.

For OpenTelemetry log records, use
[`sdk.logs.UserEventsExporter`](./user-events-logs.md) instead; it is built on
this module.

## Depending on it

```zig
const otel = b.dependency("opentelemetry", .{ .target = target, .optimize = optimize });
exe.root_module.addImport("user_events", otel.module("user_events"));
```

If you already depend on the SDK, the same module is re-exported as
`sdk.user_events`.

## Declaring an event

An event is a `Config` paired with a struct type. The wire schema is derived
from the type, so the EventHeader metadata is a compile-time constant and
`write` is checked by the compiler:

```zig
const user_events = @import("user_events");

const Checkout = user_events.Event(.{
    .provider = "myapp",
    .name = "Checkout",
    .level = .informational,
    .keyword = 1,
}, struct {
    order_id: u64,
    route: []const u8,
    latency_ms: f64,
    cache_hit: bool,
});
```

A field that does not exist, is misspelled, or has the wrong type is a compile
error rather than a decoding surprise later. There is no runtime field table and
no dynamic builder, which is also what decoders want: one event name maps to
exactly one schema, so a decoder never has to reconcile two shapes carrying the
same name.

The cost is that a schema change is a recompile. If your fields genuinely vary
per call site, declare a separate event per call site rather than widening one
schema to the union of everything.

### Field types

| Zig type | encoding | format |
| --- | --- | --- |
| `bool` | `value8` | `boolean` |
| `u8` … `u64` | `value8` … `value64` | `unsigned_int` |
| `i8` … `i64` | `value8` … `value64` | `signed_int` |
| `f32`, `f64` | `value32`, `value64` | `float` |
| `[]const u8` | `string_length16_char8` | `default` |
| `Hex(T)` | width of `T` | `hex_int` |
| `enum` | width of the tag type | int format of the tag |
| `struct` | `structure` | child count |

`default` rather than `string_utf` for strings is deliberate: for a char8
encoding `default` already means UTF-8, and it is what the Rust
`opentelemetry-user-events-logs` crate emits, so the two stay wire-compatible.

Integers of an odd width round up to the containing slot and are sign-extended,
so an `i12` occupies a `value16`. Nested structs are serialized inline; the
`structure` encoding's format byte carries the child count, not a format.

Optional fields are a compile error. Every declared field is always emitted, so
there is no representation for "absent" — give the field an explicit empty or
zero value instead.

## Emitting

```zig
var provider: user_events.Provider = .{};
_ = provider.openBestEffort();
defer provider.close();

var checkout: Checkout = .{};
checkout.registerBestEffort(&provider);
defer checkout.unregister(&provider);

if (checkout.isEnabled()) {
    try checkout.write(.{
        .order_id = 42,
        .route = "/api/checkout",
        .latency_ms = 12.5,
        .cache_hit = true,
    });
}
```

`Provider` owns the single `user_events_data` descriptor that every registration
and write goes through. The kernel has no notion of a provider; the name in
`Config` is only a tracepoint prefix.

`write` already returns early when nothing is collecting, so the `isEnabled`
guard is only needed to skip building the values themselves. Reach for it when
that work is expensive — a formatted string, a lock, a syscall — and skip it
otherwise.

Writing never allocates. Scalars accumulate in a stack buffer sized at comptime
and string bytes reach the kernel by reference, so a `write` is one `writev`.
Strings longer than the remaining payload budget are truncated on a UTF-8
boundary rather than dropping the event.

### Address stability

The kernel keeps a pointer to each event's enable word for as long as it is
registered, so a registered event must not be copied or moved. Store it in a
global, or in a heap-allocated struct — not in a local that outlives its frame
by value.

## Registration is best effort

`user_events_data` is normally root-only and absent before Linux 6.4, so most
processes cannot open it. Tracing is an optional capability, and a missing
tracing device should not keep an application from starting.

`Provider.openBestEffort` and `Event.registerBestEffort` report through the log
and leave the event inert, so `write` becomes a no-op. Use `open` and `register`
instead when tracing is a hard requirement and you want the error.

## Levels and keywords

The level and keyword are part of the tracepoint *name*, not the payload:
`<provider>_L<level>K<keyword>`, both lowercase hex. That is what lets a listener
enable errors without also enabling verbose output — the filtering happens in the
kernel, before your process is ever asked to encode anything.

| `Level` | value | tracepoint suffix |
| --- | --- | --- |
| `critical_error` | 1 | `_L1K…` |
| `err` | 2 | `_L2K…` |
| `warning` | 3 | `_L3K…` |
| `informational` | 4 | `_L4K…` |
| `verbose` | 5 | `_L5K…` |

`Event.tracepoint_name` is the exact string, which is useful for the tracefs
paths below.

The event *name* is not part of the tracepoint name — it lives in the metadata.
Two schemas with the same provider, level, and keyword therefore share one
tracepoint, and a decoder tells them apart by the name in the EventHeader. Give
them different keywords when you want them enabled independently.

### One schema at several levels

`LeveledEvent` declares one schema and owns a tracepoint for every level, with
the level chosen per write:

```zig
const Log = user_events.LeveledEvent(.{
    .provider = "myapp",
    .name = "Log",
    .keyword = 2,
}, struct { body: []const u8 });

var log_event: Log = .{};
_ = log_event.register(&provider);
defer log_event.unregister(&provider);

try log_event.write(.warning, .{ .body = "disk almost full" });
```

`register` returns how many levels the kernel accepted, since a level that fails
simply stays disabled. The metadata is identical across levels — only the header's
level byte differs — so all five share one definition. This is what
`sdk.logs.UserEventsExporter` is built on.

## Collecting events

A registered tracepoint appears under tracefs once the process registers it:

```bash
ls /sys/kernel/tracing/events/user_events/
```

With ftrace:

```bash
echo 1 > /sys/kernel/tracing/events/user_events/myapp_L4K1/enable
cat  /sys/kernel/tracing/trace_pipe
```

ftrace only formats the eight declared header fields, so the payload shows as
raw bytes. To decode the fields, use a tool that understands EventHeader, such
as `perf` with the
[LinuxTracepoints](https://github.com/microsoft/LinuxTracepoints) decoder:

```bash
perf record -e user_events:myapp_L4K1 -a
perf script
```

## Example

[`examples/tracepoints/user_events.zig`](../examples/tracepoints/user_events.zig)
is a complete program that uses only this module. Run it with:

```bash
zig build sdk-examples -Dexamples-filter=user_events
```

[`integration_tests/user_events_tracepoint.zig`](../integration_tests/user_events_tracepoint.zig)
is the same thing against a real kernel: it registers, enables its own
tracepoint through tracefs, writes, and reads the event back out of the ring
buffer. It needs root:

```bash
zig build sdk-integration -- user_events_tracepoint
```
