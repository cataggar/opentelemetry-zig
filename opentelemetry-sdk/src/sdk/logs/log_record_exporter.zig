const logs = @import("../../api/logs/logger_provider.zig");
const EnabledParameters = @import("../../api/logs/enabled_parameters.zig").EnabledParameters;

/// LogRecordExporter defines the interface that protocol-specific exporters must implement.
/// see: https://opentelemetry.io/docs/specs/otel/logs/sdk/#logrecordexporter
pub const LogRecordExporter = struct {
    ptr: *anyopaque,
    vtable: *const VTable,

    const Self = @This();

    /// VTable defines the methods that the LogRecordExporter's instance must implement.
    pub const VTable = struct {
        /// exportLogs is the method that exports a batch of log records.
        /// This is called synchronously by the processor.
        /// Exporters should complete quickly to avoid blocking emission.
        exportLogsFn: *const fn (
            ctx: *anyopaque,
            log_records: []logs.ReadableLogRecord,
        ) anyerror!void,

        /// shutdown shuts down the exporter.
        /// Should be called exactly once per exporter instance.
        shutdownFn: *const fn (ctx: *anyopaque) anyerror!void,

        /// enabled reports whether this exporter would do anything with a
        /// record matching `params`, letting `Logger.enabled` answer honestly
        /// so callers can skip building expensive records.
        ///
        /// Only exporters with a real enablement signal need this. The
        /// `user_events` exporter has one — the kernel writes an enablement
        /// word when a listener attaches — but most exporters accept
        /// everything, so this is optional and null means always enabled, in
        /// line with the spec's guidance to assume true when uncertain.
        ///
        /// MUST be safe to call concurrently.
        enabledFn: ?*const fn (ctx: *anyopaque, params: EnabledParameters) bool = null,
    };

    /// Export a batch of log records
    pub fn exportLogs(
        self: Self,
        log_records: []logs.ReadableLogRecord,
    ) anyerror!void {
        return self.vtable.exportLogsFn(self.ptr, log_records);
    }

    /// Shutdown the exporter
    pub fn shutdown(self: Self) anyerror!void {
        return self.vtable.shutdownFn(self.ptr);
    }

    /// Whether this exporter would process a matching record. True for
    /// exporters that do not report enablement.
    pub fn enabled(self: Self, params: EnabledParameters) bool {
        const enabledFn = self.vtable.enabledFn orelse return true;
        return enabledFn(self.ptr, params);
    }
};
