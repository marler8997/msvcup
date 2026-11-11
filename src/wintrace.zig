//! A copy of wintrace (https://github.com/marler8997/wintrace, commit eab22c0) for zig 0.14,
//! which wintrace itself doesn't support: only its small mode, without its tests. Replace this
//! file with the wintrace dependency when msvcup moves to a zig version it supports.
//!
//! Stack traces for Windows that need no debug info at run time.
//!
//! Frames are walked with the unwinder Windows uses for exceptions (RtlVirtualUnwind over each
//! module's .pdata) and written as `module+0xoffset`, which stays valid under ASLR. After the
//! frames, each module in the trace is listed with the identity of its PDB, so the trace can be
//! symbolized later, on another machine, with `wintrace-symbolize` and the matching PDB:
//!
//!     wintrace
//!     demo.exe+0x10c5 (ip)
//!     demo.exe+0x225f (x95)
//!     ... 160 frames
//!     demo.exe+0x22ad
//!     KERNEL32.DLL+0x2dda7
//!     module demo.exe | demo.pdb | B8F0742BA04EE44B4C4C44205044422E1
//!     module KERNEL32.DLL | kernel32.pdb | E8C3A48CAC7EB60D8781D8C10020C44F1
//!
//! The format, line by line, each indented by four spaces:
//!   - `wintrace`: the start of a trace, so one cut short, such as by the process dying while
//!     writing it, isn't taken for part of the next.
//!   - `<module>+0x<offset>`: a frame. Every frame is a return address, which points after its
//!     call, except one marked ` (ip)`: the instruction an exception happened at. ` (xN)` means
//!     the line stands for N identical frames in a row.
//!   - `0x<address>`: a frame outside any loaded module, or in one whose path is too long to
//!     read its name.
//!   - `... N frames`: frames left out of a deep stack, between its innermost and outermost.
//!     `... at least N frames` when the walk gave up first, so the frames after it may not be
//!     the outermost.
//!   - `... more frames`: the stack goes on past the last frame, from writeAddresses.
//!   - `module <module> | <pdb> | <key>`: one per module the frames are in. `<key>` is the PDB
//!     identity the linker stamps into both the image and its PDB (GUID and age, as symbol
//!     stores name its directory); `-` when the image has none. Windows file names can't
//!     contain `|`, so the names may contain spaces.
//!   - `... more modules`: the trace has frames in more modules than are listed.
//!
//! Supports x86_64, aarch64 and x86. x86 has no unwind
//! info, so its frames are walked through the frame pointer chain: the code in the trace must keep
//! frame pointers (`.omit_frame_pointer = false`), as Windows' own x86 DLLs do.

comptime {
    if (builtin.cpu.arch == .x86 and builtin.omit_frame_pointer) @compileError(
        "wintrace on x86 walks the stack through the frame pointer, set omit_frame_pointer to false",
    );
}

/// Writes the stack of the calling thread, starting at the caller of this function. When
/// `first_address` is one of its return addresses, such as a panic handler's, the frames
/// above it are skipped too.
pub noinline fn writeCurrentStackTrace(w: *Writer, first_address: ?usize) error{WriteFailed}!void {
    var context: windows.CONTEXT = undefined;
    RtlCaptureContext(&context);
    // frame 0 is this function, except on x86, where RtlCaptureContext returns its caller's
    // caller's context, as if this function had returned
    var skip: usize = if (builtin.cpu.arch == .x86) 0 else 1;
    if (first_address) |address| {
        var scan: Walker = undefined;
        scan.init(&context, no_leaf_scan);
        for (0..first_address_search) |i| {
            const ip = scan.next() orelse break;
            if (i > 0 and ip == address) {
                skip = i;
                break;
            }
        }
    }
    try writeWalk(w, &context, skip, false, no_leaf_scan);
}

/// Writes the stack starting at `context`, such as an exception's ContextRecord. The context
/// must be from the calling thread. Its first frame is marked ` (ip)`. For the current stack,
/// use writeCurrentStackTrace: on x86, RtlCaptureContext returns its caller's caller's
/// context, so a trace from it would leave out the function that called it.
pub fn writeStackTrace(w: *Writer, context: *const windows.CONTEXT) error{WriteFailed}!void {
    try writeWalk(w, context, 0, true, yes_leaf_scan);
}

/// Fills `addresses` with the instruction pointer of each frame, starting at `context`, which
/// must be from the calling thread, and returns how many it found. When that's
/// `addresses.len`, the stack may have more (or exactly that many). Doesn't allocate and
/// doesn't need debug info. The first address is the context's instruction pointer; every
/// other one is a return address.
pub fn capture(context: *const windows.CONTEXT, addresses: []usize) usize {
    var walker: Walker = undefined;
    walker.init(context, yes_leaf_scan);
    var count: usize = 0;
    while (count < addresses.len) : (count += 1) {
        addresses[count] = walker.next() orelse break;
    }
    return count;
}

pub const WriteOptions = struct {
    /// The first address is an instruction pointer, not a return address, such as the first
    /// address `capture` returns.
    first_is_ip: bool = false,
    /// The stack has frames beyond the last address, such as when `capture` filled its buffer.
    truncated: bool = false,
};

/// Writes a trace of `addresses`, such as those from `capture`. A module the addresses are in
/// must still be loaded, at the same address, when they're written.
pub fn writeAddresses(w: *Writer, addresses: []const usize, options: WriteOptions) error{WriteFailed}!void {
    var t: TraceWriter = .init(w);
    try t.start();
    try t.frames(addresses, options.first_is_ip);
    if (options.truncated) try t.line("    ... more frames", null);
    try t.finish();
}

/// Writes `module+0xoffset` for an address in a loaded module, or `0x<address>` otherwise.
pub fn writeAddress(w: *Writer, address: usize) error{WriteFailed}!void {
    const base = moduleBase(address) orelse return writeHex(w, "0x", address, 1, .lower);
    try writeModuleName(w, base);
    try writeHex(w, "+0x", address - base, 1, .lower);
}

/// The PDB a loaded image was linked with, from its CodeView debug record.
pub const PdbInfo = struct {
    guid: [16]u8,
    age: u32,
    /// The path the linker wrote the PDB to. Points into the image, so it's valid while the
    /// image stays loaded.
    path: []const u8,
};

/// Reads the CodeView (RSDS) record of the image loaded at `base`, or returns null when it has
/// none, such as a stripped image. Every offset is checked against the image's size and only
/// the image's own memory is read, so it's safe to call while crashing.
pub fn pdbInfo(base: usize) ?PdbInfo {
    const image: [*]const u8 = @ptrFromInt(base);
    if (readU16(image) != 0x5a4d) return null; // "MZ"
    // The headers read below are in the image's first page, which is always mapped.
    const nt_offset = readU32(image + 0x3c);
    if (nt_offset > 4096 - nt_headers_read) return null;
    const nt = image + nt_offset;
    if (readU32(nt) != 0x4550) return null; // "PE\0\0"
    const optional = nt + 24;
    // PE32+ in a 64-bit process, PE32 in a 32-bit one, the only kinds each runs
    if (readU16(optional) != pe_magic) return null;
    const size_of_image = readU32(optional + 56);
    // NumberOfRvaAndSizes, just before the data directories; the debug directory is the 7th
    if (readU32(optional + pe_directories - 4) <= 6) return null;
    const debug_rva = readU32(optional + pe_directories + 6 * 8);
    const debug_size = readU32(optional + pe_directories + 6 * 8 + 4);
    if (debug_rva == 0 or !inImage(debug_rva, debug_size, size_of_image)) return null;
    var offset: u32 = 0;
    while (offset + 28 <= debug_size) : (offset += 28) {
        const entry = image + debug_rva + offset;
        if (readU32(entry + 12) != 2) continue; // IMAGE_DEBUG_TYPE_CODEVIEW
        const data_size = readU32(entry + 16);
        const data_rva = readU32(entry + 20);
        if (data_rva == 0 or data_size < 24 or !inImage(data_rva, data_size, size_of_image)) continue;
        const cv = image[data_rva..][0..data_size];
        if (readU32(cv.ptr) != 0x53445352) continue; // "RSDS"
        const path = cv[24..];
        return .{
            .guid = cv[4..20].*,
            .age = readU32(cv.ptr + 20),
            // a plain loop: std.mem.indexOfScalar is vectorized, which adds hundreds of bytes
            .path = path[0..for (path, 0..) |c, i| {
                if (c == 0) break i;
            } else path.len],
        };
    }
    return null;
}

/// Writes a PDB's identity the way symbol stores name its directory: the GUID's fields as
/// uppercase hex, followed by the age.
pub fn writePdbKey(w: *Writer, guid: [16]u8, age: u32) error{WriteFailed}!void {
    // the first three fields are little-endian
    for ([_]u8{ 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 }) |i| try writeHex(w, "", guid[i], 2, .upper);
    try writeHex(w, "", age, 1, .upper);
}

/// For SetThreadStackGuarantee, so a stack overflow can be reported.
pub const stack_guarantee = 32 * 1024;

pub extern "kernel32" fn SetUnhandledExceptionFilter(
    filter: ?*const fn (*windows.EXCEPTION_POINTERS) callconv(.winapi) c_long,
) callconv(.winapi) ?*const anyopaque;
pub extern "kernel32" fn SetThreadStackGuarantee(size: *u32) callconv(.winapi) i32;

pub const panic = if (builtin.os.tag == .windows)
    std.debug.FullPanic(panicHandler)
else
    @compileError("wintrace.panic is only for Windows");

var panicking = false;
var reporting_exception = false;

fn panicHandler(msg: []const u8, first_trace_addr: ?usize) noreturn {
    @branchHint(.cold);
    const first_address = first_trace_addr orelse @returnAddress();
    if (!panicking) {
        panicking = true;
        var buf: [256]u8 = undefined;
        var stderr = smallStderr(&buf);
        writePanic(&stderr, msg, first_address) catch {};
    }
    std.process.abort();
}

/// Where the reports are written: straight to the stderr handle, without std's files.
fn smallStderr(buffer: []u8) Writer {
    return .{ .vtable = &.{ .drain = drainSmallStderr }, .buffer = buffer };
}

fn drainSmallStderr(w: *Writer, data: []const []const u8, splat: usize) error{WriteFailed}!usize {
    try writeSmallStderr(w.buffered());
    w.end = 0;
    var written: usize = 0;
    for (data[0 .. data.len - 1]) |bytes| {
        try writeSmallStderr(bytes);
        written += bytes.len;
    }
    const last = data[data.len - 1];
    for (0..splat) |_| try writeSmallStderr(last);
    return written + splat * last.len;
}

fn writeSmallStderr(bytes: []const u8) error{WriteFailed}!void {
    const stderr = windows.peb().ProcessParameters.hStdError;
    var rest = bytes;
    while (rest.len > 0) {
        var io_status: [2]usize = undefined;
        var status = NtWriteFile(
            stderr,
            null,
            null,
            null,
            &io_status,
            rest.ptr,
            @intCast(rest.len),
            null,
            null,
        );
        if (status == status_pending) {
            // a handle opened for overlapped io, which is signaled when the write is done
            if (NtWaitForSingleObject(stderr, 0, null) != 0) return error.WriteFailed;
            status = @bitCast(@as(u32, @truncate(io_status[0])));
        }
        // no stderr, or a pipe nobody reads anymore
        if (status < 0 or io_status[1] == 0) return error.WriteFailed;
        rest = rest[io_status[1]..];
    }
}

fn writePanic(w: *Writer, msg: []const u8, first_address: usize) error{WriteFailed}!void {
    // in pieces, here and in the other reports: std.fmt is several KB that the traces don't need
    try w.writeAll("panic: ");
    try w.writeAll(msg);
    try w.writeAll("\n");
    if (@errorReturnTrace()) |trace| if (trace.index > 0) {
        try w.writeAll("error return context:\n");
        try writeErrorReturnTrace(w, trace);
        try w.writeAll("stack trace:\n");
    };
    try w.flush();
    try writeCurrentStackTrace(w, first_address);
    try w.flush();
}

/// Reports an error returned from main like std does, then exits with 1.
pub fn exitWithErrorTrace(err: anyerror, trace: ?*std.builtin.StackTrace) noreturn {
    if (builtin.os.tag != .windows) @compileError("wintrace.exitWithErrorTrace is only for Windows");
    var buf: [256]u8 = undefined;
    var stderr = smallStderr(&buf);
    write: {
        stderr.writeAll("error: ") catch break :write;
        stderr.writeAll(@errorName(err)) catch break :write;
        stderr.writeAll("\n") catch break :write;
        if (trace) |t| writeErrorReturnTrace(&stderr, t) catch break :write;
        stderr.flush() catch break :write;
    }
    std.process.exit(1);
}

/// For SetUnhandledExceptionFilter. Exits with the exception code.
pub fn unhandledExceptionFilter(info: *windows.EXCEPTION_POINTERS) callconv(.winapi) c_long {
    comptime {
        if (std.options.enable_segfault_handler) @compileError(
            "std's segfault handler reports exceptions before an unhandled exception filter can, " ++
                "set std_options.enable_segfault_handler to false",
        );
    }
    // from std.process.abort
    if (info.ExceptionRecord.ExceptionCode == exception_breakpoint) return exception_continue_search;
    if (reporting_exception) return exception_continue_search;
    reporting_exception = true;
    var buf: [256]u8 = undefined;
    var stderr = smallStderr(&buf);
    writeExceptionReport(&stderr, info) catch {};
    return exception_execute_handler;
}

fn writeExceptionReport(w: *Writer, info: *windows.EXCEPTION_POINTERS) error{WriteFailed}!void {
    const record = info.ExceptionRecord;
    try writeHex(w, "unhandled exception 0x", record.ExceptionCode, 8, .upper);
    switch (record.ExceptionCode) {
        exception_access_violation => if (record.NumberParameters >= 2) {
            const access = switch (record.ExceptionInformation[0]) {
                0 => "reading",
                1 => "writing",
                8 => "executing",
                else => "accessing",
            };
            try w.writeAll(" (access violation ");
            try w.writeAll(access);
            try writeHex(w, " 0x", record.ExceptionInformation[1], 1, .lower);
            try w.writeAll(")");
        },
        exception_illegal_instruction => try w.writeAll(" (illegal instruction)"),
        exception_stack_overflow => try w.writeAll(" (stack overflow)"),
        exception_int_divide_by_zero => try w.writeAll(" (integer divide by zero)"),
        else => {},
    }
    try w.writeAll(" at ");
    try writeAddress(w, @intFromPtr(record.ExceptionAddress));
    try w.writeAll("\n");
    try w.flush();
    try writeStackTrace(w, info.ContextRecord);
    try w.flush();
}

fn writeErrorReturnTrace(w: *Writer, trace: *const std.builtin.StackTrace) error{WriteFailed}!void {
    const count = @min(trace.index, trace.instruction_addresses.len);
    try writeAddresses(w, trace.instruction_addresses[0..count], .{ .truncated = trace.index > count });
}

/// Walks the stack of the calling thread one frame at a time.
const Walker = struct {
    context: windows.CONTEXT,
    history: UNWIND_HISTORY_TABLE,
    /// The committed part of this thread's stack. A frame's stack pointer outside it means the
    /// stack is corrupt, so the walk stops there rather than fault reading it.
    stack_low: usize,
    stack_high: usize,
    leaf_scan: LeafScan,
    first: bool,
    done: bool,

    fn init(walker: *Walker, context: *const windows.CONTEXT, leaf_scan: LeafScan) void {
        const tib = &windows.teb().NtTib;
        walker.* = .{
            .context = context.*,
            .history = std.mem.zeroes(UNWIND_HISTORY_TABLE),
            .stack_low = @intFromPtr(tib.StackLimit),
            .stack_high = @intFromPtr(tib.StackBase),
            .leaf_scan = leaf_scan,
            .first = true,
            .done = false,
        };
        // An exception's context usually has CONTEXT_XSTATE set, which says extended state
        // (AVX and such) follows the record in memory. This copy doesn't have it, and the
        // unwinder in an x64 process emulated on ARM64 reads it, faulting on whatever is
        // past the copy. Unwinding needs none of it.
        walker.context.ContextFlags &= ~@as(u32, switch (builtin.cpu.arch) {
            .x86_64, .x86 => 0x40,
            .aarch64 => 0x20,
            else => unreachable,
        });
    }

    /// Returns the next frame's instruction pointer, or null after the last frame.
    fn next(walker: *Walker) ?usize {
        if (walker.done) return null;
        const regs = ipSp(&walker.context);
        // An instruction pointer of 0 ends the stack, except in the first frame, which is a
        // call through a null function pointer: its caller is found like a leaf's.
        if (regs.ip == 0 and !walker.first) {
            walker.done = true;
            return null;
        }
        walker.done = !walker.unwind(regs.ip, regs.sp);
        walker.first = false;
        return regs.ip;
    }

    /// Unwinds the context to the caller of the frame at `ip` and `sp`. Returns false when it
    /// can't, which ends the walk.
    fn unwind(walker: *Walker, ip: usize, sp: usize) bool {
        if (!walker.onStack(sp, @sizeOf(usize))) return false;
        var image_base: usize = undefined;
        if (builtin.cpu.arch == .x86) {
            if (!walker.unwindFramePointer(ip, sp)) return false;
        } else if (RtlLookupFunctionEntry(ip, &image_base, &walker.history)) |function| {
            var handler_data: ?*anyopaque = null;
            var establisher_frame: usize = undefined;
            _ = RtlVirtualUnwind(unw_flag_nhandler, image_base, ip, function, &walker.context, &handler_data, &establisher_frame, null);
        } else {
            // Only a leaf function, which calls nothing, has no unwind info, so only the
            // innermost frame can be one.
            if (!walker.first) return false;
            switch (builtin.cpu.arch) {
                // The return address is on top of the stack. A few functions, like __chkstk,
                // where stack overflows usually happen, push registers first, so skip slots
                // that don't hold an address right after a call.
                .x86_64 => {
                    var slot = sp;
                    const return_address = for (0..4) |_| {
                        if (!walker.onStack(slot, @sizeOf(usize))) return false;
                        const value = @as(*const usize, @ptrFromInt(slot)).*;
                        slot += @sizeOf(usize);
                        if (isCode(value) and followsCall(value)) break value;
                    } else return false;
                    walker.context.setIp(return_address);
                    walker.context.setSp(slot);
                },
                // the return address is in the link register
                .aarch64 => walker.context.setIp(walker.context.DUMMYUNIONNAME.DUMMYSTRUCTNAME.Lr),
                else => unreachable,
            }
        }
        // The stack only grows down, so each caller's frame is above its callee's. A leaf
        // function on aarch64 needs no stack, so the innermost frame may share its caller's.
        const caller = ipSp(&walker.context);
        if (caller.sp > sp) return true;
        return caller.sp == sp and walker.first and caller.ip != ip;
    }

    /// x86 has no unwind info, so a frame's caller comes from the frame pointer chain: EBP
    /// points at the caller's saved EBP, with the return address above it.
    fn unwindFramePointer(walker: *Walker, ip: usize, sp: usize) bool {
        const bp: usize = walker.context.Ebp;
        // An exception can happen before the function has a frame of its own, at its first
        // instruction or in a leaf like __chkstk, while EBP is still its caller's. Its return
        // address is then near the top of the stack, below the caller's frame, maybe after a
        // few pushed registers as on x86_64. A function that does have a frame can have return
        // addresses there too, left by earlier calls, or one RaiseException keeps in its
        // exception record, so only one from a call to near ip counts.
        if (walker.first and walker.leaf_scan) {
            // an EBP below the stack pointer is a register in other use, not a frame
            const limit = if (bp >= sp and walker.onStack(bp, @sizeOf(usize))) bp else walker.stack_high;
            var slot = sp;
            for (0..4) |_| {
                if (slot >= limit or !walker.onStack(slot, @sizeOf(usize))) break;
                const value = @as(*const usize, @ptrFromInt(slot)).*;
                slot += @sizeOf(usize);
                if (isCode(value) and followsCall(value) and callReaches(value, ip)) {
                    walker.context.Eip = value;
                    walker.context.Esp = slot;
                    return true;
                }
            }
        }
        // a frame is above the stack pointer, like everything its function pushed
        if (bp < sp or !walker.onStack(bp, 2 * @sizeOf(usize))) return false;
        const frame: *const [2]usize = @ptrFromInt(bp);
        if (!isCode(frame[1])) return false;
        walker.context.Ebp = frame[0];
        walker.context.Eip = frame[1];
        walker.context.Esp = bp + 2 * @sizeOf(usize);
        return true;
    }

    fn onStack(walker: *const Walker, address: usize, len: usize) bool {
        return address % @sizeOf(usize) == 0 and address >= walker.stack_low and
            address <= walker.stack_high and walker.stack_high - address >= len;
    }
};

/// On x86, whether the innermost frame may not have a frame of its own yet, as at an exception
/// (see unwindFramePointer). Only x86 walks the frame pointer chain, so elsewhere it's void.
const LeafScan = if (builtin.cpu.arch == .x86) bool else void;
const no_leaf_scan = if (builtin.cpu.arch == .x86) false else {};
const yes_leaf_scan = if (builtin.cpu.arch == .x86) true else {};

/// A context's instruction and stack pointers. std's x86 getRegs has no sp before Zig 0.17.
fn ipSp(context: *const windows.CONTEXT) struct { ip: usize, sp: usize } {
    if (builtin.cpu.arch == .x86) return .{ .ip = context.Eip, .sp = context.Esp };
    const regs = context.getRegs();
    return .{ .ip = regs.ip, .sp = regs.sp };
}

/// Walks from `context`, skipping `skip` frames, and writes the first `head_frames` and last
/// `tail_frames` of the rest, with a count of those in between.
fn writeWalk(w: *Writer, context: *const windows.CONTEXT, skip: usize, first_is_ip: bool, leaf_scan: LeafScan) error{WriteFailed}!void {
    var walker: Walker = undefined;
    walker.init(context, leaf_scan);
    for (0..skip) |_| _ = walker.next() orelse break;
    var head: [head_frames]usize = undefined;
    var tail: [tail_frames]usize = undefined;
    var count: usize = 0;
    while (count < max_walk) : (count += 1) {
        const ip = walker.next() orelse break;
        if (count < head.len) head[count] = ip else tail[(count - head.len) % tail.len] = ip;
    }
    var t: TraceWriter = .init(w);
    try t.start();
    try t.frames(head[0..@min(count, head.len)], first_is_ip);
    if (count > head.len) {
        const tail_count = @min(count - head.len, tail.len);
        const omitted = count - head.len - tail_count;
        // at max_walk the stack may go on, so the tail may not be its outermost frames
        if (count == max_walk) {
            try t.line("    ... at least ", omitted);
        } else if (omitted > 0) try t.line("    ... ", omitted);
        // the ring's oldest entry first
        const start = if (count - head.len > tail.len) (count - head.len) % tail.len else 0;
        var ordered: [tail_frames]usize = undefined;
        for (0..tail_count) |i| ordered[i] = tail[(start + i) % tail.len];
        try t.frames(ordered[0..tail_count], false);
    }
    try t.finish();
}

const TraceWriter = struct {
    w: *Writer,
    modules: [max_modules]usize,
    module_count: usize,
    modules_dropped: bool,
    /// A run of frames at one address not written yet, which the next frames may continue.
    run_address: usize,
    run_length: usize,

    fn init(w: *Writer) TraceWriter {
        return .{
            .w = w,
            .modules = undefined,
            .module_count = 0,
            .modules_dropped = false,
            .run_address = 0,
            .run_length = 0,
        };
    }

    fn start(t: *TraceWriter) error{WriteFailed}!void {
        try t.w.writeAll("    wintrace\n");
    }

    /// Writes one line per frame, collapsing runs of the same address, such as a stack
    /// overflow's recursion, even across calls.
    fn frames(t: *TraceWriter, addresses: []const usize, first_is_ip: bool) error{WriteFailed}!void {
        for (addresses, 0..) |address, i| {
            if (i == 0 and first_is_ip) {
                try t.endRun();
                try t.frame(address, true, 1);
            } else if (t.run_length > 0 and address == t.run_address) {
                t.run_length += 1;
            } else {
                try t.endRun();
                t.run_address = address;
                t.run_length = 1;
            }
        }
    }

    /// Writes a line that isn't a frame, after the frames before it: `text`, or `text`, then
    /// `frames` and ` frames`.
    fn line(t: *TraceWriter, text: []const u8, frames_count: ?usize) error{WriteFailed}!void {
        try t.endRun();
        try t.w.writeAll(text);
        if (frames_count) |n| {
            try writeDecimal(t.w, n);
            try t.w.writeAll(" frames");
        }
        try t.w.writeAll("\n");
    }

    fn endRun(t: *TraceWriter) error{WriteFailed}!void {
        if (t.run_length > 0) try t.frame(t.run_address, false, t.run_length);
        t.run_length = 0;
    }

    fn frame(t: *TraceWriter, address: usize, ip: bool, repeat: usize) error{WriteFailed}!void {
        try t.w.writeAll("    ");
        if (moduleBase(address)) |base| {
            try writeModuleName(t.w, base);
            try writeHex(t.w, "+0x", address - base, 1, .lower);
            const listed = for (t.modules[0..t.module_count]) |m| {
                if (m == base) break true;
            } else false;
            if (!listed) {
                if (t.module_count < t.modules.len) {
                    t.modules[t.module_count] = base;
                    t.module_count += 1;
                } else t.modules_dropped = true;
            }
        } else try writeHex(t.w, "0x", address, 1, .lower);
        if (ip) try t.w.writeAll(" (ip)");
        if (repeat > 1) {
            try t.w.writeAll(" (x");
            try writeDecimal(t.w, repeat);
            try t.w.writeAll(")");
        }
        try t.w.writeAll("\n");
    }

    /// Writes the module lines.
    fn finish(t: *TraceWriter) error{WriteFailed}!void {
        try t.endRun();
        for (t.modules[0..t.module_count]) |base| {
            try t.w.writeAll("    module ");
            try writeModuleName(t.w, base);
            if (pdbInfo(base)) |pdb| {
                try t.w.writeAll(" | ");
                try writeField(t.w, basename(u8, pdb.path));
                try t.w.writeAll(" | ");
                try writePdbKey(t.w, pdb.guid, pdb.age);
                try t.w.writeAll("\n");
            } else try t.w.writeAll(" | - | -\n");
        }
        if (t.modules_dropped) try t.w.writeAll("    ... more modules\n");
    }
};

/// Writes a name from an image's debug record, which can hold any bytes, so the line stays one
/// line with three fields.
fn writeField(w: *Writer, name: []const u8) error{WriteFailed}!void {
    if (name.len == 0) return w.writeAll("-");
    for (name) |c| try w.writeByte(switch (c) {
        '|', '\r', '\n' => '?',
        else => c,
    });
}

fn moduleBase(address: usize) ?usize {
    var base: ?*anyopaque = null;
    _ = RtlPcToFileHeader(address, &base);
    return if (base) |b| @intFromPtr(b) else null;
}

/// Whether `address` is in a function: one with unwind info, or on x86, which has none, anywhere
/// in an executable section.
fn isCode(address: usize) bool {
    if (builtin.cpu.arch == .x86) {
        const base = moduleBase(address) orelse return false;
        return inExecutableSection(base, address - base);
    }
    var image_base: usize = undefined;
    return RtlLookupFunctionEntry(address, &image_base, null) != null;
}

/// Whether `rva` is in an executable section of the image loaded at `base`. Only reads the
/// section headers in the image's first page, which is always mapped.
fn inExecutableSection(base: usize, rva: usize) bool {
    const image: [*]const u8 = @ptrFromInt(base);
    const nt_offset = readU32(image + 0x3c);
    if (nt_offset > 4096 - 24) return false;
    const count = readU16(image + nt_offset + 6);
    const sections = nt_offset + 24 + readU16(image + nt_offset + 20);
    if (sections + @as(usize, count) * 40 > 4096) return false;
    for (0..count) |i| {
        const section = image + sections + i * 40;
        const virtual_size = readU32(section + 8);
        const virtual_address = readU32(section + 12);
        const characteristics = readU32(section + 36);
        if (characteristics & image_scn_mem_execute != 0 and rva >= virtual_address and rva - virtual_address < virtual_size)
            return true;
    }
    return false;
}

/// Whether the instruction before `address`, which isCode, is an x86 call, as it is before
/// a return address. A pushed pointer to a function usually isn't. Reading before it is safe:
/// a function is in a section, which follows the image's headers.
fn followsCall(address: usize) bool {
    const code: [*]const u8 = @ptrFromInt(address);
    // call rel32
    if ((code - 5)[0] == 0xe8) return true;
    // call r/m (FF /2), whose length its ModRM and SIB bytes give
    for (2..8) |len| {
        const op = code - len;
        const modrm = op[1];
        if (op[0] != 0xff or (modrm >> 3) & 7 != 2) continue;
        const rm = modrm & 7;
        const call_len: usize = switch (modrm >> 6) {
            0 => if (rm == 4) (if (op[2] & 7 == 5) 7 else 3) else if (rm == 5) 6 else 2,
            1 => if (rm == 4) 4 else 3,
            2 => if (rm == 4) 7 else 6,
            else => 2,
        };
        if (call_len == len) return true;
    }
    return false;
}

/// How far into a function an x86 leaf scan finds its return address: past a few pushes, or
/// in __chkstk's probing loop.
const leaf_scan_reach = 64;

/// Whether the x86 call before `return_address`, which followsCall, can be to the function at
/// `ip`, near its start. A call through a register can't be checked, so it can be, and so can
/// a call to 0, a null function pointer.
fn callReaches(return_address: usize, ip: usize) bool {
    if (ip == 0) return true;
    const code: [*]const u8 = @ptrFromInt(return_address);
    const target = if ((code - 5)[0] == 0xe8)
        return_address +% readU32(code - 4)
    else if ((code - 6)[0] == 0xff and (code - 5)[0] == 0x15)
        // call [address], through an import table
        readPointer(readU32(code - 4)) orelse return false
    else
        return true;
    if (ip >= target and ip - target < leaf_scan_reach) return true;
    // a jmp [address] thunk to an import
    if (!isCode(target)) return false;
    const thunk: [*]const u8 = @ptrFromInt(target);
    if (thunk[0] != 0xff or thunk[1] != 0x25) return false;
    const import = readPointer(readU32(thunk + 2)) orelse return false;
    return ip >= import and ip - import < leaf_scan_reach;
}

/// The pointer at `address`, when that's in a loaded image, as an import table is.
fn readPointer(address: usize) ?usize {
    if (address % @sizeOf(usize) != 0 or moduleBase(address) == null) return null;
    return @as(*const usize, @ptrFromInt(address)).*;
}

/// Calls GetModuleFileNameW, which Microsoft's "Dynamic-Link Library Best Practices" says "can
/// indirectly acquire the loader lock". That could deadlock a crash report written while
/// another thread holds it, such as during a LoadLibrary. Testing shows it doesn't, at least
/// on modern Windows: on Windows 11 it returned at once while another thread held the loader
/// lock (LdrLockLoaderLock), so we call it here.
fn writeModuleName(w: *Writer, base: usize) error{WriteFailed}!void {
    var path_buf: [max_path]u16 = undefined;
    const len = GetModuleFileNameW(@ptrFromInt(base), &path_buf, path_buf.len);
    if (len == 0 or len == path_buf.len) return writeHex(w, "0x", base, 1, .lower);
    try writeUtf16(w, basename(u16, path_buf[0..len]));
}

// The writers below take the place of std's formatter, which would add about 1 KB.

/// Writes `prefix`, then `value` in hex with at least `width` digits.
fn writeHex(w: *Writer, prefix: []const u8, value: u64, width: u8, case: enum { lower, upper }) error{WriteFailed}!void {
    const digits = switch (case) {
        .lower => "0123456789abcdef",
        .upper => "0123456789ABCDEF",
    };
    var buf: [16]u8 = undefined;
    var i: usize = buf.len;
    var v = value;
    while (v != 0 or buf.len - i < width) : (v >>= 4) {
        i -= 1;
        buf[i] = digits[@intCast(v & 15)];
    }
    try w.writeAll(prefix);
    try w.writeAll(buf[i..]);
}

fn writeDecimal(w: *Writer, value: usize) error{WriteFailed}!void {
    var buf: [20]u8 = undefined;
    var i: usize = buf.len;
    var v = value;
    while (true) {
        i -= 1;
        buf[i] = '0' + @as(u8, @intCast(v % 10));
        v /= 10;
        if (v == 0) break;
    }
    try w.writeAll(buf[i..]);
}

/// Writes UTF-16 as UTF-8, with U+FFFD for a lone surrogate. ntdll converts it, which takes far
/// less code than encoding it here, and neither allocates nor locks.
fn writeUtf16(w: *Writer, text: []const u16) error{WriteFailed}!void {
    var rest = text;
    while (rest.len > 0) {
        var n = @min(rest.len, 32);
        // keep a surrogate pair in one chunk
        if (n < rest.len and rest[n - 1] >= 0xd800 and rest[n - 1] < 0xdc00) n -= 1;
        var buf: [32 * 3]u8 = undefined;
        var len: u32 = 0;
        _ = RtlUnicodeToUTF8N(&buf, buf.len, &len, rest.ptr, @intCast(n * 2));
        try w.writeAll(buf[0..len]);
        rest = rest[n..];
    }
}

fn basename(comptime T: type, path: []const T) []const T {
    var start: usize = 0;
    for (path, 0..) |c, i| if (c == '\\' or c == '/') {
        start = i + 1;
    };
    return path[start..];
}

fn inImage(rva: u32, size: u32, size_of_image: u32) bool {
    return @as(u64, rva) + size <= size_of_image;
}

fn readU16(p: [*]const u8) u16 {
    return std.mem.readInt(u16, p[0..2], .little);
}
fn readU32(p: [*]const u8) u32 {
    return std.mem.readInt(u32, p[0..4], .little);
}

/// How far into the NT headers pdbInfo reads: through the debug directory entry.
const nt_headers_read = 24 + pe_directories + 7 * 8;
/// A deep stack keeps its innermost frames, where it failed, and its outermost, where the
/// thread started and, for a stack overflow, where the recursion began.
const head_frames = 96;
const tail_frames = 32;
const max_walk = 1 << 20;
/// How deep writeCurrentStackTrace looks for first_address.
const first_address_search = 256;
const max_modules = 32;
const max_path = 260;
const unw_flag_nhandler = 0;
const image_scn_mem_execute = 0x20000000;
/// The optional header's magic for this process's images, and where its data directories start:
/// PE32 has one field fewer than PE32+.
const pe_magic: u16 = if (@sizeOf(usize) == 8) 0x20b else 0x10b;
const pe_directories: usize = if (@sizeOf(usize) == 8) 112 else 96;

/// The unwind types, which std defines only for some architectures. x86 has none.
const RUNTIME_FUNCTION = switch (builtin.cpu.arch) {
    .x86_64, .aarch64 => windows.RUNTIME_FUNCTION,
    .x86 => void,
    else => @compileError(unsupported),
};
const UNWIND_HISTORY_TABLE = switch (builtin.cpu.arch) {
    .x86_64, .aarch64 => windows.UNWIND_HISTORY_TABLE,
    .x86 => void,
    else => @compileError(unsupported),
};
const unsupported = "wintrace supports x86_64, aarch64 and x86 Windows";

// Declared here rather than taken from std, whose parameter types differ between versions.
extern "ntdll" fn RtlCaptureContext(context: *windows.CONTEXT) callconv(.winapi) void;
extern "ntdll" fn RtlLookupFunctionEntry(
    pc: usize,
    image_base: *usize,
    history: ?*UNWIND_HISTORY_TABLE,
) callconv(.winapi) ?*RUNTIME_FUNCTION;
extern "ntdll" fn RtlVirtualUnwind(
    handler_type: u32,
    image_base: usize,
    pc: usize,
    function: *RUNTIME_FUNCTION,
    context: *windows.CONTEXT,
    handler_data: *?*anyopaque,
    establisher_frame: *usize,
    context_pointers: ?*anyopaque,
) callconv(.winapi) ?*anyopaque;
extern "ntdll" fn NtWriteFile(
    file: ?*anyopaque,
    event: ?*anyopaque,
    apc_routine: ?*anyopaque,
    apc_context: ?*anyopaque,
    io_status: *[2]usize,
    buffer: [*]const u8,
    length: u32,
    byte_offset: ?*i64,
    key: ?*u32,
) callconv(.winapi) i32;
const status_pending = 0x103;
extern "ntdll" fn NtWaitForSingleObject(handle: ?*anyopaque, alertable: u8, timeout: ?*const i64) callconv(.winapi) i32;
extern "ntdll" fn RtlPcToFileHeader(pc: usize, base: *?*anyopaque) callconv(.winapi) ?*anyopaque;
extern "kernel32" fn GetModuleFileNameW(module: *anyopaque, name: [*]u16, size: u32) callconv(.winapi) u32;
extern "ntdll" fn RtlUnicodeToUTF8N(
    text: [*]u8,
    text_max: u32,
    text_len: *u32,
    wide: [*]const u16,
    wide_bytes: u32,
) callconv(.winapi) i32;

const exception_continue_search = 0;
const exception_execute_handler = 1;
const exception_breakpoint = 0x80000003;
const exception_stack_overflow = 0xC00000FD;
const exception_access_violation = 0xC0000005;
const exception_illegal_instruction = 0xC000001D;
const exception_int_divide_by_zero = 0xC0000094;

const builtin = @import("builtin");
const std = @import("std");
const std15 = if (zig_atleast_15) std else @import("std15");
const zig_atleast_15 = builtin.zig_version.order(.{ .major = 0, .minor = 15, .patch = 0 }) != .lt;
const Writer = std15.Io.Writer;
const windows = std.os.windows;
