const builtin = @import("builtin");
const std = @import("std");
const win32 = struct {
    usingnamespace @import("win32").foundation;
    usingnamespace @import("win32").storage.file_system;
    usingnamespace @import("win32").system.com;
    usingnamespace @import("win32").system.library_loader;
    usingnamespace @import("win32").system.memory;
    usingnamespace @import("win32").system.threading;
    usingnamespace @import("win32").ui.input.keyboard_and_mouse;
    usingnamespace @import("win32").ui.shell;
    usingnamespace @import("win32").ui.windows_and_messaging;
    usingnamespace @import("win32").zig;
};
const virtualkey = @import("virtualkey.zig");

const fmtW = std.unicode.fmtUtf16Le;

fn oom(e: error{OutOfMemory}) noreturn { @panic(@errorName(e)); }
fn fatal(comptime fmt: []const u8, args: anytype) noreturn {
    std.log.err(fmt, args);
    std.process.exit(0xff);
}

const Command = enum { status, enable, pause, log, run };
const command_map = std.StaticStringMap(Command).initComptime(.{
    .{ "status", .status },
    .{ "enable", .enable },
    .{ "pause", .pause },
    .{ "log", .log },
    .{ "run", .run },
});
const Mode = enum { log, run };
const global = struct {
    pub var mode: Mode = .log;
};

const interprocess_lock_name = win32.L("Global\\KeymapLock");
const shared_memory_name = win32.L("KeymapSharedMem");

pub fn main() !u8 {
    var arena_instance = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    // no need to free
    const arena = arena_instance.allocator();

    const maybe_config_path = getConfigPath(arena);
    if (maybe_config_path) |config_path| {
        // ignore errors here
        initConfig(config_path) catch { };
    } else |_| { }

    const cmdline_all = try std.process.argsAlloc(arena);
    if (cmdline_all.len <= 1) {
        try std.io.getStdErr().writer().writeAll(
            \\Usage:
            \\    keymap status
            \\    keymap enable    Enable the keymap
            \\    keymap pause     Temporarily pause the keymap
            \\    keymap log       Log all keyboard events
            \\
        );
        if (maybe_config_path) |config_path| {
            try std.io.getStdErr().writer().print(
                \\
                \\Configuration File at:
                \\    {s}
                \\
                ,
                .{fmtW(config_path)},
            );
        } else |_| { }
        return 0xff;
    }
    const cmd = cmdline_all[1];
    const cmd_args = cmdline_all[2..];

    global.mode = blk: {
        switch (command_map.get(cmd) orelse fatal(
            "unknown command '{s}'", .{cmd}
        )) {
            .status => {
                if (isRunning()) |pid| {
                    try std.io.getStdOut().writer().print("keymap is enabled (pid {})", .{pid});
                } else {
                    const config_path = maybe_config_path catch |err| fatal(
                        "failed to get config path, error={s}", .{@errorName(err)}
                    );
                    const instructions = try loadConfig(arena, config_path);
                    if (instructions.len == 0) {
                        try std.io.getStdOut().writer().print(
                            "not configured, create configuration at:\n    {}", .{fmtW(config_path)}
                        );
                    } else {
                        try std.io.getStdOut().writer().print("keymap is disabled", .{});
                    }
                }
                return 0;
            },
            .enable => {
                if (cmd_args.len > 0) fatal(
                    "the 'enable' command doesn't support any extra arguments", .{}
                );
                const config_path = maybe_config_path catch |err| fatal(
                    "failed to get config path, error={s}", .{@errorName(err)}
                );
                const instructions = try loadConfig(arena, config_path);
                if (instructions.len == 0) fatal(
                    "keymap not configured, create configuration at:\n    {}", .{fmtW(config_path)}
                );
                return enable();
            },
            .pause => {
                if (cmd_args.len > 0) fatal(
                    "the 'pause' command doesn't support any extra arguments", .{}
                );
                return pause();
            },
            .log => {
                if (cmd_args.len > 0) fatal(
                    "the 'log' command doesn't support any extra arguments", .{}
                );
                break :blk .log;
            },
            .run => {
                if (cmd_args.len > 0) fatal(
                    "the 'run' command doesn't support any extra arguments", .{}
                );
                break :blk .run;
            },
        }
    };

    switch (global.mode) {
        .log => {},
        .run => {
            const config_path = maybe_config_path catch |err| fatal(
                "failed to get config path, error={s}", .{@errorName(err)}
            );
            global_instructions = try loadConfig(arena, config_path);
            if (global_instructions.len == 0) fatal(
                "keymap not configured, create configuration at:\n    {}", .{fmtW(config_path)}
            );
        },
    }

    const hook = win32.SetWindowsHookExW(
        win32.WH_KEYBOARD_LL,
        hookproc,
        win32.GetModuleHandleW(null),
        0,
    ) orelse fatal(
        "SetWindowsHookExW failed, error={s}", .{lastErrorName()}
    );
    _ = hook;

    // TODO: will there be a problem if we don't call UnhookWindowsHookEx?
    //defer2(UnhookWindowsHookEx(hook));

    const shared_mem: ?SharedMem = blk: {
        const lock = InterprocessLock.init(interprocess_lock_name);
        defer lock.deinit();

        switch (global.mode) {
            .log => break :blk null,
            .run => {},
        }
        const shared_mem = SharedMem.init(shared_memory_name);
        switch (shared_mem.create) {
            .newly_created => {
                shared_mem.mem[0] = 0; // version number
                writeInt(u32, shared_mem.mem[1..5], win32.GetCurrentProcessId());
                break :blk shared_mem;
            },
            .already_exists => {
                const pid = readInt(u32, shared_mem.mem[1..5]);
                fatal("keymap process is already running (pid {})", .{pid});
            },
        }
    };
    _ = shared_mem;

    while (true) {
        var msg: win32.MSG = undefined;
        if (0 == win32.GetMessageW(&msg, null, 0, 0))
            return @intCast(msg.wParam);
        if (0 == win32.TranslateMessage(&msg)) fatal(
            "TranslateMessage failed, error={s}", .{lastErrorName()}
        );
        _ = win32.DispatchMessageW(&msg);
    }
}

fn readInt(comptime T: type, buffer: *const [@divExact(@typeInfo(T).Int.bits, 8)]u8) T {
    return std.mem.readInt(T, buffer, builtin.cpu.arch.endian());
}
fn writeInt(comptime T: type, buffer: *[@divExact(@typeInfo(T).Int.bits, 8)]u8, value: T) void {
    return std.mem.writeInt(T, buffer, value, builtin.cpu.arch.endian());
}

fn isRunning() ?u32 {
    const lock = InterprocessLock.init(interprocess_lock_name);
    defer lock.deinit();
    const shared_mem = SharedMem.init(shared_memory_name);
    return switch (shared_mem.create) {
        .newly_created => null,
        .already_exists => return readInt(u32, shared_mem.mem[1..5]),
    };
}

fn enable() !u8 {
    std.log.err("todo: configure launch on login", .{});
    if (isRunning()) |pid| {
        try std.io.getStdErr().writer().print("keymap process: already running (pid {})\n", .{pid});
        return 0;
    }
    var exe_path_buf: [std.os.windows.PATH_MAX_WIDE]u16 = undefined;
    const result = win32.GetModuleFileNameW(null, @ptrCast(&exe_path_buf), exe_path_buf.len);
    if (result == 0) fatal(
        "GetModuleFileNameW failed, error={}", .{win32.GetLastError()}
    );
    var startup = std.mem.zeroes(win32.STARTUPINFOW);
    var process_info: win32.PROCESS_INFORMATION = undefined;
    if (0 == win32.CreateProcessW(
        @ptrCast(&exe_path_buf), // application name
        @constCast(@ptrCast(win32.L("keymap.exe run"))), // command line
        null, // process attributes
        null, // thread attributes
        0, // inherit handles
        .{
            .DETACHED_PROCESS = 1,
            .CREATE_NEW_PROCESS_GROUP = 1,
        },
        null, // environment
        null, // current directory,
        &startup,
        &process_info,
    )) fatal(
        "CreateProcess failed, error={}", .{win32.GetLastError()}
    );
    try std.io.getStdErr().writer().writeAll("keymap process: newly launched\n");
    return 0;
}

fn pause() !u8 {
    const pid = isRunning() orelse {
        try std.io.getStdErr().writer().writeAll("already paused\n");
        return 0;
    };

    const proc = win32.OpenProcess(win32.PROCESS_TERMINATE, 0, pid) orelse fatal(
        "OpenProcess {} failed, error={s}", .{pid, lastErrorName()}
    );
    defer closeHandle(proc);

    if (0 == win32.TerminateProcess(proc, 0)) fatal(
        "TerminateProcess {} failed with {s}",
        .{ pid, lastErrorName() },
    );
    try std.io.getStdErr().writer().print("succesfully paused (killed process {})\n", .{pid});
    return 0;
}

fn initConfig(path: [:0]const u16) !void {
    const handle = win32.CreateFileW(
        path,
        win32.FILE_GENERIC_WRITE,
        .{ .READ = 1 },
        null,
        win32.CREATE_NEW,
        win32.FILE_ATTRIBUTE_NORMAL,
        null,
    );
    if (handle == win32.INVALID_HANDLE_VALUE) {
        const ec = win32.GetLastError();
        if (ec == .ERROR_FILE_EXISTS)
            return;
        fatal("CreateFile failed, error={s}", .{lastErrorName()});
    }
    defer closeHandle(handle);
    const file = std.fs.File{ .handle = handle };
    try file.writer().writeAll(
        \\# keymap configuration file
        \\#
        \\# Syntax:
        \\#
        \\#     replace KEY from SOURCE with KEY
        \\#
        \\#     KEY    | NUMBER[e]
        \\#     SOURCE | hardware[:NUMBER] | software[:NUMBER] | keymap
        \\#
        \\# Examples:
        \\#
        \\#     replace 29e from hardware with 91
        \\#
        \\
    );
}

fn loadConfig(allocator: std.mem.Allocator, path: [:0]const u16) ![]Instruction {
    const content = blk: {
        const handle = win32.CreateFileW(
            path,
            win32.FILE_GENERIC_READ,
            .{ .WRITE = 1, .READ = 1 },
            null,
            win32.OPEN_EXISTING,
            win32.FILE_ATTRIBUTE_NORMAL,
            null,
        );
        if (handle == win32.INVALID_HANDLE_VALUE) fatal(
            "keymap not configured, create configuration at:\n    {}", .{fmtW(path)}
        );
        const file = std.fs.File{ .handle = handle };
        break :blk try file.readToEndAlloc(allocator, std.math.maxInt(usize));
    };
    defer allocator.free(content);

    var instructions = std.ArrayList(Instruction).init(allocator);
    defer instructions.deinit();

    var line_it = std.mem.splitScalar(u8, content, '\n');
    var line_number: u32 = 0;
    while (line_it.next()) |line| {
        line_number += 1;
        const content_start = skipWhitespace(line, 0);
        if (content_start == line.len or line[content_start] == '#')
            continue;
        var it = std.mem.tokenizeAny(u8, line, &std.ascii.whitespace);
        const command = it.next() orelse continue;
        if (std.mem.eql(u8, command, "replace")) {
            try instructions.append(parseReplace(path, line_number, &it));
        } else fatal(
            "{}:{} unknown command '{s}'",
            .{fmtW(path), line_number, command},
        );
    }

    return instructions.toOwnedSlice();
}

fn parseReplace(path: [:0]const u16, line_number: u32, it: anytype) Instruction {
    const replace_key = blk: {
        const str = it.next() orelse fatal(
            "{}:{} 'replace' command missing arguments",
            .{fmtW(path), line_number}
        );
        break :blk parseKey(str) orelse fatal(
            "{}:{} invalid key '{s}'",
            .{fmtW(path), line_number, str}
        );
    };
    {
        const from_token_str = it.next() orelse fatal(
            "{}:{} 'replace' command missing arguments",
            .{fmtW(path), line_number}
        );
        if (!std.mem.eql(u8, "from", from_token_str)) fatal(
            "{}:{} expected 'from' but got '{s}'",
            .{fmtW(path), line_number, from_token_str},
        );
    }
    const source = blk: {
        const str = it.next() orelse fatal(
            "{}:{} 'replace' command missing arguments",
            .{fmtW(path), line_number}
        );
        break :blk parseSourceQuery(str) orelse fatal(
            "{}:{} invalid source '{s}', expected " ++ expected_source,
            .{fmtW(path), line_number, str}
        );
    };
    {
        const with_token_str = it.next() orelse fatal(
            "{}:{} 'replace' command missing arguments",
            .{fmtW(path), line_number}
        );
        if (!std.mem.eql(u8, "with", with_token_str)) fatal(
            "{}:{} expected 'with' but got '{s}'",
            .{fmtW(path), line_number, with_token_str},
        );
    }
    const with_key = blk: {
        const str = it.next() orelse fatal(
            "{}:{} 'replace' command missing arguments",
            .{fmtW(path), line_number}
        );
        break :blk parseKey(str) orelse fatal(
            "{}:{} invalid key '{s}'",
            .{fmtW(path), line_number, str}
        );
    };
    if (it.next()) |_| fatal(
        "{}:{} 'replace' command has too many arguments",
        .{fmtW(path), line_number}
    );


    return .{
        .query = .{
            .key = replace_key,
            .source_kind = source.kind,
            .source_extra = source.extra,
        },
        .action = .{ .replace = with_key },
    };
}

fn parseKey(s: []const u8) ?Key {
    const info: struct {
        num: []const u8,
        extended: bool,
    } = if (std.mem.endsWith(u8, s, "e")) .{
        .num = s[0..s.len-1], .extended = true
    } else .{
        .num = s, .extended = false
    };
    return .{
        .scancode = std.fmt.parseInt(u16, info.num, 10) catch return null,
        .extended = info.extended,
    };
}

const expected_source = "'hardware' or 'software' with optional :NUMBER suffix";
fn parseSourceQuery(s: []const u8) ?struct {
    kind: ?SourceKind,
    extra: ?usize,
} {
    if (std.mem.eql(u8, s, "hardware"))
        return .{ .kind = .hardware, .extra = null };
    return null;
}

fn skipWhitespace(s: []const u8, start: usize) usize {
    for (s[start..], start..) |c, i| {
        if (!std.ascii.isWhitespace(c)) return i;
    }
    return s.len;
}

const Query = struct {
    key: Key,
    source_kind: ?SourceKind,
    source_extra: ?usize,
    pub fn matches(self: Query, key: Key, source: Source) bool {
        if (!self.key.matches(key))
            return false;
        if (self.source_kind) |kind| {
            if (kind != source.kind)
                return false;
        }
        if (self.source_extra) |extra| {
            if (extra != source.extra)
                return false;
        }
        return true;
    }
};
const Action = union(enum) {
    drop,
    replace: Key,
    pub fn execute(self: Action, state: KeyState, key: Key, source: Source) OnKeyResult {
        switch (self) {
            .drop => return .drop,
            .replace => |replace| switch (sendInputKeyboard(state, replace)) {
                .NO_ERROR => {
                    addEvent(.{ .replace = .{
                        .state = state,
                        .key_original = key,
                        .source = source,
                        .key_new = replace,
                    }});
                    return .drop;
                },
                else => |ec| {
                    // TODO: addEvent instead of log
                    std.log.err("remap error {}, propagating old", .{ec});
                    return .propagate;
                },
            },
        }
    }
};

const key_control_left: Key = .{ .scancode = 29, .extended = false };
const key_control_right: Key = .{ .scancode = 29, .extended = true };
const key_win_left: Key = .{ .scancode = 91, .extended =true };

const Instruction = struct {
    query: Query,
    action: Action,
};
var global_instructions: []Instruction = &.{};

const our_extra_info = 0x3f968859;

fn sendInputKeyboard(
    state: KeyState,
    key: Key,
) win32.WIN32_ERROR {
    var inputs = [_]win32.INPUT{ .{
        .type = .KEYBOARD,
        .Anonymous = .{ .ki = .{
            // ignored because SCANCODE = 1
            .wVk = .LBUTTON,
            .wScan = key.scancode,
            .dwFlags = .{
                .EXTENDEDKEY = if (key.extended) 1 else 0,
                .KEYUP = switch (state) { .down => 0, .up => 1 },
                .UNICODE = 0,
                .SCANCODE = 1,
            },
            .time = 0,
            .dwExtraInfo = our_extra_info,
        }},
    } };
    if (1 != win32.SendInput(1, &inputs, @sizeOf(win32.INPUT)))
        return win32.GetLastError();
    return .NO_ERROR;
}

const known_flags: win32.KBDLLHOOKSTRUCT_FLAGS = .{
    .EXTENDED = 1,
    .LOWER_IL_INJECTED = 1,
    .INJECTED = 1,
    .ALTDOWN = 1,
    .UP = 1,
};
const unknown_flags_mask: u32 = ~@as(u32, @bitCast(known_flags));

const SourceKind = enum { hardware, software };
const Source = struct {
    kind: SourceKind,
    extra: usize,
    pub fn isKeymap(self: Source) bool {
        return self.kind == .software and self.extra == our_extra_info;
    }
    pub fn format(
        self: Source,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        if (self.isKeymap()) {
            try writer.writeAll("keymap");
        } else {
            try writer.writeAll(@tagName(self.kind));
            if (self.extra != 0) {
                try writer.print(":{}", .{self.extra});
            }
        }
    }
};

fn sourceFromHook(hook: win32.KBDLLHOOKSTRUCT) Source {
    return .{
        .kind = if (hook.flags.INJECTED == 1) .software else .hardware,
        .extra = hook.dwExtraInfo,
    };
}

const FmtHookStruct = struct {
    s: *const win32.KBDLLHOOKSTRUCT,
    pub fn format(
        self: FmtHookStruct,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        _ = fmt;
        _ = options;
        const source = sourceFromHook(self.s.*);
        try writer.print(
            "{}{s} from {} (virtual key {})",
            .{
                self.s.scanCode,
                @as([]const u8, if (self.s.flags.EXTENDED == 1) "e" else ""),
                source,
                virtualkey.fmtName(self.s.vkCode),
                //unknown_flags_mask & @as(u32, @bitCast(self.s.flags)),
            },
        );
    }
};
fn fmtHookStruct(s: *const win32.KBDLLHOOKSTRUCT) FmtHookStruct {
    return FmtHookStruct{ .s = s };
}

const Key = struct {
    scancode: u16,
    extended: bool,
    pub fn matches(self: Key, other: Key) bool {
        return
            self.scancode == other.scancode and
            self.extended == other.extended;
    }
    pub fn format(
        self: Key,
        comptime fmt: []const u8,
        options: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        if (fmt.len != 0) @compileError("unsupported format specifier: " ++ fmt);
        var buf: [30]u8 = undefined;
        const suffix: []const u8 = if (self.extended) "e" else "";
        const s = std.fmt.bufPrint(&buf, "{}{s}", .{self.scancode, suffix}) catch unreachable;
        try std.fmt.formatType(s, "s", options, writer, 1);
    }
};

const Event = union(enum) {
    replace: struct {
        state: KeyState,
        key_original: Key,
        source: Source,
        key_new: Key,
    },
    // we received an unexpected wparam value in our hook proc
    unexpected_wparam: win32.WPARAM,
    mismatched_key_state: struct {
        state: KeyState,
        data: win32.KBDLLHOOKSTRUCT,
    },
};
fn addEvent(event: Event) void {
    // TODO: we could do other things here besides log
    switch (event) {
        .replace => |r| {
            std.log.info(
                "{s} replace {} from {} with {}",
                .{@tagName(r.state), r.key_original, r.source, r.key_new},
            );
        },
        .unexpected_wparam => |wparam| {
            std.log.err("hook procedure received unexpected wparam {}", .{wparam});
        },
        .mismatched_key_state => |e| {
            std.log.err("keystate mismatch {s} {}", .{@tagName(e.state), fmtHookStruct(&e.data)});
        },
    }
}

fn hookproc(
    code: i32,
    wparam: win32.WPARAM,
    lparam: win32.LPARAM
) callconv(@import("std").os.windows.WINAPI) win32.LRESULT {
    if (code == win32.HC_ACTION) {
        switch (on_key(wparam, lparam)) {
            .propagate => {},
            .drop => return 1,
        }
    }
    return win32.CallNextHookEx(null, code, wparam, lparam);
}

const KeyState = enum { up, down };

const OnKeyResult = enum { propagate, drop };
fn on_key(
    wparam: win32.WPARAM,
    lparam: win32.LPARAM,
) OnKeyResult {
    const state: KeyState = switch (wparam) {
        win32.WM_KEYDOWN    => .down,
        win32.WM_KEYUP      => .up,
        win32.WM_SYSKEYDOWN => .down,
        win32.WM_SYSKEYUP   => .up,
        else => {
            addEvent(.{ .unexpected_wparam = wparam });
            return .propagate;
        },
    };
    const data: *win32.KBDLLHOOKSTRUCT = @ptrFromInt(@as(usize, @bitCast(lparam)));

    {
        const flag_key_state: KeyState = if (data.flags.UP == 1) .up else .down;
        if (flag_key_state != state) {
            addEvent(.{ .mismatched_key_state = .{
                .state = state,
                .data = data.*,
            }});
            return .propagate;
        }
    }

    switch (global.mode) {
        .log => {
            const kind: []const u8 = switch (state) { .down => "down", .up => "up  " };
            std.io.getStdOut().writer().print("{s} {}\n", .{kind, fmtHookStruct(data)}) catch |err| fatal(
                "print to stdout failed, error={s}", .{@errorName(err)}
            );
        },
        .run => {
            const is_feedback = (data.dwExtraInfo == our_extra_info);
            if (is_feedback) {
                return .propagate;
            }
            const key = Key{
                .scancode = @intCast(0xffff & data.scanCode),
                .extended = if (data.flags.EXTENDED == 1) true else false,
            };
            if (key.scancode != data.scanCode) {
                // we got a scancode larger than 16 bits which we can't inject because
                // SendInput only takes a u16 scancode so we'll just ignore this event
                return .propagate;
            }
            const source = sourceFromHook(data.*);
            for (global_instructions) |instruction| {
                if (instruction.query.matches(key, source)) {
                    return instruction.action.execute(state, key, source);
                }
            }
        }
    }

    return .propagate;
}

fn lastErrorName() []const u8 {
    return @tagName(win32.GetLastError());
}
fn closeHandle(handle: win32.HANDLE) void {
    if (0 == win32.CloseHandle(handle)) std.debug.panic(
        "CloseHandle failed, error={s}", .{lastErrorName()}
    );
}

const INFINITE: u32 = 0xffffffff;

const InterprocessLock = struct {
    mutex: win32.HANDLE,
    pub fn init(name: [*:0]const u16) InterprocessLock {
        const mutex = win32.CreateMutexW(null, 0, name) orelse fatal(
            "CreateMutex failed, error={s}", .{lastErrorName()}
        );
        errdefer closeHandle(mutex);

        switch (win32.WaitForSingleObject(mutex, INFINITE)) {
            @intFromEnum(win32.WAIT_OBJECT_0) => {},
            else => |result| fatal(
                "failed to acquire shared mutex, result={}, error={s}",
                .{ result, lastErrorName() },
            ),
        }
        return .{ .mutex = mutex };
    }
    pub fn deinit(self: InterprocessLock) void {
        if (0 == win32.ReleaseMutex(self.mutex)) fatal(
            "ReleaseMutex failed, error={s}", .{lastErrorName()}
        );
        closeHandle(self.mutex);
    }
};

// we only need 4 bytes of memory to save the pid but we reserve
// more in case we need more shared memory in the future
const shared_mem_len = 80;
const Create = enum { newly_created, already_exists };
const SharedMem = struct {
    create: Create,
    mapping: win32.HANDLE,
    mem: *[shared_mem_len]u8,
    pub fn init(name: [*:0]const u16) SharedMem {
        win32.SetLastError(.NO_ERROR);
        const mapping = win32.CreateFileMappingW(
            win32.INVALID_HANDLE_VALUE, // use the paging file
            null,
            win32.PAGE_READWRITE,
            0,
            shared_mem_len,
            name,
        ) orelse fatal("CreateFileMapping failed, error={s}", .{@tagName(win32.GetLastError())});
        errdefer {
            if (0 == win32.CloseHandle(mapping)) fatal(
                "CloseHandle for mapping failed, error={s}", .{@tagName(win32.GetLastError())}
            );
        }

        const create: Create = switch (win32.GetLastError()) {
            .NO_ERROR => .newly_created,
            .ERROR_ALREADY_EXISTS => .already_exists,
            else => |e| fatal("CreateFileMapping returned unexpected error {s}", .{@tagName(e)}),
        };

        const mem = win32.MapViewOfFile(
            mapping,
            win32.FILE_MAP_ALL_ACCESS,
            0, 0,
            shared_mem_len,
        ) orelse fatal("MapViewOfFile failed, error={s}", .{@tagName(win32.GetLastError())});
        return .{
            .create = create,
            .mapping = mapping,
            .mem = @as([*]u8, @ptrCast(mem))[0 .. shared_mem_len],
        };
    }
    pub fn deinit(self: SharedMem) void {
        if (0 == win32.UnmapViewOfFile(self.mem.ptr)) fatal(
            "UnmapViewOfFile failed, error={s}", .{lastErrorName()}
        );
        if (0 == win32.CloseHandle(self.handle)) fatal(
            "CloseHandle for file mapping failed, error={s}", .{lastErrorName()}
        );
    }
};

fn getConfigPath(allocator: std.mem.Allocator) ![:0]u16 {
    const appdata_dir = std.mem.span(alloc_appdata_dir(.create));
    defer free_appdata_dir(appdata_dir.ptr);
    return try std.mem.concatWithSentinel(
        allocator,
        u16,
        &.{ appdata_dir, win32.L("\\keymap.txt" ) },
        0,
    );
}

fn free_appdata_dir(dir: [*:0]u16) void {
    win32.CoTaskMemFree(dir);
}

fn alloc_appdata_dir(create_option: enum { nocreate, create }) [*:0]u16 {
    var dir: ?[*:0]u16 = undefined;
    {
        const hresult = win32.SHGetKnownFolderPath(
            &win32.FOLDERID_LocalAppData,
            switch (create_option) {
                .nocreate => 0,
                .create => @intFromEnum(win32.KF_FLAG_CREATE),
            },
            null,
            &dir,
        );
        if (hresult != win32.S_OK)
            // TODO: we could fallback to using %APPDATA%
            fatal("SHGetKnownFolderPath for LocalAppData failed. (hresult=0x{x})", .{hresult});
    }
    return dir.?;
}
