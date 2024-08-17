const std = @import("std");

pub fn isDirSep(char: u16) bool { return char == '\\' or char == '/'; }

pub fn basename(path: []const u16) []const u16 {
    std.debug.assert(path.len > 0);
    std.debug.assert(!isDirSep(path[path.len-1]));
    var end = path.len - 1;
    while (true) : (end -= 1) {
        if (end == 0) return path;
        if (isDirSep(path[end])) return path[end + 1..];
    }
}

pub fn dirname(path: []const u16) ?[]const u16 {
    std.debug.assert(path.len > 0);
    std.debug.assert(!isDirSep(path[path.len-1]));
    var end = path.len - 1;
    while (true) : (end -= 1) {
        if (end == 0) return null;
        if (isDirSep(path[end])) return path[0 .. end];
    }
}

