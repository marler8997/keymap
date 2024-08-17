# keymap

Keymap allows you to remap keys on Windows.

Copy `keymap.exe` to somewhere in your `PATH` and manage it from the command-line:

```batch
keymap status     # print the current status
keymap enable     # enable the keymap
keymap pause      # temporarily disable the keymap
keymap log        # log all keyboard events to the current console
```

The configuration file is located at `%localappdata%\keymap.txt`:

```
# keymap configuration file
#
# Syntax:
#
#     replace KEY from SOURCE with KEY
#
#     KEY    | NUMBER[e]
#     SOURCE | hardware[:NUMBER] | software[:NUMBER] | keymap
#
# Examples:
#     replace 29 from hardware with 91e
#
```

## Why keymap when there is PowerToys and AutoHotKey?

keymap allows you to limit remappings to specific sources. You can specify
that a remapping should only apply to inputs that come from hardware, software,
or even specific applications so long as those applications make use of the
"dwExtraInfo" field on their synthesized inputs.

Limiting remappings to hardware allows keymap to support custom keyboard layouts
that only apply to locally attached devices and bypass virtual inputs that come
from applications like remoting software.

# Windows Input Pipeline

There are 3 mechanisms to remap keys on Windows:

1. Keyboard Layouts
2. The Registry Scancode Map
3. Keyboard Hooks

### 1. Keyboard Layouts

Keyboard Layouts are meant to accomodate different languages. They are limited in that
they don't allow you to remap all the keys on the physical keyboard like Control/Alt/Tab/etc.
The benefit of a keyboard layout is Microsoft has builtin support for them. You can to create a
layout with the Microsoft Keyboard Layout Creator (MSKLC).

### 2. The Registry Scancode Map

This method involves writing an entry into the registry. The downside is it requires
you to sign out or restart to apply changes. Check out the "sharpkeys" utility if you'd
like to use this method: https://github.com/randyrants/sharpkeys

### 3. Keyboard Hooks

Keyboard hooks receive all keyboard events before they are passed to applications.
A hook can't modify an event that's in flight, but it can return a value that tells
the pipeline to "drop" the current event, at which point it can implement a remapping by
synthesizing a new input (via a function like `SendInput`). All hooks require a thread
to service them, so if that thread ends the hook is uninstalled.

This method is the most flexible in that it can remap any key, can be applied without
having to restart and can do anything in response to keyboard events, not just remappings.
This flexibility is why tools like PowerToys and AutoHotKey use this method.

# How to Build

Download/install zig version 0.0.13 [https://ziglang.org/download](https://ziglang.org/download/#release-0.13.0).

Run `zig build` and copy `zig-out\bin\keymap.exe` to a location in your `PATH`.
