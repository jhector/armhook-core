# armhook-core
Core of Linux hooking engine for ARM architecture

## Shared Library Injection
The engine contains a linker which is used to inject a shared library into a given process.
It provides minimal functionality and uses `ptrace` to load and link the library in the target process.

The implemented linker can't inject a library whose dependancies are not already present in the target process memory.
Kepp that in mind when developing your hook handlers.

## Hook Mechanism
A **trampoline** is used as an intermediate stop for each hook. It finds the correct hook handler based on the return address given by the `lr` register when the **trampoline** is called. 

It is also responsible to construct the argument for the hook handler and handle the return to the original function or the caller based on the return value of the hook handler. The signature of a hook handler funciton and the argument structure is shown below:

```C
struct hook_data {
	uint32_t cpsr;
	uint32_t r0, r1, r2, r3;
	uint32_t *sp;
	uint32_t skip_lr;
};

typedef int8_t (*hook_handler)(struct hook_data*);
```

The orginal function prolog is saved and used when the handler returns `1` meaning that the original function should be continued. To modify the arguments to the original function, it is only required to modify the fields inside the argument struct.
The **trampoline** will restore the register content based on the values given in the struct before executing the saved prolog.

Due to the changed location of the prolog instructions, continuation of the original function may not work properly.
This is the case when the prolog contains a PC-relative instruction or a relative branch.
Currently the engine does not detect these kind of instructions, so it is up to the user to determine whether or not the original function can be continued without breaking the application.

The size of the detour for ARM mode is 12 bytes and for Thumb mode 8 bytes.

An instruction decoder is used to avoid breaking instructions by only saving part of them.

## Configuration
A JSON file is used to configure the hooks that should be inserted. An example configuration is shown below:

```JSON
{
    "hooks": [
        {
            "relative": 1141,
            "handler": "handler_get_value",
            "base": "example_target",
            "library": "/data/libhandler.so"
        }
    ],
    "settings": {
        "libc": "libc.so",
        "helper": "/data/libarmhook.so"
    }
}
```

An object in the `hooks` array represents one active hook. It is possible to specify either an `absolute` or `relative` value where in memory the hook should be inserted. If `relative` is specified the hook will be inserted at the given offset relative to the base specified in `base` which is the name of a segment in memory as it can be found in `/proc/<pid>/maps`. For example, in the above configuration, and the following `/proc/<pid>/maps` content:

```
b6fed000-b6fee000 r-xp 00000000 b3:0c 110        /system/bin/example_target
b6fee000-b6fef000 r--p 00000000 b3:0c 110        /system/bin/example_target
```

the base address of `example_target` serves as the base for the relative hook.
So the hook would be inserted at `0xb6fed000 + 1141 = 0xb6fed475`. It is important to note that the value given in the configuration is used to determine the instruction mode used for that function. If the LSB is set, then the engine assumes that the function is called in Thumb mode.

`libc` in the `settings` section specifies the libc name as it appears in `/proc/<pid>/maps`, it is used to resolve functions from libc which are called during the injection process.

`heler` in the `settings` sections specifies the full path to the helper library that is build as part of the engine.
This library will be injected into the target process as well and is used to set up the hook mappings and copy the trampoline at its location.
