package udis

/*
#include <stdlib.h>
#include <udis86.h>
#cgo LDFLAGS: -ludis86

extern void setup_input_hook(struct ud*, void*);
extern void setup_sym_resolver(struct ud*, void*);
extern void free_opaque_data(struct ud*);
*/
import "C"

import "unsafe"

// We want to be able to set various callbacks.  For this to work, we need to
// pass a callback function to udis86, which it will then call to perform work
// such as obtaining each byte, or resolving a symbol.  For this to work, we
// need to be able to call into Go code from C, which is tricky to accomplish.
// We do it by doing the following:
//      - We have some C code that sets an opaque pointer on the udis86 struct,
//        containing the function pointers that we want to save (at the time of
//        writing, for input hook and sym resolver).  The setup code will also
//        set the appropriate pointer to another C function (the "C callback").
//      - The "C callback" will then be called first.  It will obtain the
//        opaque pointer from the udis86 struct, and then use this to obtain
//        the appropriate function pointer.  However, we can't simply call this
//        function pointer.  So, we instead call an (exported) Go function,
//        passing the function pointer and all previous arguments along.
//      - The exported Go code will take the input pointer, and, if it's not
//        NULL, convert it to a Go function pointer, and then call it.  It will
//        also take care of marshalling the various C types to/from the built-
//        in Go types.  Eventually, the original callback will be called.
//
// In short, the flow looks like this:
//
//      udis86 --> C code --> Constant Go function --> Actual callback
//
// Another, final note: the map below is used to maintain a mapping between the
// udis86 structure and the Go wrapping structure.  It is inserted to whenever
// a callback is set, and cleared upon Close().  The purpose is to allow the
// callbacks to look up the Go structure and pass this to the user-provided
// callback function, rather than just a udis86 structure from C.

var udMap = make(map[unsafe.Pointer]*Udis)

//export goInputHookCallback
func goInputHookCallback(ud, ptr unsafe.Pointer) int {
    // Immediately EOF if there's no pointer specified.
    if ptr == nil {
        return -1
    }

    // Obtain the Udis struct.
    udObj, ok := udMap[ud]
    if !ok {
        // TODO: throw error?
        return -1
    }

    // Cast this pointer to a Go function (which it is), and then
    // call it to obtain the value.
    fn := (*func(*Udis) int)(ptr)
    return (*fn)(udObj)
}

//export goSymResolverCallback
func goSymResolverCallback(ud unsafe.Pointer, addr C.uint64_t,
                           offset *C.int64_t, ptr unsafe.Pointer) *C.char {
    // Immediately return nil if there's no callback - this does nothing, then.
    if ptr == nil {
        return nil
    }

    // Obtain the Udis struct.
    udObj, ok := udMap[ud]
    if !ok {
        // TODO: throw error?
        return nil
    }

    // Otherwise, cast this pointer to a Go function (which it is), and then
    // call it to obtain the value.
    fn := (*func(*Udis, uint64, *int64) string)(ptr)
    ret := (*fn)(udObj, uint64(addr), (*int64)(offset))

    // Convert the return value to a C string.
    c_ret := C.CString(ret)

    // Free the old last_symbol value.
    if udObj.last_symbol != nil {
        C.free(unsafe.Pointer(udObj.last_symbol))
    }

    // Store the new last symbol value and return it.
    udObj.last_symbol = c_ret
    return c_ret
}

// Set up the input hook.
func (u *Udis) SetInputHook(hook func(*Udis) int) {
    // Firstly, add to the map.
    udMap[unsafe.Pointer(u.udis)] = u

    // And then set the hook.
    C.setup_input_hook(u.udis, unsafe.Pointer(&hook))
}

// Set up the symbol resolver.
func (u *Udis) SetSymResolver(fn func(*Udis, uint64, *int64) string) {
    // Firstly, add to the map.
    udMap[unsafe.Pointer(u.udis)] = u

    // And then set the sym resolver function.
    C.setup_sym_resolver(u.udis, unsafe.Pointer(&fn))
}

// Cleans up after ourselves.
func (u *Udis) cleanupCallbacks() {
    // Remove our pointer from the map.
    delete(udMap, unsafe.Pointer(u.udis))

    // Cleanup the udis86 structure too.
    C.free_opaque_data(u.udis)

    // If there's a last symbol value, free it.
    if u.last_symbol != nil {
        C.free(unsafe.Pointer(u.last_symbol))
    }
}
