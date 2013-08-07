package udis

import (
    "fmt"
)

func ExampleUdis_SetReadFromStdin() {
    u := New()
    defer u.Close()

    u.SetMode(32)
    u.SetSyntax(UD_SYN_INTEL)
    u.SetReadFromStdin()

    for u.Disassemble() {
        fmt.Println(u.InstructionAsm())
    }
}

func ExampleUdis_SetInputHook() {
    u := New()
    defer u.Close()

    u.SetMode(32)
    u.SetSyntax(UD_SYN_INTEL)

    var i int = 0
    u.SetInputHook(func(ud *Udis) int {
        i += 1
        if i <= 5 {
            return 0x90     // nop
        }
        return -1
    })

    for u.Disassemble() {
        fmt.Println(u.InstructionAsm())
    }

    // Output:
    // nop
    // nop
    // nop
    // nop
    // nop
}

func ExampleUdis_SetInputBuffer() {
    u := New()
    defer u.Close()

    u.SetMode(32)
    u.SetSyntax(UD_SYN_INTEL)
    u.SetInputBuffer([]byte{0x54, 0x56, 0x90})

    for u.Disassemble() {
        fmt.Println(u.InstructionAsm())
    }

    // Output:
    // push esp
    // push esi
    // nop
}
