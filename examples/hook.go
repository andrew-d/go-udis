package main

import (
    "fmt"
    "github.com/andrew-d/go-udis"
)

func main() {
    u := udis.New()
    defer u.Close()

    u.SetMode(32)
    u.SetSyntax(udis.UD_SYN_INTEL)

    var i int = 0
    u.SetInputHook(func(ud *udis.Udis) int {
        i += 1
        if i <= 5 {
            return 0x90     // nop
        }
        return -1
    })

    for u.Disassemble() {
        fmt.Println(u.InstructionAsm())
    }
}
