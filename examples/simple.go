package main

import (
    "fmt"
    "github.com/andrew-d/go-udis"
)

func main() {
    fmt.Printf("Udis Test\n----------\n")

    u := udis.NewUdis()
    u.SetMode(32)
    u.SetSyntax(udis.UD_SYN_INTEL)
    u.SetReadFromStdin()

    for u.Disassemble() {
        fmt.Println(u.InstructionAsm())
    }
}
