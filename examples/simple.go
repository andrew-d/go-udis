package main

import (
    "fmt"
    "github.com/andrew-d/go-udis"
)

func main() {
    fmt.Printf("Udis Test\n----------\n")

    u := udis.New()
    defer u.Close()
    u.SetMode(32)
    u.SetSyntax(udis.UD_SYN_INTEL)
    u.SetReadFromStdin()

    for u.Disassemble() {
        fmt.Println(u.InstructionAsm())
    }
}
