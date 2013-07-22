package main

/*
#include <stdlib.h>
#include <udis86.h>
#cgo LDFLAGS: -ludis86

void c_ud_set_syntax(struct ud* u, void* func) {
    ud_set_syntax(u, (void (*)(struct ud*))func);
}

void* c_ud_translate_intel() {
    return &ud_translate_intel;
}

void* c_ud_translate_att() {
    return &ud_translate_att;
}
*/
import "C"

import (
    "fmt"
    "unsafe"
)

type Udis struct {
    udis    *C.struct_ud
}

const (
    UD_SYN_INTEL        = 1
    UD_SYN_ATT          = 2

    UD_VENDOR_ANY       = (uint)(C.UD_VENDOR_ANY)
    UD_VENDOR_INTEL     = (uint)(C.UD_VENDOR_INTEL)
    UD_VENDOR_AMD       = (uint)(C.UD_VENDOR_AMD)

    UD_OP_MEM           = (uint)(C.UD_OP_MEM)
)

func NewUdis() *Udis {
    s := &C.struct_ud{}
    C.ud_init(s)
    return &Udis{s}
}

func (u *Udis) SetMode(mode int) {
    C.ud_set_mode(u.udis, (C.uint8_t)(mode))
}

func (u *Udis) SetPC(pc uint64) {
    C.ud_set_pc(u.udis, (C.uint64_t)(pc))
}

func (u *Udis) SetVendor(vendor uint) {
    C.ud_set_vendor(u.udis, (C.unsigned)(vendor))
}

func (u *Udis) SetSyntax(syntax int) {
    var syn unsafe.Pointer

    switch syntax {
    case UD_SYN_INTEL:  syn = C.c_ud_translate_intel()
    case UD_SYN_ATT:    syn = C.c_ud_translate_att()
    default:            panic("bad syntax")
    }

    C.c_ud_set_syntax(u.udis, syn)
}

func (u *Udis) SetInputHook(hook func() int) {
    // This doesn't work.
    //C.ud_set_input_hook(u.udis, hook)
}

func (u *Udis) SetInputBuffer(buff []byte) {
    size := (C.size_t)(len(buff))
    ptr := (*C.uint8_t)(unsafe.Pointer(&buff[0]))
    C.ud_set_input_buffer(u.udis, ptr, size)
}

func (u *Udis) Disassemble() bool {
    ret := C.ud_disassemble(u.udis)
    return (uint)(ret) != 0
}

func (u *Udis) InstructionAsm() string {
    s := C.ud_insn_asm(u.udis)
    return C.GoString(s)
}

func (u *Udis) InstructionLen() int {
    return (int)(C.ud_insn_len(u.udis))
}

func (u *Udis) InstructionOffset() uint64 {
    return (uint64)(C.ud_insn_off(u.udis))
}

func (u *Udis) InstructionHex() string {
    s := C.ud_insn_hex(u.udis)
    return C.GoString(s)
}

func (u *Udis) InstructionBytes() []byte {
    l := u.InstructionLen()
    ptr := unsafe.Pointer(C.ud_insn_ptr(u.udis))
    return C.GoBytes(ptr, (C.int)(l))
}

// TODO: fill this out
type UdisOperand struct {

}

func (u *Udis) InstructionOperand(index int) (*UdisOperand, error) {
    return nil, nil
}

func (u *Udis) InstructionMnemonic() uint {
    return (uint)(u.udis.mnemonic)
}

func (u *Udis) InstructionMnemonicString() string {
    mn := u.InstructionMnemonic()
    s := C.ud_lookup_mnemonic((uint16)(mn))
    return C.GoString(s)
}

func main() {
    fmt.Printf("Udis Test\n\n")

    u := NewUdis()
    u.SetMode(32)
    u.SetSyntax(UD_SYN_INTEL)

    C.ud_set_input_file(u.udis, C.stdin)

    for u.Disassemble() {
        fmt.Println(u.InstructionAsm())
    }
}
