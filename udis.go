package udis

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
    "encoding/binary"
    "fmt"
    "unsafe"
)

type Udis struct {
    udis *C.struct_ud

    // Used to store the last symbol string that was converted.  Since we
    // replace this each time, we store the last value here and free it before
    // adding a new one.
    last_symbol *C.char
}

// Constants from #defines and such.
const (
    UD_SYN_NONE  = 0
    UD_SYN_INTEL = 1
    UD_SYN_ATT   = 2

    UD_VENDOR_ANY   = (uint32)(C.UD_VENDOR_ANY)
    UD_VENDOR_INTEL = (uint32)(C.UD_VENDOR_INTEL)
    UD_VENDOR_AMD   = (uint32)(C.UD_VENDOR_AMD)
)

// Constants that are straight from the C enum.
const (
    UD_NONE = (uint32)(C.UD_NONE)

    // 8-bit GPRs
    UD_R_AL   = (uint32)(C.UD_R_AL)
    UD_R_CL   = (uint32)(C.UD_R_CL)
    UD_R_DL   = (uint32)(C.UD_R_DL)
    UD_R_BL   = (uint32)(C.UD_R_BL)
    UD_R_AH   = (uint32)(C.UD_R_AH)
    UD_R_CH   = (uint32)(C.UD_R_CH)
    UD_R_DH   = (uint32)(C.UD_R_DH)
    UD_R_BH   = (uint32)(C.UD_R_BH)
    UD_R_SPL  = (uint32)(C.UD_R_SPL)
    UD_R_BPL  = (uint32)(C.UD_R_BPL)
    UD_R_SIL  = (uint32)(C.UD_R_SIL)
    UD_R_DIL  = (uint32)(C.UD_R_DIL)
    UD_R_R8B  = (uint32)(C.UD_R_R8B)
    UD_R_R9B  = (uint32)(C.UD_R_R9B)
    UD_R_R10B = (uint32)(C.UD_R_R10B)
    UD_R_R11B = (uint32)(C.UD_R_R11B)
    UD_R_R12B = (uint32)(C.UD_R_R12B)
    UD_R_R13B = (uint32)(C.UD_R_R13B)
    UD_R_R14B = (uint32)(C.UD_R_R14B)
    UD_R_R15B = (uint32)(C.UD_R_R15B)

    // 16-bit GPRs
    UD_R_AX   = (uint32)(C.UD_R_AX)
    UD_R_CX   = (uint32)(C.UD_R_CX)
    UD_R_DX   = (uint32)(C.UD_R_DX)
    UD_R_BX   = (uint32)(C.UD_R_BX)
    UD_R_SP   = (uint32)(C.UD_R_SP)
    UD_R_BP   = (uint32)(C.UD_R_BP)
    UD_R_SI   = (uint32)(C.UD_R_SI)
    UD_R_DI   = (uint32)(C.UD_R_DI)
    UD_R_R8W  = (uint32)(C.UD_R_R8W)
    UD_R_R9W  = (uint32)(C.UD_R_R9W)
    UD_R_R10W = (uint32)(C.UD_R_R10W)
    UD_R_R11W = (uint32)(C.UD_R_R11W)
    UD_R_R12W = (uint32)(C.UD_R_R12W)
    UD_R_R13W = (uint32)(C.UD_R_R13W)
    UD_R_R14W = (uint32)(C.UD_R_R14W)
    UD_R_R15W = (uint32)(C.UD_R_R15W)

    // 32-bit GPRs
    UD_R_EAX  = (uint32)(C.UD_R_EAX)
    UD_R_ECX  = (uint32)(C.UD_R_ECX)
    UD_R_EDX  = (uint32)(C.UD_R_EDX)
    UD_R_EBX  = (uint32)(C.UD_R_EBX)
    UD_R_ESP  = (uint32)(C.UD_R_ESP)
    UD_R_EBP  = (uint32)(C.UD_R_EBP)
    UD_R_ESI  = (uint32)(C.UD_R_ESI)
    UD_R_EDI  = (uint32)(C.UD_R_EDI)
    UD_R_R8D  = (uint32)(C.UD_R_R8D)
    UD_R_R9D  = (uint32)(C.UD_R_R9D)
    UD_R_R10D = (uint32)(C.UD_R_R10D)
    UD_R_R11D = (uint32)(C.UD_R_R11D)
    UD_R_R12D = (uint32)(C.UD_R_R12D)
    UD_R_R13D = (uint32)(C.UD_R_R13D)
    UD_R_R14D = (uint32)(C.UD_R_R14D)
    UD_R_R15D = (uint32)(C.UD_R_R15D)

    // 64-bit GPRs
    UD_R_RAX = (uint32)(C.UD_R_RAX)
    UD_R_RCX = (uint32)(C.UD_R_RCX)
    UD_R_RDX = (uint32)(C.UD_R_RDX)
    UD_R_RBX = (uint32)(C.UD_R_RBX)
    UD_R_RSP = (uint32)(C.UD_R_RSP)
    UD_R_RBP = (uint32)(C.UD_R_RBP)
    UD_R_RSI = (uint32)(C.UD_R_RSI)
    UD_R_RDI = (uint32)(C.UD_R_RDI)
    UD_R_R8  = (uint32)(C.UD_R_R8)
    UD_R_R9  = (uint32)(C.UD_R_R9)
    UD_R_R10 = (uint32)(C.UD_R_R10)
    UD_R_R11 = (uint32)(C.UD_R_R11)
    UD_R_R12 = (uint32)(C.UD_R_R12)
    UD_R_R13 = (uint32)(C.UD_R_R13)
    UD_R_R14 = (uint32)(C.UD_R_R14)
    UD_R_R15 = (uint32)(C.UD_R_R15)

    // Segement registers
    UD_R_ES = (uint32)(C.UD_R_ES)
    UD_R_CS = (uint32)(C.UD_R_CS)
    UD_R_SS = (uint32)(C.UD_R_SS)
    UD_R_DS = (uint32)(C.UD_R_DS)
    UD_R_FS = (uint32)(C.UD_R_FS)
    UD_R_GS = (uint32)(C.UD_R_GS)

    // Control registers
    UD_R_CR0  = (uint32)(C.UD_R_CR0)
    UD_R_CR1  = (uint32)(C.UD_R_CR1)
    UD_R_CR2  = (uint32)(C.UD_R_CR2)
    UD_R_CR3  = (uint32)(C.UD_R_CR3)
    UD_R_CR4  = (uint32)(C.UD_R_CR4)
    UD_R_CR5  = (uint32)(C.UD_R_CR5)
    UD_R_CR6  = (uint32)(C.UD_R_CR6)
    UD_R_CR7  = (uint32)(C.UD_R_CR7)
    UD_R_CR8  = (uint32)(C.UD_R_CR8)
    UD_R_CR9  = (uint32)(C.UD_R_CR9)
    UD_R_CR10 = (uint32)(C.UD_R_CR10)
    UD_R_CR11 = (uint32)(C.UD_R_CR11)
    UD_R_CR12 = (uint32)(C.UD_R_CR12)
    UD_R_CR13 = (uint32)(C.UD_R_CR13)
    UD_R_CR14 = (uint32)(C.UD_R_CR14)
    UD_R_CR15 = (uint32)(C.UD_R_CR15)

    // Debug registers
    UD_R_DR0  = (uint32)(C.UD_R_DR0)
    UD_R_DR1  = (uint32)(C.UD_R_DR1)
    UD_R_DR2  = (uint32)(C.UD_R_DR2)
    UD_R_DR3  = (uint32)(C.UD_R_DR3)
    UD_R_DR4  = (uint32)(C.UD_R_DR4)
    UD_R_DR5  = (uint32)(C.UD_R_DR5)
    UD_R_DR6  = (uint32)(C.UD_R_DR6)
    UD_R_DR7  = (uint32)(C.UD_R_DR7)
    UD_R_DR8  = (uint32)(C.UD_R_DR8)
    UD_R_DR9  = (uint32)(C.UD_R_DR9)
    UD_R_DR10 = (uint32)(C.UD_R_DR10)
    UD_R_DR11 = (uint32)(C.UD_R_DR11)
    UD_R_DR12 = (uint32)(C.UD_R_DR12)
    UD_R_DR13 = (uint32)(C.UD_R_DR13)
    UD_R_DR14 = (uint32)(C.UD_R_DR14)
    UD_R_DR15 = (uint32)(C.UD_R_DR15)

    // MMX registers
    UD_R_MM0 = (uint32)(C.UD_R_MM0)
    UD_R_MM1 = (uint32)(C.UD_R_MM1)
    UD_R_MM2 = (uint32)(C.UD_R_MM2)
    UD_R_MM3 = (uint32)(C.UD_R_MM3)
    UD_R_MM4 = (uint32)(C.UD_R_MM4)
    UD_R_MM5 = (uint32)(C.UD_R_MM5)
    UD_R_MM6 = (uint32)(C.UD_R_MM6)
    UD_R_MM7 = (uint32)(C.UD_R_MM7)

    // x87 registers
    UD_R_ST0 = (uint32)(C.UD_R_ST0)
    UD_R_ST1 = (uint32)(C.UD_R_ST1)
    UD_R_ST2 = (uint32)(C.UD_R_ST2)
    UD_R_ST3 = (uint32)(C.UD_R_ST3)
    UD_R_ST4 = (uint32)(C.UD_R_ST4)
    UD_R_ST5 = (uint32)(C.UD_R_ST5)
    UD_R_ST6 = (uint32)(C.UD_R_ST6)
    UD_R_ST7 = (uint32)(C.UD_R_ST7)

    // Extended multimedia registers
    UD_R_XMM0  = (uint32)(C.UD_R_XMM0)
    UD_R_XMM1  = (uint32)(C.UD_R_XMM1)
    UD_R_XMM2  = (uint32)(C.UD_R_XMM2)
    UD_R_XMM3  = (uint32)(C.UD_R_XMM3)
    UD_R_XMM4  = (uint32)(C.UD_R_XMM4)
    UD_R_XMM5  = (uint32)(C.UD_R_XMM5)
    UD_R_XMM6  = (uint32)(C.UD_R_XMM6)
    UD_R_XMM7  = (uint32)(C.UD_R_XMM7)
    UD_R_XMM8  = (uint32)(C.UD_R_XMM8)
    UD_R_XMM9  = (uint32)(C.UD_R_XMM9)
    UD_R_XMM10 = (uint32)(C.UD_R_XMM10)
    UD_R_XMM11 = (uint32)(C.UD_R_XMM11)
    UD_R_XMM12 = (uint32)(C.UD_R_XMM12)
    UD_R_XMM13 = (uint32)(C.UD_R_XMM13)
    UD_R_XMM14 = (uint32)(C.UD_R_XMM14)
    UD_R_XMM15 = (uint32)(C.UD_R_XMM15)

    UD_R_RIP = (uint32)(C.UD_R_RIP)

    // Operand types
    UD_OP_REG   = (uint32)(C.UD_OP_REG)
    UD_OP_MEM   = (uint32)(C.UD_OP_MEM)
    UD_OP_PTR   = (uint32)(C.UD_OP_PTR)
    UD_OP_IMM   = (uint32)(C.UD_OP_IMM)
    UD_OP_JIMM  = (uint32)(C.UD_OP_JIMM)
    UD_OP_CONST = (uint32)(C.UD_OP_CONST)
)

func New() *Udis {
    s := &C.struct_ud{}
    C.ud_init(s)
    return &Udis{s, nil}
}

func (u *Udis) Close() {
    // Cleanup any use of input hooks.
    u.cleanupCallbacks()
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
    case UD_SYN_NONE:
        syn = unsafe.Pointer(uintptr(0))
    case UD_SYN_INTEL:
        syn = C.c_ud_translate_intel()
    case UD_SYN_ATT:
        syn = C.c_ud_translate_att()
    default:
        panic("bad syntax")
    }

    C.c_ud_set_syntax(u.udis, syn)
}

func (u *Udis) SetInputBuffer(buff []byte) {
    size := (C.size_t)(len(buff))
    ptr := (*C.uint8_t)(unsafe.Pointer(&buff[0]))
    C.ud_set_input_buffer(u.udis, ptr, size)
}

func (u *Udis) SetReadFromStdin() {
    C.ud_set_input_file(u.udis, C.stdin)
}

func (u *Udis) Skip(num uint) {
    C.ud_input_skip(u.udis, (C.size_t)(num))
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

type PtrVal struct {
    Seg uint16
    Off uint32
}

type UdisOperand struct {
    Type   uint32
    Size   uint8
    Base   uint32
    Index  uint32
    Scale  uint8
    Offset uint8

    // This value can be one of any sized numeric type (int8, uint8, int16, etc.),
    // or a PtrVal type (from above).
    Lval interface{}
    Disp uint64
}

func (o *UdisOperand) ToString() string {
    return fmt.Sprintf("UdisOperand{%d, %d, %d, %d, %d, %d, %s, %d}",
        o.Type, o.Size, o.Base, o.Index, o.Scale, o.Offset,
        o.Lval, o.Disp)
}

func (u *Udis) InstructionOperands() []UdisOperand {
    var ret []UdisOperand

    n := C.uint(0)
    for {
        ptr := C.ud_insn_opr(u.udis, n)
        if ptr == nil {
            break
        }

        // The name of the first field is "type", which is a reserved
        // keyword in Go.  So, we resort to a dirty hack - since the
        // structure pointer will not align the first member, we just
        // typecast (unsafely) to a *uint32, and then dereference it.
        type_val := *(*uint32)(unsafe.Pointer(ptr))

        // Decode the value of lval.
        var lval interface{}

        // Currently an assumption: always running on little-endian
        // systems.  Probably a giant hack.
        var NativeEndian = binary.LittleEndian

        // Helper functions that, given a size, will extract the appropriate
        // bits from ptr.lval.
        extract_signed := func(size uint) {
            switch size {
            case 8:
                lval = int8(ptr.lval[0])
            case 16:
                lval = int16(NativeEndian.Uint16(ptr.lval[:]))
            case 32:
                lval = int32(NativeEndian.Uint32(ptr.lval[:]))
            case 64:
                lval = int64(NativeEndian.Uint64(ptr.lval[:]))
            default:
                panic("unknown value for ptr.offset!")
            }
        }

        extract_unsigned := func(size uint) {
            switch size {
            case 8:
                lval = int8(ptr.lval[0])
            case 16:
                lval = NativeEndian.Uint16(ptr.lval[:])
            case 32:
                lval = NativeEndian.Uint32(ptr.lval[:])
            case 64:
                lval = NativeEndian.Uint64(ptr.lval[:])
            default:
                panic("unknown value for ptr.offset!")
            }
        }

        switch type_val {
        case UD_OP_MEM:
            // We only have an lval if the offset is non-zero.
            extract_signed(uint(ptr.offset))

        case UD_OP_PTR:
            // The value is a segment:offset pointer.  It's stored as the following:
            // struct {
            //     uint16_t seg;
            //     uint32_t off;
            // } ptr;
            //
            // Thus, we can just read manually.
            lval = PtrVal{
                NativeEndian.Uint16(ptr.lval[0:2]),
                NativeEndian.Uint32(ptr.lval[2:]),
            }

        case UD_OP_IMM:
            // The value is an immediate value.  The size of the value is given
            // in ptr.size.
            extract_unsigned(uint(ptr.size))

        case UD_OP_JIMM:
            // An Immediate operand to a branch instruction - note that these are
            // these are relative offsets.
            extract_signed(uint(ptr.size))

        case UD_OP_CONST:
            // Implicit constant operand
            extract_unsigned(uint(ptr.size))

        case UD_OP_REG:
            // No lval, so zero-initialize it.
            lval = uint8(0)

        default:
            panic("unknown value for ptr.type")
        }

        curr := UdisOperand{
            type_val,
            uint8(ptr.size),
            uint32(ptr.base),
            uint32(ptr.index),
            uint8(ptr.scale),
            uint8(ptr.offset),
            lval,
            uint64(ptr.disp),
        }

        ret = append(ret, curr)

        n += 1
    }

    return ret
}

func (u *Udis) InstructionMnemonic() uint {
    return (uint)(u.udis.mnemonic)
}

func (u *Udis) InstructionMnemonicString() string {
    mn := u.InstructionMnemonic()
    s := C.ud_lookup_mnemonic((uint16)(mn))
    return C.GoString(s)
}
