package udis

import (
    "bytes"
    "fmt"
    "testing"
)

func setupDisasm(code []byte, mode, syntax int) *Udis {
    u := New()

    u.SetMode(mode)
    u.SetSyntax(syntax)
    u.SetInputBuffer(code)

    return u
}

func TestSimpleDisasm(t *testing.T) {
    code := []byte{
        0x65, 0x67, 0x89, 0x87, 0x76, 0x65, // mov [gs:bx+0x6576], eax
        0x54,       // push esp
        0x56,       // push esi
        0x78, 0x89, // js 0x93
        0x09, 0x00, // or [eax], eax
        0x87, // fragment
    }
    expected := []string{
        "mov [gs:bx+0x6576], eax",
        "push esp",
        "push esi",
        "js 0xffffff93",
        "or [eax], eax",
        "invalid",
    }

    u := setupDisasm(code, 32, UD_SYN_INTEL)

    var idx int
    for u.Disassemble() {
        actual := u.InstructionAsm()
        expect := expected[idx]

        if actual != expect {
            t.Errorf("Actual != expected: '%s' != '%s'\n", actual, expect)
        }

        idx++
    }
}

func TestInstructionHex(t *testing.T) {
    code := []byte{
        0x65, 0x67, 0x89, 0x87, 0x76, 0x65, // mov [gs:bx+0x6576], eax
        0x54, // push esp
    }
    hex := []string{
        "656789877665",
        "54",
    }

    u := setupDisasm(code, 32, UD_SYN_INTEL)

    var idx int
    for u.Disassemble() {
        actual := u.InstructionHex()
        expect := hex[idx]

        if actual != expect {
            t.Errorf("Actual != expected: '%s' != '%s'\n", actual, expect)
        }

        idx++
    }
}

func TestInstructionBytes(t *testing.T) {
    code := []byte{
        0x65, 0x67, 0x89, 0x87, 0x76, 0x65, // mov [gs:bx+0x6576], eax
        0x54, // push esp
    }
    ins := [][]byte{
        {0x65, 0x67, 0x89, 0x87, 0x76, 0x65}, // mov [gs:bx+0x6576], eax
        {0x54}, // push esp
    }

    u := setupDisasm(code, 32, UD_SYN_INTEL)

    var idx int
    for u.Disassemble() {
        actual := u.InstructionBytes()
        expect := ins[idx]

        if !bytes.Equal(actual, expect) {
            t.Errorf("Actual != expected: '%s' != '%s'\n", actual, expect)
        }

        idx++
    }
}

func diffOperands(op1, op2 UdisOperand) string {
    var details string

    if op1.Type != op2.Type {
        details += fmt.Sprintf("Type: %d != %d\n", op1.Type, op2.Type)
    }
    if op1.Size != op2.Size {
        details += fmt.Sprintf("Size: %d != %d\n", op1.Size, op2.Size)
    }
    if op1.Base != op2.Base {
        details += fmt.Sprintf("Base: %d != %d\n", op1.Base, op2.Base)
    }
    if op1.Index != op2.Index {
        details += fmt.Sprintf("Index: %d != %d\n", op1.Index, op2.Index)
    }
    if op1.Scale != op2.Scale {
        details += fmt.Sprintf("Scale: %d != %d\n", op1.Scale, op2.Scale)
    }
    if op1.Offset != op2.Offset {
        details += fmt.Sprintf("Offset: %d != %d\n", op1.Offset, op2.Offset)
    }
    if op1.Lval != op2.Lval {
        details += fmt.Sprintf("Lval: %s != %s\n", op1.Lval, op2.Lval)
    }
    if op1.Disp != op2.Disp {
        details += fmt.Sprintf("Disp: %d != %d\n", op1.Disp, op2.Disp)
    }

    return details
}

func TestInstructionOperands(t *testing.T) {
    code := [][]byte{
        {0x65, 0x67, 0x89, 0x87, 0x76, 0x65}, // mov [gs:bx+0x6576], eax
        {0x90}, // nop
    }
    ops := [][]UdisOperand{
        {
            UdisOperand{UD_OP_MEM, 32, UD_R_BX, 0, 0, 16, int16(0x6576), 0},
            UdisOperand{UD_OP_REG, 32, UD_R_EAX, 0, 0, 0, uint8(0), 0},
        },
        {},
    }

    for insn, v := range code {
        u := setupDisasm(v, 32, UD_SYN_INTEL)

        u.Disassemble()
        actual := u.InstructionOperands()
        expected := ops[insn]

        // Compare lengths.
        if len(expected) != len(actual) {
            t.Errorf("Instruction %d, invalid lengths: expected %d, got %d\n", insn+1, len(expected), len(actual))
        }

        // Compare operands
        for i := 0; i < len(expected); i++ {
            if actual[i] != expected[i] {
                details := fmt.Sprintf("Instruction %d, operand %d not equal (actual != expected):\n", insn+1, i)
                details += diffOperands(actual[i], expected[i])
                t.Errorf(details)
            }
        }
    }
}
