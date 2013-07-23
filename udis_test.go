package udis

import (
    "bytes"
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
