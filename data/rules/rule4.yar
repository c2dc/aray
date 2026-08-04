rule rule2
{
    strings:
        $a = { E2 34 C8 FB }
        $b = "dummy2"

    condition:
        $a at 0x600 and $b
}
