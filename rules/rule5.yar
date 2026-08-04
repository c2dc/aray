rule multi_offset
{
    strings:
        $a = "alpha"
        $b = "beta"

    condition:
        $a at 0x600 and $b at 0x800
}
