rule rule2
{
    strings:
        $a = "dummy1"
        $b = "dummy2"

    condition:
        $a at 0x600 and $b
}
