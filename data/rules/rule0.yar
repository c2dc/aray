rule rule0
{
    strings:
        $a = "dummy1"

    condition:
        $a
}
