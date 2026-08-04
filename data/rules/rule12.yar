rule pe_string_at_offset
{
    meta:
        desc = "Runnable Windows PE with an ASCII string pinned at file offset 0x600"

    strings:
        $s = "aray_marker_2026"

    condition:
        // MZ header                   PE signature (indirect offset via e_lfanew)
        uint16(0) == 0x5A4D and
        uint32(uint32(0x3C)) == 0x00004550 and
        $s at 0x600
}
