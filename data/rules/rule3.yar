rule WildcardExample
{
    strings:
        $hex_string = { E2 34 C8 FB }

    condition:
        $hex_string
}
