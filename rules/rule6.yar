rule maindll_mutex
{
   
    meta:
        author = "Matt Brooks, @cmatthewbrooks"
        desc = "Matches on the maindll mutex"
        ref = "https://citizenlab.org/2016/04/between-hong-kong-and-burma/"
        
    strings:
        $mutex = "h31415927tttt"
        
    condition:
        //MZ header  //PE signature
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550 and $mutex
}
