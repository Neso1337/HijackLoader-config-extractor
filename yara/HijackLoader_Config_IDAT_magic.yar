rule HijackLoader_Config_IDAT_magic
{
    meta:
        description = "HijackLoader encrypted configuration dropped to disk by the MSI installer"
        author = "neso"
        reference = "https://neso.re/posts/clickfix-x-hijackloader-Part2" 
        family = "HijackLoader, IDATLoader, GHOSTPULSE"
        hash = "ff1a2dcfdca25561b587bfa06214d70c85bcb802c5e5e7397dc977e1c5c20815"
        tlp = "white"
        version = "1.0"

    strings:
        $idat_magic_marker = {49 44 41 54 C6 A5 79 EA}

    condition:
       $idat_magic_marker
}