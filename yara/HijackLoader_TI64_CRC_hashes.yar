rule HijackLoader_TI64_CRC_hashes
{
    meta:
        description = "HijackLoader ti64 orchestrator CRC32 module constants"
        author      = "neso"
        reference   = "https://neso.re/posts/clickfix-x-hijackloader-part-2/"
        family      = "HijackLoader, IDATLoader, GHOSTPULSE"
        hash        = "a9d0b740d294db8b771f481bb84661188e56c209f52edba440e72b6ca047c6cb"
        tlp         = "white"
        version     = "1.0"

    strings:
        $crc32_poly             = { B7 1D C1 04 }
        $module_X64L            = { 3F 9F 5B CB }
        $module_COPYLIST        = { 0A 70 E7 1A }
        $module_SM              = { 45 21 22 D8 }
        $module_AVDATA          = { CA 83 B7 78 }
        $module_TinyCallProxy64 = { EA DC 15 55 }
        $module_CUSTOMINJECT    = { AE A6 18 B7 }

    condition:
        filesize < 500KB
        and $crc32_poly
        and 3 of ($module_*)
}