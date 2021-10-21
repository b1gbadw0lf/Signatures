rule vibecheck
{
    meta:
        author = "John Wolfram"
        date_created = "2021-10-19"
        description = "Yara rule to detect NIM-based BEACON loader used by UNC2602"

    strings:
        $a1 = "injectCreateRemoteThread" fullword ascii
        $a2 = "NimSyscalls" fullword ascii

        $s1 = "processID" fullword ascii
        $s2 = "suspend" fullword ascii
        $s3 = "osproc.nim" fullword ascii
        $s4 = "VirtualAllocEx" fullword ascii

    condition:
        uint16(0) == 0x5a4d and uint32(uint32(0x3C)) == 0x00004550 and filesize <850KB and (1 of ($a*) and (3 of ($s*)))
}
