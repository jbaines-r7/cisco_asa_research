rule Unsigned_SFR_Package {

    meta:
        description = "Unsigned FirePOWER Services Software for ASA PAckage"

    strings:
        $magic = "\xc0\xc5"
        $ignoreit = "ignoreit"
        $checksum = "checksum"
        $data = "\x01data"
        $key = "\x03key"

    condition:
        $magic at 0 and $ignoreit at 10 and $checksum and $data and not $key
}

