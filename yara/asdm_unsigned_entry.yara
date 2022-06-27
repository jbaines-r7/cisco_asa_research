rule ASDM_Log_Unsigned_Entry {

    meta:
        description = "ASDM Log Unsigned Entry IOC"
        author = "Jacob Baines"

    strings:
        $magic = "Application Logging Started at"
        $local_launcher = "Local Launcher Version"
        $server_launcher = "Server Launcher Version"
        $sgz_loader = "invoking SGZ Loader"
        $unsigned = "SgzReader: unsigned entry "

    condition:
        $magic at 0 and $local_launcher and $server_launcher and $sgz_loader and $unsigned
}

