rule ASDM_Log_User_Pass {

    meta:
        description = "ASDM Log Entry Containing ASDM User and Password"
        author = "Jacob Baines"

    strings:
        $magic = "Application Logging Started at"
        $local_launcher = "Local Launcher Version"
        $server_launcher = "Server Launcher Version"
        $sgz_loader = "invoking SGZ Loader"
        $arglist = /argList=\[-codebase=[^,]+, -sgzTarget=com.cisco.nm.dice.loader.Loader, -dynApplet=com.cisco.pdm.PDMApplet, -dynArchives=pdm.sgz, -errorUrl=error.html, -cacheDir=[^,]+, -appMode=true, -username="[^"]+", -password="[^"]+"\]/

    condition:
        $magic at 0 and $local_launcher and $server_launcher and $sgz_loader and $arglist
}

