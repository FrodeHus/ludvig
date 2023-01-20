
rule CompressedFile {
    meta:
        description = "Detects compressed files (known formats)"
        type = "compressed_file"
        handler = "TBD"
        strings:
                $zip = { 04 03 4b 50 }
                $gzip = { 1f 8b 08 }
                $bzip = { 42 5a }
                $z = { 1f 9d }
                $pkzip = { 50 4b 03 04 }
                $tar_posix = { 75 73 74 61  }

        condition:
                (for any of ($gzip, $zip, $bzip, $z, $pkzip) : ($ at 0)) or ($tar_posix)
}
