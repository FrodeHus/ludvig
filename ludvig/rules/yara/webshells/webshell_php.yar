rule PhpWebShell : php webshell {
    meta:
        description = "Finds PHP webshells"
        severity = "CRITICAL"
        id  = "LM0002"
    strings:
        $s0 = "fsockopen"
        $s1 = "pipe"
        $s2 = "proc_open"
    condition:
        all of them
}
