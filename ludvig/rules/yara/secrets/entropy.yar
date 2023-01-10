import "math"
rule PossibleSecret : high_entropy secret{
    meta:
        description = "Detects possible secret based on high entropy - may cause many false positives"
        severity = "LOW"
    strings:
        $s = /[\w\.\-_~@!#()[\]%${}]{12,}/ nocase ascii wide fullword
    condition:
        math.entropy(@s,!s) > 4.9
}
