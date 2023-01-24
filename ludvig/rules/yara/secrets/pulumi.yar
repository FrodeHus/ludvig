rule PulumiApiToken : pulumi secret {
    meta:
        description = "Detects a Pulumi API token"
        severity = "CRITICAL"
        id = "LS0013"

    strings:
        $ = /pul-[a-f0-9]{40}/ ascii
    condition:
        all of them
}
