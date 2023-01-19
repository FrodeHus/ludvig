rule PulumiAPIToken : pulumi secret {
    meta:
        description = "Detects a Pulumi API token"
        severity = "CRITICAL"

    strings:
        $ = /pul-[a-f0-9]{40}/ ascii
    condition:
        all of them
}
