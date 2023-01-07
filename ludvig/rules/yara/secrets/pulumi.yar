rule pulumi_api_token : pulumi secret {
    meta:
        description = "Detects a Pulumi API token"
    strings:
        $ = /pul-[a-f0-9]{40}/ ascii
    condition:
        all of them
}
