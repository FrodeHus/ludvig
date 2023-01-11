rule SendgridAPIToken : sendgrid secret{
    meta:
        description = "Detects a Sendgrid API token"
        severity = "HIGH"

    strings:
        $ = /SG\.[a-z0-9_\-\.]{66}/ nocase ascii
    condition:
        all of them
}
