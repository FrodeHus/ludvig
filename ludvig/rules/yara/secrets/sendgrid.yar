rule SendgridApiToken : sendgrid secret{
    meta:
        description = "Detects a Sendgrid API token"
        severity = "HIGH"
        id = "LS0014"

    strings:
        $ = /SG\.[a-z0-9_\-\.]{66}/ nocase ascii
    condition:
        all of them
}
