rule sendgrid_api_token : sendgrid secret{
    meta:
        description = "Detects a Sendgrid API token"
    strings:
        $ = /SG\.[a-z0-9_\-\.]{66}/ nocase ascii
    condition:
        all of them
}
