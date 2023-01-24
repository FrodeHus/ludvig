rule TwilioApiKey : twilio secret {
    meta:
        description = "Detects a Twilio API token"
        severity = "HIGH"
        id = "LS0017"

    strings:
        $ = /SK[0-9a-fA-F]{32}/
    condition:
        all of them
}
