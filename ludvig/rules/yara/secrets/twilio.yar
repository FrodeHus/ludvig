rule TwilioAPIKey : twilio secret {
    meta:
        description = "Detects a Twilio API token"
        severity = "HIGH"

    strings:
        $ = /SK[0-9a-fA-F]{32}/
    condition:
        all of them
}
