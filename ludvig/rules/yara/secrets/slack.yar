rule SlackWebHook : slack secret hook {
    meta:
        description = "Detects a Slack webhook"
    strings:
        $ = /https:\/\/hooks.slack.com\/services\/[A-Za-z0-9+\/]{44,48}/
    condition:
        all of them
}

rule SlackAccessToken : slack secret {
    meta:
        description = "Detects a Slack access token"
    strings:
        $ = /xox[baprs]-([0-9a-zA-Z]{10,48})/
    condition:
        all of them
}
