rule PostmanApiToken : postman secret {
    meta:
        description = "Detects a Postman API token"
        severity = "HIGH"
        id = "LS0012"

    strings:
        $ = /PMAK-[a-f0-9]{24}-[a-f0-9]{34}/ ascii fullword wide
    condition:
        all of them
}