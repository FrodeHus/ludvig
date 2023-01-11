rule JWT : jwt secret {
    meta:
        description = "Detects a JWT token "
        severity = "HIGH"

    strings:
        $1 = /eyJ[a-zA-Z0-9+\/=]*\.eyJ[a-zA-Z0-9+\/=]*\..*/ ascii fullword
    condition:
        all of them
}

