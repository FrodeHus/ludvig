rule PyPiApiToken {
    meta:
        description = "Detects PyPi API token"
        severity = "HIGH"
        id = "LS0018"
    strings:
        $token = /pypi-[a-zA-Z0-9]{199}/
    condition:
        all of them
}
