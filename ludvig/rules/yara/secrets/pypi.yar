rule PyPiApiToken {
    meta:
        description = "Detects PyPi API token"
        severity = "HIGH"
        id = "LS0018"
    strings:
        $token = /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9\-_]{50,1000}/
    condition:
        all of them
}
