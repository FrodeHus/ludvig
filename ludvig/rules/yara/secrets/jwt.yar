rule jwt_token : jwt secret {
    meta:
        description = "Detects a JWT token "
    strings:
        $1 = /eyJ[a-zA-Z0-9+\/=]*\.eyJ[a-zA-Z0-9+\/=]*\..*/ ascii
    condition:
        all of them
}

