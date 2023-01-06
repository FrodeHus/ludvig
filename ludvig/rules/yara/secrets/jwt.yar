rule jwt_token : jwt secret {
    meta:
        description = "Detects a JWT token "
    strings:
        $1 = "iss" base64
        $2 = "iat" base64
        $3 = "nbf" base64
        $4 = "exp" base64
    condition:
        all of them
}

