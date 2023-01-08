rule postman_api_token : postman secret {
    meta:
        description = "Detects a Postman API token"
    strings:
        $ = /PMAK-[a-f0-9]{24}\-[a-f0-9]{34}/ nocase ascii
    condition:
        all of them

}