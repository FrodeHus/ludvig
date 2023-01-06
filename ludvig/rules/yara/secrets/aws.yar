rule aws_access_key : aws secret
{

        meta:
                description = "Finds AWS Access Key IDs"

        strings:
                $key = /(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/                                                                                                                                 nocase wide ascii fullword
        condition:
                all of them
}

rule aws_account_id : aws secret
{

        meta:
                description = "Finds AWS Account IDs"

        strings:
                $ = /aws.account.id/                nocase wide ascii private
                $id = /0-9]{4}\-[0-9]{4}\-[0-9]{4}/ nocase wide ascii fullword
        condition:
                all of them
}

rule aws_secret_access_key : aws secret
{

        meta:
                description = "Finds AWS Secret Access Keys"

        strings:
                $ = /aws.secret.access.key/ nocase wide ascii private
                $key = /[0-9a-z]{40}/       nocase wide ascii fullword
        condition:
                all of them
}

rule aws_session_token : aws secret
{

        meta:
                description = "Finds AWS Session Tokens"

        strings:
                $ = /aws.session.token/         nocase wide ascii private
                $token = /[A-Za-z0-9\/+=]{16,}/ nocase wide ascii fullword
        condition:
                all of them
}

