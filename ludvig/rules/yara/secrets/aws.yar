rule AwsAccessKey : aws secret
{

        meta:
                description = "Finds AWS Access Key IDs"
                severity = "CRITICAL"
                id = "LS0001"
        strings:
                $key = /(A3T[A-Z0-9]|AKIA|AGPA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}/  nocase wide ascii fullword
        condition:
                all of them
}

rule AwsAccountId : aws secret
{

        meta:
                description = "Finds AWS Account IDs"
                severity = "HIGH"
                id = "LS0002"

        strings:
                $ = /aws.account.id/                nocase wide ascii private
                $id = /0-9]{4}\-[0-9]{4}\-[0-9]{4}/ nocase wide ascii fullword
        condition:
                all of them
}

rule AwsSecretAccessKey : aws secret
{

        meta:
                description = "Finds AWS Secret Access Keys"
                severity = "CRITICAL"
                id = "LS0003"

        strings:
                $ = /aws.secret.access.key/ nocase wide ascii private
                $key = /[0-9a-z]{40}/       nocase wide ascii fullword
        condition:
                all of them
}

rule AwsSessionToken : aws secret
{

        meta:
                description = "Finds AWS Session Tokens"
                severity = "CRITICAL"
                id = "LS0004"

        strings:
                $ = /aws.session.token/         nocase wide ascii private
                $token = /[A-Za-z0-9\/+=]{16,}/ nocase wide ascii fullword
        condition:
                all of them
}

