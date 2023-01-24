rule GitHubToken : github secret
{

        meta:
                description = "Finds GitHub API tokens"
                severity = "CRITICAL"
                id = "LS0006"

        strings:
                $s1 = "ghp_" nocase wide ascii private
                $s2 = "ghu_" nocase wide ascii private
                $s3 = "ghs_" nocase wide ascii private
                $s4 = "gho_" nocase wide ascii private
                $token = /[0-9a-zA-Z]{36}/ nocase wide ascii fullword
        condition:
                $token and any of ($s*)
}

rule GitHubRefreshToken : github secret
{

        meta:
                description = "Finds GitHub refresh tokens"
                severity = "CRITICAL"
                id = "LS0007"

        strings:
                $s1 = "ghr_" nocase wide ascii private
                $token = /[0-9a-zA-Z]{76}/ nocase wide ascii fullword
        condition:
                all of them
}