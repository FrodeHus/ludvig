rule PrivateKey : keys secret
{
	meta:
		description = "Private key"
		severity = "CRITICAL"
        id = "LS0009"

	strings:
		$ = "BEGIN PRIVATE KEY" ascii wide

	condition:
		all of them
}

rule PrivateRSAKey : keys secret
{
	meta:
		description = "RSA private key"
		severity = "CRITICAL"
        id = "LS0010"

	strings:
		$ = "BEGIN RSA PRIVATE KEY" ascii wide

	condition:
		all of them
}

rule OpenSSHKey : keys secret
{
	meta:
		description = "OpenSSH private key"
		severity = "CRITICAL"
        id = "LS0011"

	strings:
		$ = "BEGIN OPENSSH PRIVATE KEY"

	condition:
		all of them
}
