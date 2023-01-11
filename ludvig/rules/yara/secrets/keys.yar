rule PrivateKey : keys secret
{
	meta:
		description = "Private key"
		severity = "CRITICAL"

	strings:
		$ = "BEGIN PRIVATE KEY" ascii wide

	condition:
		all of them
}

rule PrivateRSAKey : keys secret
{
	meta:
		description = "RSA private key"

	strings:
		$ = "BEGIN RSA PRIVATE KEY" ascii wide

	condition:
		all of them
}

rule OpenSSHKey : keys secret
{
	meta:
		description = "OpenSSH private key"

	strings:
		$ = "BEGIN OPENSSH PRIVATE KEY"

	condition:
		all of them
}
