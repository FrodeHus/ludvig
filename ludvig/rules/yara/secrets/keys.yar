rule private_key : keys secret
{
	meta:
		description = "Private key"

	strings:
		$ = "BEGIN PRIVATE KEY" ascii wide

	condition:
		all of them
}

rule private_rsa_key : keys secret
{
	meta:
		description = "RSA private key"

	strings:
		$ = "BEGIN RSA PRIVATE KEY" ascii wide

	condition:
		all of them
}

rule open_ssh_key : keys secret
{
	meta:
		description = "OpenSSH private key"

	strings:
		$ = "BEGIN OPENSSH PRIVATE KEY"

	condition:
		all of them
}
