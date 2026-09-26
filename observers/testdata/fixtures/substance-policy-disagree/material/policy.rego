package policy

default allow = false

allow {
	input.certificate.Subject.CommonName == "client.example"
}

allow {
	input.certificate.Subject.OrganizationalUnit[_] == "policy-ou"
}
