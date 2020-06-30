from __future__ import unicode_literals

from pyinfra.api import operation, StringCommand
from pyinfra.facts.certbot import CertBot

@operation
def certonly(state, host, cert_name, domains, dns_provider=None):

	current_certificates = host.fact.cert_bot_certificates()
	present = cert_name in current_certificates

	if not present:
		cb = CertBot(
			cert_name=cert_name,
			domains=domains,
			dns_provider=dns_provider,
		)

		yield cb("certonly")

@operation
def delete(state, host, cert_name):
	cb = CertBot(
		cert_name=cert_name,
	)

	yield cb("delete")
