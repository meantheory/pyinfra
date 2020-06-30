from __future__ import unicode_literals
from pyinfra.api import FactBase, MaskString, QuoteString, StringCommand


class CertBot:

	def __init__(self,
		cert_name=None,
		domains=None, dns_provider=None,
	):
		self._domains = domains
		self.dns_provider = dns_provider
		self.cert_name = cert_name


	def __call__(self, command):
		return self.command(command)

	@property
	def domains(self):
		return ','.join(self._domains)

	def command(self, command):
		bits = ['certbot', command]

		if self.cert_name:
			bits.append('--cert-name {0}'.format(self.cert_name))

		if self.dns_provider:
			# create dns flag like, --dns-google
			bits.append('--dns-{0}'.format(self.dns_provider))

		if self._domains:
			bits.append('-d {0}'.format(self.domains))
		
		return StringCommand(*bits)

class CertBotFactBase(FactBase):
    abstract = True

class CertBotCertificates(CertBotFactBase):

    def command(self):
    	cb = CertBot()
    	return cb("certificates")

    def process(self, output):
    	certificates = {}
    	this = dict(name=None, fullchain=None, private=None)

    	for line in output:
    		try:
    			rhs = line.split(":")[1].strip()
    		except IndexError:
    			continue

    		if line.startswith("Certificate Name:"):
    			this["name"] = rhs

    		elif line.startswith("Certificate Path:"):
    			this["fullchain"] = rhs

    		elif line.startswith("Private Key Path:"):
    			this["private"] = rhs

    			certificates[this["name"]] = this
    			this = dict(name=None, fullchain=None, private=None)

    	return certificates
