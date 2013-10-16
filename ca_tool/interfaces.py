# Copyright (c) Twisted Matrix Laboratories.
# See LICENSE for details.

from zope.interface import Interface

class ICertificateStore(Interface):
    def submitCertificateRequest(req):
        pass

    def getCertificate(subject):
        pass

from twisted.protocols.amp import Command, String



class CertificateNotFound(LookupError):
    pass



class GetCertificate(Command):
    """
    Request a certificate by subject
    """
    arguments = [
        ("subject", String()),
        ]

    response = [("certificate", String())]

    errors = {CertificateNotFound: "NotFound"}



class SubmitCertificateRequest(Command):
    """
    Submit a certificate request.
    """
    arguments = [
        ("request", String()),
        ]
    response = []
