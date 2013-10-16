from twisted.application import service
application = service.Application('ca-tool-daemon')
from ca_tool.wiring import AMPService
from ca_tool.authority import CertificateStore, CertificateStoreServer

from twisted.python.filepath import FilePath
store = CertificateStore.fromFilePath(FilePath('.ca-data'))
AMPService('unix:test.sock', CertificateStoreServer(store)).setServiceParent(application)

