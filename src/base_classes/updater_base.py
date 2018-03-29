import urllib.request as req
import zipfile
from io import BytesIO
import gzip
import bz2

from abc import ABC, abstractmethod


class Updater(ABC):

    config = {}

    def __init__(self, config):
        if config is None:
            self.config = dict()
        else:
            if isinstance(config, dict):
                self.config = config
            else:
                self.config = dict()
        self.configure()
        super(Updater, self).__init__()

    @abstractmethod
    def configure(self):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def populate(self):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def update(self):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def parse(self, file):
        raise NotImplementedError("Should be implemented")

    def __get_raw_file(self, getfile, http_proxy=None):
        try:
            if http_proxy:
                proxy = req.ProxyHandler({'http': http_proxy, 'https': http_proxy})
                auth = req.HTTPBasicAuthHandler()
                opener = req.build_opener(proxy, auth, req.HTTPHandler)
                req.install_opener(opener)

            data = response = req.urlopen(getfile)

            return data, response

        except Exception as ex:
            return None, str(ex)

    def __get_gzip_file(self, getfile, http_proxy=None):
        try:
            if http_proxy:
                proxy = req.ProxyHandler({'http': http_proxy, 'https': http_proxy})
                auth = req.HTTPBasicAuthHandler()
                opener = req.build_opener(proxy, auth, req.HTTPHandler)
                req.install_opener(opener)

            data = response = req.urlopen(getfile)

            if 'gzip' in response.info().get('Content-Type'):
                buf = BytesIO(response.read())
                data = gzip.GzipFile(fileobj=buf)

                return data, response

            return None, 'no gzip format'

        except Exception as ex:
            return None, str(ex)

    def __get_bzip_file(self, getfile, http_proxy=None):
        try:
            if http_proxy:
                proxy = req.ProxyHandler({'http': http_proxy, 'https': http_proxy})
                auth = req.HTTPBasicAuthHandler()
                opener = req.build_opener(proxy, auth, req.HTTPHandler)
                req.install_opener(opener)

            data = response = req.urlopen(getfile)

            if 'bzip2' in response.info().get('Content-Type'):
                data = BytesIO(bz2.decompress(response.read()))

                return data, response

            return None, 'no bzip format'

        except Exception as ex:
            return None, str(ex)

    def __get_zip_file(self, getfile, http_proxy=None):
        try:
            if http_proxy:
                proxy = req.ProxyHandler({'http': http_proxy, 'https': http_proxy})
                auth = req.HTTPBasicAuthHandler()
                opener = req.build_opener(proxy, auth, req.HTTPHandler)
                req.install_opener(opener)

            data = response = req.urlopen(getfile)

            if 'zip' in response.info().get('Content-Type'):
                fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
                length_of_namelist = len(fzip.namelist())
                if length_of_namelist > 0:
                    data = BytesIO(fzip.read(fzip.namelist()[0]))

                return data, response

            return None, 'no zip format'

        except Exception as ex:
            return None, str(ex)
