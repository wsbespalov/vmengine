import sys
import json
import urllib.request as req
import zipfile
from io import BytesIO
import gzip
import bz2
import redis
from bson import json_util

from xml.sax import make_parser
from xml.sax.handler import ContentHandler
from dateutil.parser import parse as parse_datetime

def to_string_formatted_cpe(cpe, autofill=False):
    """Convert CPE to formatted string"""
    cpe = cpe.strip()
    if not cpe.startswith('cpe:2.3:'):
        if not cpe.startswith('cpe:/'):
            return False
        cpe = cpe.replace('cpe:/', 'cpe:2.3:')
        cpe = cpe.replace('::', ':-:')
        cpe = cpe.replace('~-', '~')
        cpe = cpe.replace('~', ':-:')
        cpe = cpe.replace('::', ':')
        cpe = cpe.strip(':-')
    if autofill:
        element = cpe.split(':')
        for _ in range(0, 13 - len(element)):
            cpe += ':-'
    return cpe


class CVEHandler(ContentHandler):
    """Class CVEHandler"""
    def __init__(self):
        self.cves = []
        self.accessv = ""
        self.accessc = ""
        self.accessa = ""
        self.impacta = ""
        self.impactc = ""
        self.impacti = ""
        self.cvssgen = ""
        self.ref = None
        self.CVSS = ""
        self.SUMM = ""
        self.DT = ""
        self.PUB = ""
        self.inCVSSElem = 0
        self.inSUMMElem = 0
        self.inDTElem = 0
        self.inPUBElem = 0
        self.inAccessvElem = 0
        self.inAccesscElem = 0
        self.inAccessaElem = 0
        self.inCVSSgenElem = 0
        self.inImpactiElem = 0
        self.inImpactcElem = 0
        self.inImpactaElem = 0

    def startElement(self, name, attrs):
        if name == 'entry':
            self.cves.append({
                'id': attrs.get('id'),
                'references': [],
                'vulnerable_configuration': [],
                'vulnerable_configuration_cpe_2_2':[]})
            self.ref = attrs.get('id')
        if name == 'cpe-lang:fact-ref':
            self.cves[-1]['vulnerable_configuration'].append(
                to_string_formatted_cpe(attrs.get('name')))
            self.cves[-1]['vulnerable_configuration_cpe_2_2'].append(
                attrs.get('name'))
        if name == 'cvss:score':
            self.inCVSSElem = 1
            self.CVSS = ""
        if name == 'cvss:access-vector':
            self.inAccessvElem = 1
            self.accessv = ""
        if name == 'cvss:access-complexity':
            self.inAccesscElem = 1
            self.accessc = ""
        if name == 'cvss:authentication':
            self.inAccessaElem = 1
            self.accessa = ""
        if name == 'cvss:confidentiality-impact':
            self.inImpactcElem = 1
            self.impactc = ""
        if name == 'cvss:integrity-impact':
            self.inImpactiElem = 1
            self.impacti = ""
        if name == 'cvss:availability-impact':
            self.inImpactaElem = 1
            self.impacta = ""
        if name == 'cvss:generated-on-datetime':
            self.inCVSSgenElem = 1
            self.cvssgen = ""
        if name == 'vuln:summary':
            self.inSUMMElem = 1
            self.SUMM = ""
        if name == 'vuln:published-datetime':
            self.inDTElem = 1
            self.DT = ""
        if name == 'vuln:last-modified-datetime':
            self.inPUBElem = 1
            self.PUB = ""
        if name == 'vuln:reference':
            self.cves[-1]['references'].append(
                attrs.get('href'))
        if name == 'vuln:cwe':
            self.cves[-1]['cwe'] = attrs.get('id')

    def characters(self, ch):
        if self.inCVSSElem:
            self.CVSS += ch
        if self.inSUMMElem:
            self.SUMM += ch
        if self.inDTElem:
            self.DT += ch
        if self.inPUBElem:
            self.PUB += ch
        if self.inAccessvElem:
            self.accessv += ch
        if self.inAccesscElem:
            self.accessc += ch
        if self.inAccessaElem:
            self.accessa += ch
        if self.inCVSSgenElem:
            self.cvssgen += ch
        if self.inImpactiElem:
            self.impacti += ch
        if self.inImpactcElem:
            self.impactc += ch
        if self.inImpactaElem:
            self.impacta += ch

    def endElement(self, name):
        if name == 'cvss:score':
            self.inCVSSElem = 0
            self.cves[-1]['cvss'] = self.CVSS
        if name == 'cvss:access-vector':
            self.inAccessvElem = 0
            if 'access' not in self.cves[-1]:
                self.cves[-1]['access'] = {}
            self.cves[-1]['access']['vector'] = self.accessv
        if name == 'cvss:access-complexity':
            self.inAccesscElem = 0
            if 'access' not in self.cves[-1]:
                self.cves[-1]['access'] = {}
            self.cves[-1]['access']['complexity'] = self.accessc
        if name == 'cvss:authentication':
            self.inAccessaElem = 0
            if 'access' not in self.cves[-1]:
                self.cves[-1]['access'] = {}
            self.cves[-1]['access']['authentication'] = self.accessa
        if name == 'cvss:confidentiality-impact':
            self.inImpactcElem = 0
            if 'impact' not in self.cves[-1]:
                self.cves[-1]['impact'] = {}
            self.cves[-1]['impact']['confidentiality'] = self.impactc
        if name == 'cvss:integrity-impact':
            self.inImpactiElem = 0
            if 'impact' not in self.cves[-1]:
                self.cves[-1]['impact'] = {}
            self.cves[-1]['impact']['integrity'] = self.impacti
        if name == 'cvss:availability-impact':
            self.inImpactaElem = 0
            if 'impact' not in self.cves[-1]:
                self.cves[-1]['impact'] = {}
            self.cves[-1]['impact']['availability'] = self.impacta
        if name == 'cvss:generated-on-datetime':
            self.inCVSSgenElem = 0
            self.cves[-1]['cvss-time'] = parse_datetime(self.cvssgen, ignoretz=True)
        if name == 'vuln:summary':
            self.inSUMMElem = 0
            self.cves[-1]['summary'] = self.SUMM
        if name == 'vuln:published-datetime':
            self.inDTElem = 0
            self.cves[-1]['Published'] = parse_datetime(self.DT, ignoretz=True)
        if name == 'vuln:last-modified-datetime':
            self.inPUBElem = 0
            self.cves[-1]['Modified'] = parse_datetime(self.PUB, ignoretz=True)


class CVEUpdater(object):

    def __init__(self, config):
        # type: (dict) -> None
        self.config = config

        self.cache = self.config.get('cache', redis.StrictRedis())

        self.cache_collection_modified = self.config.get('cache_collection_modified', 'SurePatch:modified')
        self.cache_collection_new = self.config.get('cache_collection_new', 'SurePatch:new')

        self.cache.delete(self.cache_collection_new)
        self.cache.delete(self.cache_collection_modified)

    def populate_database(self):
        pass

    def update_database(self):
        prefix = self.config.get('file_prefix', 'nvdcve-2.0-')
        suffix = self.config.get('file_suffix', '.xml.gz')
        cve_source = self.config.get('cve_source', "https://static.nvd.nist.gov/feeds/xml/cve/")

        print('[+] Download ~modified~ file')

        filename = prefix + 'modified' + suffix
        full_filename = cve_source + filename

        file = self.__download_cve_file(full_filename)

        print('[+] Parse ~modified~ file')

        cve_handler = self.__parse_file(file)

        print('[+] File ~modified~ parsed')
        print('[+] Save ~modified~ changes in database and cache')

        self.__process_cve_data(cve_handler)

        print('[+] Data ~modified~  saved')

        print('[+] Download ~recent~ file')

        filename = prefix + 'recent' + suffix
        full_filename = cve_source + filename

        file = self.__download_cve_file(full_filename)

        print('[+] Parse ~recent~ file')

        cve_handler = self.__parse_file(file)

        print('[+] File ~recent~ parsed')
        print('[+] Save ~recent~ changes in database and cache')

        self.__process_cve_data(cve_handler)

        print('[+] Complete process CVE updates')

        return True

    # Data processing

    def __process_cve_data(self, cve_handler):
        count_modified = 0
        count_new = 0
        for item in cve_handler.cves:
            if item:
                element = self.__get_cve(item.get('id', None))
                if element:
                    item['cvss'] = None if 'cvss' not in item else item['cvss']
                    item['cwe'] = dict(cwe="Unknown") if 'cwe' not in item else item['cwe']
                    self.__update_cve_object_in_database(item)
                    self.__push_cve_object_into_cache_collection_modified(item)
                    count_modified = count_modified + 1
                    continue
                self.__insert_cve_object_into_database(item)
                self.__push_cve_object_into_cache_collection_new(item)
                count_new = count_new + 1
        print('[+] Process modified items: {}'.format(count_modified))
        print('[+] Process new items: {}'.format(count_new))
        return True

    def __parse_file(self, file):
        parser = make_parser()
        cve_handler = CVEHandler()
        parser.setContentHandler(cve_handler)
        parser.parse(file)
        return cve_handler

    def __get_cve(self, id):
        return False

    def __if_vulnerable_configuration_is_not_empty(self, item):
        # if len(item['vulnerable_configuration']) == 0:
        #     return False
        # if len(item['vulnerable_configuration_cpe_2_2']) == 0:
        #     return False
        return True

    # Database

    def __insert_cve_object_into_database(self, item):
        if self.__if_vulnerable_configuration_is_not_empty(item):
            pass
            # INSERT CVE object
            pass

        return True

    def __update_cve_object_in_database(self, item):
        if self.__if_vulnerable_configuration_is_not_empty(item):
            pass
            # UPDATE CVE object
            pass

        return True

    # Cache

    def __push_cve_object_into_cache_collection_new(self, item):
        if self.__if_vulnerable_configuration_is_not_empty(item):
            self.cache.rpush(self.cache_collection_new, json.dumps(item, default=json_util.default))
        return True

    def __push_cve_object_into_cache_collection_modified(self, item):
        if self.__if_vulnerable_configuration_is_not_empty(item):
            self.cache.rpush(self.cache_collection_modified, json.dumps(item, default=json_util.default))
        return True

    # Download file

    def __download_cve_file(self, full_filename):
        try:
            print('[+] Download file: {}'.format(full_filename))
            (file, response) = self.__get_file(full_filename)
            if file:
                return file
        except Exception as ex:
            print('[-] Get an exception: {}'.format(ex))
        return None

    def __get_file(self, getfile, unpack=True, raw=False):
        http_roxy = self.config.get('http_proxy', None)
        try:
            if http_roxy:
                proxy = req.ProxyHandler({'http': http_roxy, 'https': http_roxy})
                auth = req.HTTPBasicAuthHandler()
                opener = req.build_opener(proxy, auth, req.HTTPHandler)
                req.install_opener(opener)

            data = response = req.urlopen(getfile)

            if raw:
                return data

            if unpack:
                if 'gzip' in response.info().get('Content-Type'):
                    buf = BytesIO(response.read())
                    data = gzip.GzipFile(fileobj=buf)

                elif 'bzip2' in response.info().get('Content-Type'):
                    data = BytesIO(bz2.decompress(response.read()))

                elif 'zip' in response.info().get('Content-Type'):
                    fzip = zipfile.ZipFile(BytesIO(response.read()), 'r')
                    if len(fzip.namelist()) > 0:
                        data = BytesIO(fzip.read(fzip.namelist()[0]))

            return data, response

        except Exception as ex:
            print('[-] Get an exception: {}'.format(ex))
            return None, str(ex)


if __name__ == '__main__':
    u = CVEUpdater({})
    u.update_database()