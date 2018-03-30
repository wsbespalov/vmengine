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

