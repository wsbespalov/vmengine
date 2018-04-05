import urllib.request as req
import io
import gzip
import json

HTTP_PROXY = None
SOURCE = "https://nvd.nist.gov/feeds/json/cve/1.0/nvdcve-1.0-modified.json.gz"

def get_gz_file(getfile):
    try:
        if HTTP_PROXY:
            proxy = req.ProxyHandler({'http': HTTP_PROXY, 'https': HTTP_PROXY})
            auth = req.HTTPBasicAuthHandler()
            opener = req.build_opener(proxy, auth, req.HTTPHandler)
            req.install_opener(opener)

        response = req.urlopen(getfile)

        if 'gzip' in response.info().get('Content-Type'):
            compressed_file = io.BytesIO(response.read())
            decompressed_file = gzip.GzipFile(fileobj=compressed_file)
            return decompressed_file, response.info()

    except Exception as ex:
        print('Get an exception wile load file: {}'.format(ex))

def get_modified_cve_file():
    file_stream, response_info = get_gz_file(SOURCE)
    result = json.load(file_stream)
    return result


from ps.parser import Item

d = get_modified_cve_file()

i = Item(d["CVE_Items"][1])
print(i.cvssv3)