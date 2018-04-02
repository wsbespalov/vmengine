import json

filename = 'modified.json'

with open(filename, 'r') as file:
    j = json.load(file)


class Item(object):

    def __init__(self, data):
        cve = data.get("cve", {})
        self.data_type = cve.get("data_type", None)
        self.data_format = cve.get("data_format", None)
        self.data_version = cve.get("data_version", None)
        data_meta = cve.get("CVE_data_meta", {})
        self.id = data_meta.get("ID", None)


i = Item(j["CVE_Items"][0])
print(i.id)