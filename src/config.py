
import os

configuration = {
    "cache": {
        "host": os.getenv('REDIS_HOST', 'localhost'),
        "port": int(os.getenv('REDIS_PORT', 6379)),
        "collections": {
            "modified": "SurePatch:modified",
            "new": "SurePatch:new"
        }
    },
    "mongo": {
        "host": os.getenv('MONGO_HOST', 'localhost'),
        "port": int(os.getenv("MONGO_PORT", 27017)),
        "db_name": os.getenv('MONGO_DB', "SurePatch-CVE"),
        "collections": {
            "info": "info",
            "cves": "cves",
            "new": "new",
            "modified": "modified"
        },
    },
    "mycollection": "cves",
    "files": {
        "prefix": "nvdcve-2.0-",
        "suffix": ".xml.gz",
        "modified": "modified",
        "recent": "recent"
    },
    "http_proxy": None,
    "start_year": 2017,
    "use_ssl": False,
    "ssl_certificate": "cve-search.crt",
    "ssl_key": "cve-search.crt",
    "index_dir": "./indexdir",
    "temp_dir": "./tmp",
    "sources": {
        "cve": "https://static.nvd.nist.gov/feeds/xml/cve/",
    },
    "messages": {
        'normal': 0,
        'file_exception': 1,
        'parsing_error': 2
    }
}
