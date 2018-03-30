import redis
from dateutil.parser import parse as parse_datetime
from datetime import datetime
from datetime import timedelta

from config import configuration as config
from base_classes.updater import Updater

from xml.sax import make_parser

from mongo_db import Mongo

from handlers.cvehandler import CVEHandler

class CVEUpdater(Updater):

    def configure(self):
        self.cache_config = self.config.get("cache", {})
        self.cache_host = self.cache_config.get("host", 'localhost')
        self.cache_port = self.cache_config.get("port", 6379)
        self.cache = redis.StrictRedis(
            host=self.cache_host,
            port=self.cache_port
        )
        self.cache_collections_config = self.cache_config.get("collections", {})
        self.cache_collection_new = self.cache_collections_config.get("new", "SurePatch:new")
        self.cache_collection_modififed = self.cache_collections_config.get("modified", "SurePatch:modified")

        self.sources = self.config.get("sources", {})

        self.db = Mongo(self.config)

        self.mongo_config = self.config.get("mongo", {})
        self.mongo_collections_config = self.mongo_config.get("collections", {})

        self.collection_cves_name = self.mongo_collections_config.get("cves", "cves")

        self.mongo_collections = {
            "cves": self.db.mongo[self.collection_cves_name]
        }

    def populate(self):
        start_year = config.get('start_year', 2017)

    def update(self):



        self.db.drop_info_table()


        self.db.drop_modified()
        self.db.drop_new()

        # download modified file
        files_config = self.config.get("files", {})
        prefix = files_config.get("prefix", "nvdcve-1.0-")
        suffix = files_config.get("suffix", ".json.gz")
        modified = files_config.get("modified", "modified")
        recent = files_config.get("recent", "recent")

        getfile = self.sources.get("cves", "https://nvd.nist.gov/feeds/json/cve/1.0/") + prefix + modified + suffix

        print('[+] Download {} file'.format(getfile))

        file, response = self.get_gzip_file(getfile=getfile)

        info = self.db.get_info(collection=self.collection_cves_name)

        last_modified = parse_datetime(response.headers['last-modified'], ignoretz=True)

        print('[+] CVES was modified at: {}'.format(last_modified))

        if info is not None:
            if last_modified == info['last-modified']:
                print("[-] Collection {} not modified".format(self.collection_cves_name))
                return 1

        self.db.set_last_modified(collection=self.collection_cves_name)

        print(file)

        start_time = datetime.utcnow()
        print('[t] Start update MongoDB at: {}'.format(start_time))

        # for item in cve_handler.cves:
        #     if "id" in item:
        #         element = self.db.get_one_by_id(id=item["id"])

        stop_time = datetime.utcnow()
        delta_time = stop_time - start_time
        print('[t] Start update MongoDB at: {}'.format(start_time))
        print('[t] Update takes: {} sec.'.format(delta_time.total_seconds()))

        pass

    def parse(self, **kwargs):
        file = kwargs.get("file", None)
        if file is not None:
            handler = kwargs.get("handler", None)
            if handler is not None:
                parser = make_parser()
                cve_handler = CVEHandler()
                parser.setContentHandler(handler)
                parser.parse(file)
        pass


if __name__ == '__main__':
    u = CVEUpdater(config=config)
    u.update()