import redis
import pymongo

from config import configuration as config
from base_classes.updater_base import Updater

from mongo_db import Mongo

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

        self.mongo_collections = {
            "cves": self.db.mongo[self.mongo_collections_config.get("cves", "cves")]
        }

    def populate(self):
        start_year = config.get('start_year', 2017)
        i = []

        i.append(self.db.get_one_by_id(
            collection=self.mongo_collections["cves"],
            id="CVE-2001-1594"))
        i[0]["cvss"] = '12.0'

        i.append(self.db.get_one_by_id(
            collection=self.mongo_collections["cves"],
            id="CVE-2002-2446"))
        i[1]["cvss"] = '12.0'

        self.db.update_many(
            collection=self.mongo_collections["cves"],
            data=i
        )

    def update(self):
        pass

    def parse(self, file):
        pass


if __name__ == '__main__':
    u = CVEUpdater(config=config)
    u.populate()