import pymongo
from pymongo import errors
from datetime import datetime

from base_classes.database import Database


class Mongo(Database):

    def configure(self):
        self.mongo_config = self.config.get("mongo", {})
        self.mongo_host = self.mongo_config.get("host", 'localhost')
        self.mongo_port = self.mongo_config.get("port", 27017)
        self.mongo_db_name = self.mongo_config.get("db_name", "SurePatch-CVE")
        self.mongo = pymongo.MongoClient(
            host=self.mongo_host,
            port=self.mongo_port,
            connect=True
        )[self.mongo_db_name]
        self.mongo_collection_config = self.config.get("collections", {})
        self.collection_info = self.mongo[self.mongo_collection_config.get("info", "info")]
        self.collection_modified = self.mongo[self.mongo_collection_config.get("modified", "modified")]
        self.collection_new = self.mongo[self.mongo_collection_config.get("new", "new")]

    def set_last_modified(self, **kwargs):
        collection = kwargs.get("collection", "cves")
        date = kwargs.get("date", datetime.utcnow())
        try:
            self.collection_info.update(
                {"db": collection},
                {"$set": {"last-modified": date}},
                upsert=True
            )
        except errors.PyMongoError as err:
            print("Get an exception in ~set_last_modified~: {}".format(err))

    def set_collection_info(self, **kwargs):
        collection = kwargs.get("collection", "cves")
        field = kwargs.get("field", "default")
        data = kwargs.get("data", None)
        try:
            self.collection_info.update(
                {"db": collection},
                {"$set": {field: data}},
                upsert=True
            )
        except errors.PyMongoError as err:
            print("Get an exception in ~set_last_modified~: {}".format(err))

    def update_one(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            data = kwargs.get("data", {})
            if "id" in data:
                try:
                    collection.update(
                        {"id": data["id"]},
                        {"$set": data}
                    )
                except errors.PyMongoError as err:
                    print("Get an exception in ~set_last_modified~: {}".format(err))

    def update_many(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            data = kwargs.get("data", {})
            for d in data:
                try:
                    self.update_one(
                        collection=collection,
                        data=d
                    )
                except errors.PyMongoError as err:
                    print("Get an exception in ~set_last_modified~: {}".format(err))

    def insert_one(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            data = kwargs.get("data", {})
            try:
                collection.insert(data)
            except errors.PyMongoError as err:
                print("Get an exception in ~set_last_modified~: {}".format(err))

    def insert_many(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            data = kwargs.get("data", {})
            for d in data:
                try:
                    self.insert_one(
                        collection=collection,
                        data=d
                    )
                except errors.PyMongoError as err:
                    print("Get an exception in ~set_last_modified~: {}".format(err))

    def get_one_by_id(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            id = kwargs.get("id", None)
            if id is not None:
                try:
                    result = collection.find_one(
                        {"id": id}
                    )
                    return self.sanitize(result)
                except errors.PyMongoError as err:
                    print("Get an exception in ~set_last_modified~: {}".format(err))
        return None

    def get_one_by_name(self, **kwargs):
        pass

    def get_last_modified(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            info = self.get_info(collection=collection)
            return info['last-modified'] if info else None
        return None

    def get_info(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            try:
                result = self.collection_info.find_one(
                    {"db": collection}
                )
                return self.sanitize(result)
            except errors.PyMongoError as err:
                print("Get an exception in ~set_last_modified~: {}".format(err))
        return None

    def check_one(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            id = kwargs.get("id", None)
            if id is not None:
                try:
                    result = collection.find_one(
                        {"id": id}
                    )
                    if 'last-modified' in result:
                        return True, result['last-modified']
                except errors.PyMongoError as err:
                    print("Get an exception in ~set_last_modified~: {}".format(err))
        return False, None

    def get_size(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            try:
                self.mongo[collection].count()
            except errors.PyMongoError as err:
                print("Get an exception in ~set_last_modified~: {}".format(err))

    def ensure_index(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            field = kwargs.get("field", "id")
            try:
                self.mongo[collection].ensure_index(field)
            except errors.PyMongoError as err:
                print("Get an exception in ~set_last_modified~: {}".format(err))

    def drop_table(self, **kwargs):
        collection = kwargs.get("collection", None)
        if collection is not None:
            try:
                result = collection.drop()
            except errors.PyMongoError as err:
                print("Get an exception in ~set_last_modified~: {}".format(err))

    def drop_new(self, **kwargs):
        try:
            self.collection_new.drop()
        except errors.PyMongoError as err:
            print("Get an exception in ~set_last_modified~: {}".format(err))

    def drop_modified(self, **kwargs):
        try:
            self.collection_modified.drop()
        except errors.PyMongoError as err:
            print("Get an exception in ~set_last_modified~: {}".format(err))

    def sanitize(self, item):
        if isinstance(item, pymongo.cursor.Cursor):
            item = list(item)
        if isinstance(item, list):
            for _ in item:
                self.sanitize(_)
        if item and "_id" in item:
            item.pop("_id")
        return item