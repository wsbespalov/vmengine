import pymongo
from pymongo import errors
from datetime import datetime

from old_code_1.base_classes.database import Database


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
        """
        Set parameter "last-modified" in INFO collection
        :param kwargs:
            collection:     collection name
            date:           date to set
        :return:
        """
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
        return None

    def set_collection_info(self, **kwargs):
        """
        Set field in INFO collection
        :param kwargs:
            collection:     collection name
            field:          field to set
            data:           data to set in field
        :return:
        """
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
        return None

    def update_one(self, **kwargs):
        """
        Update one item in MongoDB
        :param kwargs:
            collection:     MongoDB collection
            data:           data in JSON to update in collection
        :return:
        """
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
        return None

    def update_many(self, **kwargs):
        """
        Update list of data in MongoDB
        :param kwargs:
            collection:     MongoDB collection
            data:           list of JSON data to update
        :return:
        """
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
        return None

    def insert_one(self, **kwargs):
        """
        Insert new item into MongoDB
        :param kwargs:
            collection:     MongoDB collection
            data:           item to insert into MongoDB
        :return:
        """
        collection = kwargs.get("collection", None)
        if collection is not None:
            data = kwargs.get("data", {})
            try:
                collection.insert(data)
            except errors.PyMongoError as err:
                print("Get an exception in ~set_last_modified~: {}".format(err))
        return None

    def insert_many(self, **kwargs):
        """
        Insert list of data int MongoDB
        :param kwargs:
            collection:     MongoDB collection
            data:           list of items to insert into MongoDB
        :return:
        """
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
        return None

    def get_one_by_id(self, **kwargs):
        """
        Get one item from collection in MongoDB by ID field
        :param kwargs:
            collection:     MongoDB collection
        :return:
            item or None
        """
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
        """
        No implemented now
        :param kwargs:
        :return:
        """
        return None

    def get_last_modified(self, **kwargs):
        """
        Get last-modified field from MongoDB collection
        :param kwargs:
            collection:     MongoDB collection
        :return:
            last-modified value or None
        """
        collection = kwargs.get("collection", None)
        if collection is not None:
            info = self.get_info(collection=collection)
            return info['last-modified'] if info else None
        return None

    def get_info(self, **kwargs):
        """
        Get information from INFO collection
        :param kwargs:
            collection:     collection NAME
        :return:
            information or None
        """
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
        """
        Check if item in MongoDB collection
        :param kwargs:
            collection:     MongoDB collection
            id:             item ID
        :return:
            (True, last-modified) or None
        """
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
        """
        Get MongoDB collection count
        :param kwargs:
            collection:     MongoDB collection
        :return:
            size or None
        """
        collection = kwargs.get("collection", None)
        if collection is not None:
            try:
                self.mongo[collection].count()
            except errors.PyMongoError as err:
                print("Get an exception in ~set_last_modified~: {}".format(err))
        return None

    def ensure_index(self, **kwargs):
        """
        Ensure index for MongoDB collection by field
        :param kwargs:
            collection:     MongoDB collection NAME
            field:          field NAME to ensure index
        :return:
        """
        collection = kwargs.get("collection", None)
        if collection is not None:
            field = kwargs.get("field", "id")
            try:
                self.mongo[collection].ensure_index(field)
            except errors.PyMongoError as err:
                print("Get an exception in ~set_last_modified~: {}".format(err))
        return None

    def drop_table(self, **kwargs):
        """
        Drop collection in MongoDB
        :param kwargs:
            collection:     MongoDB collection to drop
        :return:
        """
        collection = kwargs.get("collection", None)
        if collection is not None:
            try:
                result = collection.drop()
            except errors.PyMongoError as err:
                print("Get an exception in ~set_last_modified~: {}".format(err))
        return None

    def drop_new(self, **kwargs):
        """
        Drop NEW collection in MongoDB
        :param kwargs:
        :return:
        """
        try:
            self.collection_new.drop()
        except errors.PyMongoError as err:
            print("Get an exception in ~set_last_modified~: {}".format(err))
        return None

    def drop_modified(self, **kwargs):
        """
        Drop MODIFIED collection
        :param kwargs:
        :return:
        """
        try:
            self.collection_modified.drop()
        except errors.PyMongoError as err:
            print("Get an exception in ~set_last_modified~: {}".format(err))
        return None

    def drop_info_table(self, **kwargs):
        """
        Drop INFO collection in MongoDB
        :param kwargs:
        :return:
        """
        try:
            self.collection_info.drop()
        except errors.PyMongoError as err:
            print("Get an exception in ~set_last_modified~: {}".format(err))
        return None

    def sanitize(self, item):
        """
        Sanitize item in MongoDB
        :param item:
            item:       item to sanitize
        :return:
        """
        if isinstance(item, pymongo.cursor.Cursor):
            item = list(item)
        if isinstance(item, list):
            for _ in item:
                self.sanitize(_)
        if item and "_id" in item:
            item.pop("_id")
        return item