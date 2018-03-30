import pymongo

from abc import ABC, abstractmethod

class Database(ABC):

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
        super(Database, self).__init__()

    @abstractmethod
    def configure(self):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def set_last_modified(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def set_collection_info(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def update_one(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def update_many(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def insert_one(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def insert_many(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def get_one_by_id(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def get_one_by_name(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def get_last_modified(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def get_info(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def check_one(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def get_size(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def ensure_index(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def drop_table(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def drop_new(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def drop_modified(self, **kwargs):
        raise NotImplementedError("Should be implemented")

    @abstractmethod
    def drop_info_table(self, **kwargs):
        raise NotADirectoryError("Should be implemented")