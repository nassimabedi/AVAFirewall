import abc


class AbstractFirewall(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def __init__(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def share(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def insert_rule(self, **kwargs):
        pass

    @abc.abstractmethod
    def append_rule(self, **kwargs):
        pass

    @abc.abstractmethod
    def replace_rule(self, **kwargs):
        pass

    @abc.abstractmethod
    def delete_rule(self, **kwargs):
        pass

    @abc.abstractmethod
    def view_all(self, table_name=''):
        pass

    @abc.abstractmethod
    def view_one(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def permanent(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def get_line_number(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def create_chain(self, table_name, chain_name):
        # table name ,chain name
        pass

    @abc.abstractmethod
    def delete_chain(self, *args, **kwargs):
        pass

    @abc.abstractmethod
    def rename_chain(self, *args, **kwargs):
        pass
