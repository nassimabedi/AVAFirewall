import json
import os
JSON_CONFIG = 'config.json'


class Singleton(object):
    _instance = None

    def __new__(class_, *args, **kwargs):
        if not isinstance(class_._instance, class_):
            class_._instance = object.__new__(class_, *args, **kwargs)
        return class_._instance


# This class read json file
class ReadJson(Singleton):
    def __init__(self, filename=''):
        self.filename = JSON_CONFIG if filename == '' else filename
        # self.filename = JSON_CONFIG
        curr_dir = os.path.dirname(__file__)
        with open(os.path.join(curr_dir, self.filename)) as json_file:
            self.data = json.load(json_file)

    def get_file_path(self):
        return self.data['file_path']

    def get_os(self):
        return self.data['os']

    def get_type_firewall(self):
        return self.data['type_firewall']

    def get_default_table(self):
        return self.data['default_table']

    def get_default_chain(self):
        return self.data['default_chain']

    def get_ip_version(self):
        return self.data['ip_version']

    def get_err(self, num_err):
        return self.data[num_err]

if __name__ == '__main__':
    err_code = ReadJson("error_code.json")
    print err_code
    print err_code.get_err("200")
