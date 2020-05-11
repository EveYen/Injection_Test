import os
import ConfigParser

class Config(object):
    """docstring for Config"""
    def __init__(self, ini_path):
        if not ini_path or not os.path.exists(ini_path):
            open(ini_path, 'w+')
        self.ini_path = ini_path
        self.config = ConfigParser.RawConfigParser()
        self.config.read(ini_path)

    def get_value(self, section, key):
        return self.config.get(section, key)

    def set_value(self, section, key, value):
        self.config.set(section, key, value)
        self.write_config()

    def add_new_key(self, section, key):
        self.config.set(section, key, '')
        self.write_config()

    def reload(self):
        self.config.read(self.ini_path)

    def write_config(self):
        with open(self.ini_path, 'w') as configfile:
            self.config.write(configfile)

    def add_new_section(self, section):
        self.config.add_section(section)
        self.write_config()

ini_path = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../config/settings.ini"))
DefaultConfig = Config(ini_path)

if __name__ == '__main__':
    print ini_path
    DefaultConfig = Config(ini_path)