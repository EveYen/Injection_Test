import json
from utils.debug_module import Log

INJECTION_TAG = 'INJECTION_TAG'

class HeaderParser(object):
    def __init__(self, headers):
        self.headers = headers
        self.inject_key_list = []

    def get_inject_place(self):
        if INJECTION_TAG in str(self.headers):
            return self.find_inject_tag_key()
        else:
            return self.parse_injection_key()

    def find_inject_tag_key(self):
        temp_header = json.loads(json.dumps(self.headers))
        for key, value in temp_header.items():
            if value == INJECTION_TAG:
                self.inject_key_list.append(key)
        return self.inject_key_list

    def replace_target_key(self, key, inject_str):
        temp_header = json.loads(json.dumps(self.headers))
        temp_header[key] = inject_str
        return temp_header

    def parse_injection_key(self):
        inject_key_list = []
        if isinstance(self.headers, dict):
            for key, value in self.headers.items():
                inject_key_list.append(key)
        return inject_key_list