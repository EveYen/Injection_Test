import json
from utils.debug_module import Log

INJECTION_TAG = 'INJECTION_TAG'

def content_type_parse_handler(content_type, payload):
    if content_type == 'application/json':
        Log.debug('The content type is json.')
        return JsonParser(payload)
    Log.error('Can\'t find handler.')
    return None
        
class JsonParser(object):
    """docstring for JsonParser"""
    def __init__(self, payloads):
        self.payloads = payloads
        self.inject_key_list = []

    def get_inject_place(self):
        if INJECTION_TAG in str(self.payloads):
            return self._find_inject_tag_key(self.payloads)
        else:
            return self.parse_injection_key(self.payloads)

    def _find_inject_tag_key(self, payload, parent_key=None):
        if isinstance(payload, dict):
            for key, value in payload.items():
                _parent_key = parent_key[:] if isinstance(parent_key, list) else []
                _parent_key.append(key)
                if isinstance(value, (dict, list)):
                    self._find_inject_tag_key(value, parent_key=_parent_key)
                elif INJECTION_TAG in str(value):
                    self.inject_key_list.append(_parent_key)
        if isinstance(payload, list):
            for index, value in enumerate(payload):
                _parent_key = parent_key[:] if isinstance(parent_key, list) else []
                _parent_key.append(index)
                if isinstance(value, (dict, list)):
                    self._find_inject_tag_key(value, parent_key=_parent_key)
                elif INJECTION_TAG in str(value):
                    self.inject_key_list.append(_parent_key)
        return self.inject_key_list

    def replace_target_key(self, parent_key, inject_str):
        temp_payload = json.loads(json.dumps(self.payloads))
        key_str = 'temp_payload'
        for key in parent_key:
            if isinstance(key, (str, unicode)):
                key_str += '["{key}"]'.format(key=key)
            elif isinstance(key, int):
                key_str += '[{key}]'.format(key=key)
        exec(key_str + ' = inject_str')
        return temp_payload

    def parse_injection_key(self, payload, parent_key=None):
        tmp_payload = json.loads(json.dumps(payload))
        if isinstance(tmp_payload, dict):
            for key, value in tmp_payload.items():
                self.__recursive_parse(key, value, parent_key)
        elif isinstance(tmp_payload, list):
            for index, value in enumerate(tmp_payload):
                self.__recursive_parse(index, value, parent_key)
        return self.inject_key_list

    def __recursive_parse(self, key, value, parent_key):
        _parent_key = parent_key[:] if isinstance(parent_key, list) else []
        _parent_key.append(key)

        if isinstance(value, (dict, list)):
            self.parse_injection_key(value, parent_key=_parent_key)

        self.inject_key_list.append(_parent_key)
