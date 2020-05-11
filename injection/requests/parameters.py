import json
from utils.debug_module import Log

INJECTION_TAG = 'INJECTION_TAG'

class ParameterParser(object):
    """docstring for ParameterParser"""
    def __init__(self, parameters):
        self.parameters = parameters
        self.inject_key_list = []

    def str2dict(self, parameters):
        result = {}
        if parameters:
            groups = parameters.split('&')
            for group in groups:
                result[group.split('=')[0]] = group.split('=')[1]
        return result

    def get_inject_place(self):
        dict_parameters = self.str2dict(self.parameters)
        if INJECTION_TAG in str(self.parameters):
            return self.__find_inject_tag_key(dict_parameters)
        else:
            return self.__parse_injection_key(dict_parameters)

    def __find_inject_tag_key(self, parameters):
        temp_parameter = json.loads(json.dumps(parameters))
        for key, value in temp_parameter.items():
            if value == INJECTION_TAG:
                self.inject_key_list.append(key)
        return self.inject_key_list

    def __parse_injection_key(self, parameters):
        inject_key_list = []
        if isinstance(parameters, dict):
            for key, value in parameters.items():
                inject_key_list.append(key)
        return inject_key_list

    def replace_target_key(self, key, inject_str):
        temp_parameter = self.str2dict(self.parameters)
        temp_parameter[key] = inject_str
        return temp_parameter