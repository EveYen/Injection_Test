import json
from requests.headers import HeaderParser
from requests.payload import JsonParser
from utils.config import DefaultConfig
from utils.debug_module import Log

class InjectorMeta(type):
    def __init__(cls, name, bases, attrs):
        super(InjectorMeta, cls).__init__(name, bases, attrs)
        if not hasattr(cls, 'injectors'):
            cls.injectors = []
        elif cls not in cls.injectors:
            cls.injectors.append(cls)


class InjectorBase(object):
    __metaclass__ = InjectorMeta

    SEPARATORS = ["", ";", "%3B", "&", "%26", "&&", "%26%26", "|", "%7C", "||", "%7C%7C", "%0a", "%0d%0a"]

    def __init__(self, request_obj, request_info):
        Log.report('[ %s ]', self.__class__.__name__)
        self.request_obj = request_obj
        self.request_info = request_info

    def do_injection(self, inject_config):
        for injection_part, config in inject_config.items():
            self.current_part = injection_part
            current_step = 0
            if config['enabled']:
                injection_points_list = config['inject_point_list']
                total_steps = len(injection_points_list)
                for inject_point in injection_points_list:
                    current_step += 1
                    Log.report('|  [ %d/%d ] Injecting %s: %s', current_step, total_steps, injection_part, str(inject_point))
                    Log.debug('Start to test the key: %s', str(inject_point))
                    self.replace_func = config['replace']
                    self.decision(inject_point)
                current_step = 0
            else:
                Log.report('|  Skip injecting %s.', injection_part)

    def find_injectable(self, keys, cmd, result):
        Log.report('|  Find injectable key!')
        Log.report('|\tkeys:\t\t%s', str(keys))
        Log.report('|\tcommand:\t%s', str(cmd).replace('\n', '\n|\t\t'))
        Log.report('|\tresult:\t\t%s', str(result))

    def record_traffic_logs(self, request_info, inject_info, response_info, result):
        version_info = 'HTTP/1.0' if response_info['version'] == 10 else 'HTTP/1.1'
        title_template = "\n====={inject_method}  {separator}  {keys}  {tag}  {cmd}====="
        traffic_template = "{method} {version_info} {path}\n{headers}\n\n{body}"
        Log.request(title_template.format(inject_method=inject_info['inject_method'],
                                          separator=inject_info['seperator'],
                                          keys=str(inject_info['inject_key']),
                                          tag=inject_info['tag'],
                                          cmd=inject_info['command']
                                          ))
        Log.request('[Request]')
        Log.request(traffic_template.format(method=request_info['req_method'],
                                            version_info=version_info,
                                            path=request_info['req_path'],
                                            headers='\n'.join(['{}: {}'.format(key, value) for key, value in request_info['req_headers'].items()]),
                                            body=request_info['req_body'] or ''))
        Log.request('[Response]')
        Log.request(traffic_template.format(method=request_info['req_method'],
                                            version_info=version_info,
                                            path=request_info['req_path'],
                                            headers='\n'.join(['{}: {}'.format(key, value) for key, value in response_info['res_headers']]),
                                            body=response_info['res_body'] or ''))
        Log.request('[Result]')
        Log.request(result)

        info = request_info.copy()
        info.update(inject_info)
        info.update(response_info)
        info['result'] = result
        Log.info(str(info))
        

    def decision(self, data, inject_key):
        raise NotImplementedError('decision is not implement.')
