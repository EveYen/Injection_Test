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

class EvalBased(InjectorBase):

    inject_level = 5

    def __init__(self, request_obj, request_info):
        super(EvalBased, self).__init__(request_obj, request_info)

    def decision(self, inject_key):
        for separator in self.SEPARATORS:
            for length in xrange(6):
                # check exit flag
                SelfThread.is_exit()
                time.sleep(eval(DefaultConfig.get_value('System', 'RequestDelay')))
                # change tag each round in case false positive 
                self.tag = ''.join(random.choice(string.ascii_uppercase) for i in range(6))
                Log.debug('Start to test with separator: %s, TAG: %s, length: %d', separator, self.tag, length)
                random1 = random.randrange(100)
                random2 = random.randrange(100)
                random_sum = random1 + random2
                cmd = self.gen_calculate_cmd(separator, self.tag, random1, random2)
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
                if self.is_inject_success(random_sum, response_info):
                    inject_result = True
                    self.find_injectable(inject_key, cmd, response_info['res_body'])
                else:
                    inject_result = False
                self.record_traffic_logs(self.request_info.get_record(), inject_info, response_info, inject_result)


    def is_inject_success(self, random_sum, response):
        if re.findall(r"{tag}{sum}{tag}{tag}".format(tag=self.tag, sum=random_sum), response['res_body']):
            return True
        return False

    def gen_calculate_cmd(self, separator, TAG, num1, num2):
        if separator == "":
            result = "print(`echo {tag}`.`echo $(({num1}+{num2}))`.`echo {tag}`.`echo {tag}`){separator}".format(separator=separator, tag=TAG, num1=num1, num2=num2)
        else:
            result = "print(`echo {tag}{separator}echo $(({num1}+{num2})){separator}echo {tag}{separator}echo {tag}`)%3B".format(separator=separator, tag=TAG, num1=num1, num2=num2)
        return result
