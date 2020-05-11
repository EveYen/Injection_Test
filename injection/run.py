import os
import json
import logging
import urlparse
from utils.debug_module import Logger_obj, Log
from utils.thread_handler import SelfThread
from requests.requests import Requests
from requests.request_info import RequestInfo
from techniques.injector import InjectorBase
from utils.config import DefaultConfig

from techniques.classic import Classic
from techniques.eval_based import EvalBased
from techniques.time_based import TimeBases
from techniques.file_based import FileBased
from techniques.tempfile_based import TempfileBased

class Scan(object):
    """docstring for Scan"""
    def __init__(self, debug_level, task_id=None):
        super(Scan, self).__init__()
        self.task_id = task_id
        self.setup_thread_handler()
        self.create_folder('./logs/')
        self.set_logger(debug_level)

    def setup_thread_handler(self):
        SelfThread.create_thread_control_file(self.task_id)

    def create_folder(self, path):
        if not os.path.isdir(path):
            os.makedirs(path)

    def set_logger(self, debug_level):
        logger_name = self.task_id or 'injection_test'
        Logger_obj.logger = logging.getLogger(logger_name)
        debug_level = debug_level * 10 or 5
        Logger_obj.set_default_level(5)
        # TODO: remove this log setting after complete
        #Logger_obj.print_log_mode(debug_level)
        if self.task_id:
            self.log_folder = './logs/{}/'.format(self.task_id)
            self.create_folder(self.log_folder)
            self.requests_path = '{}Injection_test_request.log'.format(self.log_folder)
            self.report_path = '{}Injection_test_report.log'.format(self.log_folder)
            self.debug_path = '{}Injection_test_debug.log'.format(self.log_folder)
            self.burp_path = '{}Injection_test_burpinfo.log'.format(self.log_folder)
            Logger_obj.write_log_mode(self.requests_path, logging.REQUEST, True)
            Logger_obj.write_log_mode(self.report_path, logging.CRITICAL, False)
            Logger_obj.write_log_mode(self.burp_path, logging.INFO, True)
            Logger_obj.write_log_mode(self.debug_path, logging.DEBUG, False)
        else:
            Logger_obj.print_log_mode(debug_level)
            self.log_folder = './logs/{}/'.format(self.task_id)
            self.create_folder(self.log_folder)
            self.requests_path = '{}Injection_test_request.log'.format(self.log_folder)
            Logger_obj.write_log_mode(self.requests_path, logging.REQUEST, True)
            self.debug_path = '{}Injection_test_debug.log'.format(self.log_folder)
            Logger_obj.write_log_mode(self.debug_path, logging.DEBUG, True)
            self.debug_path = '{}Injection_test_burpinfo.log'.format(self.log_folder)
            Logger_obj.write_log_mode(self.debug_path, logging.INFO, True)

    def test_conncetion(self, url, method, headers=None, payload=None):
        url_parts = urlparse.urlparse(url)
        url_path = url_parts.path

        request_info = RequestInfo(url, method, headers, payload)

        req_obj = Requests(IP=request_info.hostname, Port=request_info.port)
        response_info = req_obj.serverRestAPI(request_info)
        return response_info

    def run(self, url, method, headers=None, payload=None):

        SelfThread.exit_flag = False
        Log.debug(headers)
        request_info = RequestInfo(url, method, headers, payload)
        request_obj = Requests(IP=request_info.hostname, Port=request_info.port)

        inject_config = {
            'Headers': {
                'enabled': eval(DefaultConfig.get_value('System', 'InjectHeaders')),
                'inject_point_list':  request_info.get_header_inject_point(),
                'replace': request_info.header_replace
            },
            'Payloads': {
                'enabled': eval(DefaultConfig.get_value('System', 'InjectPayloads')),
                'inject_point_list':  request_info.get_payload_inject_point(),
                'replace': request_info.payload_replace
            },
            'Parameters': {
                'enabled': eval(DefaultConfig.get_value('System', 'InjectParameters')),
                'inject_point_list':  request_info.get_parameter_inject_point(),
                'replace': request_info.parameter_relpace
            }
        }

        for inject_cls in InjectorBase.injectors:
            injector = inject_cls(request_obj, request_info)
            injector.do_injection(inject_config)
        Log.report('Finish Command Injection Scan.')

    def stop_scan(self):
        SelfThread.exit_flag = True

    def delete_logs(self):
        self.stop_scan()
        self.delete_debug_file(self.requests_path)
        self.delete_debug_file(self.report_path)
        self.delete_debug_file(self.debug_path)
        os.rmdir(self.log_folder)

    def delete_debug_file(self, file_path):
        if os.path.isfile(file_path):
            Log.critical("The debug file %s has been deleted!", file_path)
            os.remove(file_path)

    def get_progress(self):
        if os.path.isfile(self.report_path):
            with open(self.report_path, 'r') as report:
                data = report.read()
        else:
            data = "The request related data has been deleted already!"
        return data


if __name__ == '__main__':
    import time
    from menu import parse_args
    user_options = parse_args()
    scan = Scan(user_options.debug_level, user_options.task_id)
    scan.run(user_options.url, user_options.method, user_options.headers, user_options.payload)
