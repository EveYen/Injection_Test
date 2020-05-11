import re
import ssl
import sys
import gzip
import json
import time
import random
import httplib
import traceback

from utils.debug_module import Log
from user_agent import USER_AGENT

try:
    from cStringIO import StringIO
except:
    from StringIO import StringIO

def traffic_log_record(method, url_path, version, headers, data):
    log = method.upper() + ' '
    log += url_path + ' '
    version_info = 'HTTP/1.0' if version==10 else 'HTTP/1.1'
    log += version_info + '\n'
    for header, value in headers.items():
        log += '{}s: {}\n'.format(header, value)
    log += '\n' + str(data) + '\n\n'
    Log.request(log)

def header_list2dict(list):
    result = {}
    for item in list:
        result[item[0]] = item[1]
    return result

class Requests:
    def __init__(self, IP=None, Port=443, proxy=None):
        self.conn = None
        self.cookie = None
        self.csrf_token = None
        self.IP = IP
        self.Port = Port
        self.proxy = proxy
        self.connInit()

    def __del__(self):
        if self.conn:
            self.conn.close()

    def connInit(self):
        if self.conn is None:
            Log.debug('[Init Connection] Initialize a new connection.')
            if sys.version[0:3] == '2.7':
                self.conn = httplib.HTTPSConnection(
                    self.IP, self.Port, timeout=240, context=ssl.SSLContext(ssl.PROTOCOL_TLSv1_2))
            else:
                self.conn = httplib.HTTPSConnection(self.IP, self.Port, timeout=240)

            if self.proxy is not None:
                Log.debug('Proxy!!!')
                self.conn = httplib.HTTPConnection(self.proxy, self.Port, timeout=20)
        else:
            Log.debug('[Init Connection] Connection is not None. reuse the connection')

    def serverRestAPI(self, request_info):
        
        request_info.headers['User-Agent'] = random.choice(USER_AGENT)

        if self.cookie != None:
            request_info.headers["Cookie"] = "session={0}".format(self.cookie)

        self.connInit()
        #Log.debug('[Send Request] Request method: %s', request_info.method)
        #Log.debug('[Send Request] Request path: %s', request_info.get_entire_path())
        #Log.debug('[Send Request] Request headers: %s', request_info.headers)
        #try:
        #    Log.debug('[Send Request] Request body: ' + json.dumps(json.loads(request_info.body), indent=4))
        #except:
        #    Log.debug('[Send Request] Request body: {}'.format(request_info.body))
        start_request = time.time()
        self.conn.request(request_info.method, request_info.get_entire_path(), body=json.dumps(request_info.body), headers=request_info.headers)
        res = self.conn.getresponse()
        end_request = time.time()
        total_request_time = end_request - start_request 
        res_status = res.status
        res_header = res.getheaders()
        res_body = res.read()

        response = {
            'version': res.version,
            'res_status': res_status,
            'res_headers': res_header,
            'res_body': res_body,
            'res_time': total_request_time
        }

        #Log.debug('[Send Request] Response status: {}'.format(res_status))
        #Log.debug('[Send Request] Response header: {}'.format(res_header))
        #Log.debug('[Send Request] Response body: {}'.format(res_body))
        #Log.debug('[Send Request] Response time: {}'.format(total_request_time))

        #Log.request('[Request]')
        #traffic_log_record(request_info.method, request_info.get_entire_path(), res.version, request_info.headers, request_info.body)
        #Log.request('[Response]')
        #traffic_log_record(request_info.method, request_info.get_entire_path(), res.version, header_list2dict(res_header), res_body)

        return response

if __name__ == "__main__":
    pass
