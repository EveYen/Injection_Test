import re
import json
import socket
import urllib
from urlparse import urlparse
from requests import Requests
from headers import HeaderParser
from payload import JsonParser
from parameters import ParameterParser

class RequestInfo(object):
    """docstring for RequestInfo"""
    def __init__(self, url, method, headers=None, body=None):
        self.url = url
        self.parse_url(self.url)
        self.method = method
        self._headers = json.loads(headers) if headers else {}
        self._body = json.loads(body) if body else {}
        # TODO: support other types of body
        self._header_parser = HeaderParser(self.headers)
        self._payload_parser = JsonParser(self.body)
        self._parameter_parser = ParameterParser(self.query)

    def get_header_inject_point(self):
        return self._header_parser.get_inject_place()

    def get_payload_inject_point(self):
        return self._payload_parser.get_inject_place()

    def get_parameter_inject_point(self):
        return self._parameter_parser.get_inject_place()

    def header_replace(self, keys, inject_str):
        self._headers = self._header_parser.replace_target_key(keys, inject_str)

    def payload_replace(self, keys, inject_str):
        self._body = self._payload_parser.replace_target_key(keys, inject_str)

    def parameter_relpace(self, keys, inject_str):
        query_dict = self._parameter_parser.replace_target_key(keys, inject_str)
        self._query = urllib.urlencode(query_dict)#self._parameter_parser.dict2str(query_dict)

    @property
    def url(self):
        return self._url
    
    @url.setter
    def url(self, url):
        self._url = url
        self.parse_url(url)

    @property
    def query(self):
        return self._query or ''

    @property
    def headers(self):
        return self._headers
    
    @property
    def body(self):
        return self._body

    def combine_url(self):
        url = ''
        if self.scheme:
            url += self.scheme + '://'
        url += self.hostname
        if self.port:
            url += ':' + str(self.port)
        url += self.path
        if self._query:
            url += '?' + self._query
        if self.fragment:
            url += '#' + self.fragment
        return url

    def get_entire_path(self):
        url = ''
        url += self.path
        if self._query:
            url += '?' + self._query
        if self.fragment:
            url += '#' + self.fragment
        return url

    def parse_url(self, url):
        parse = urlparse(url)
        self.scheme = parse.scheme
        if parse.port:
            self.hostname = ':'.join(parse.netloc.split(':')[:-1])
        else:
            self.hostname = parse.netloc
        self.path = parse.path
        self.port = parse.port
        self._query = parse.query
        self.fragment = parse.fragment

    def check_ipv6(self, hostname):
        try:
            socket.inet_pton(socket.AF_INET6, hostname)
            return True
        except socket.error:
            return False

    def get_record(self):
        result = {}
        result['req_url'] = self.combine_url()
        result['req_method'] = self.method
        result['req_path'] = self.get_entire_path()
        result['req_headers'] = self.headers
        result['req_body'] = str(self.body) if  self.body else None
        return result 
