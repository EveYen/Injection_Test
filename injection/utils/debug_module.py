import sys
import datetime
import logging

execute_time = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')

class Logger(object):
    """docstring for Logger"""
    def __init__(self):
        self.formatter = RequestFormatter()
        self.add_custom_log_level()
        self._logger = None

    @property
    def logger(self):
        return self._logger

    @logger.setter
    def logger(self, logger):
        self._logger = logger

    def set_default_level(self, level):
        self.logger.setLevel(level)

    def add_custom_log_level(self):
        logging.REQUEST = 5
        logging.addLevelName(logging.REQUEST, 'REQUEST')
        logging.REPORT = 60
        logging.addLevelName(logging.REPORT, 'REPORT')

        def request(self, message, *args, **kws):
            self.log(logging.REQUEST, message, *args, **kws)

        def report(self, message, *args, **kws):
            self.log(logging.REPORT, message, *args, **kws)

        logging.Logger.request = request
        logging.Logger.report = report

    def write_log_mode(self, log_file_name, log_level, only_this_level=False):
        # output in file
        f_handler = logging.FileHandler(log_file_name)
        f_handler.setFormatter(self.formatter)
        f_handler.setLevel(log_level)
        if only_this_level:
            f_handler.addFilter(LevelFilter(log_level))
        self.logger.addHandler(f_handler)

    def print_log_mode(self, log_level, only_this_level=False):
        s_handler = logging.StreamHandler(sys.stdout)
        s_handler.setFormatter(self.formatter)
        s_handler.setLevel(log_level)
        if only_this_level:
            s_handler.addFilter(LevelFilter(log_level))
        self.logger.addHandler(s_handler)


class RequestFormatter(logging.Formatter):
    request_fmt = "%(message)s"
    report_fmt = "%(message)s"

    def __init__(self, fmt="%(asctime)s [%(levelname)-10s] %(message)s"):
        logging.Formatter.__init__(self, fmt)

    def format(self, record):
        # Save the original format configured by the user
        # when the logger formatter was instantiated
        format_orig = self._fmt

        # Replace the original format with one customized by logging level
        if record.levelno < 10:
            self._fmt = RequestFormatter.request_fmt
        if record.levelno > 50:
            self._fmt = RequestFormatter.report_fmt
        if record.levelno == 20:
            self._fmt = RequestFormatter.report_fmt

        # Call the original formatter class to do the grunt work
        result = logging.Formatter.format(self, record)

        # Restore the original format configured by the user
        self._fmt = format_orig
        return result


class LevelFilter(object):
    def __init__(self, level):
        self.__level = level

    def filter(self, logRecord):
        return logRecord.levelno == self.__level

# share logger object in a thread
Logger_obj = Logger()

class Log(object):
    @classmethod
    def request(cls, *args, **kwargs):
        return Logger_obj.logger.request(*args, **kwargs)

    @classmethod
    def debug(cls, *args, **kwargs):
        return Logger_obj.logger.debug(*args, **kwargs)

    @classmethod
    def warning(cls, *args, **kwargs):
        return Logger_obj.logger.warning(*args, **kwargs)

    @classmethod
    def info(cls, *args, **kwargs):
        return Logger_obj.logger.info(*args, **kwargs)

    @classmethod
    def error(cls, *args, **kwargs):
        return Logger_obj.logger.error(*args, **kwargs)

    @classmethod
    def critical(cls, *args, **kwargs):
        return Logger_obj.logger.critical(*args, **kwargs)

    @classmethod
    def report(cls, *args, **kwargs):
        return Logger_obj.logger.report(*args, **kwargs)


if __name__ == '__main__':
    # output in terminal
    Logger_obj.logger = 'hello'
    Logger_obj.set_default_level(logging.REQUEST)
    Logger_obj.print_log_mode(logging.REQUEST)
    # output in file
    #Logger_obj.write_log_mode('Injection_test_debug_{}.log'.format(execute_time), logging.DEBUG, False)
    #Logger_obj.write_log_mode('Injection_test_request_{}.log'.format(execute_time), logging.REQUEST, True)
    logger = Logger_obj.logger

    logger.debug('This is a debug message')
    logger.info('This is an info message')
    logger.warning('This is a warning message')
    logger.error('This is an error message')
    logger.critical('This is a critical message')
    info = """
        GET /account/loginstate HTTP/1.1
        Host: dotblogs.com.tw
        Accept: */*
        Connection: close
        Cookie: _ga=GA1.3.1406543465.1547018057; __atuvc=0%7C13%2C0%7C14%2C0%7C15%2C0%7C16%2C6%7C17; ARRAffinity=e635d98f14f9f754b56eb63e9f833992b2a1734c991c38716cf89b1f76c95083; __atssc=google%3B4; __utma=49683379.1406543465.1547018057.1547435190.1547435190.1; __utmz=49683379.1547435190.1.1.utmcsr=google|utmccn=(organic)|utmcmd=organic|utmctr=(not%20provided); ai_user=CUHSc|2019-01-09T07:12:14.915Z
        User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
        Accept-Language: zh-tw
        Referer: https://dotblogs.com.tw/hatelove/2012/11/02/learning-tdd-in-30-days-day1-tdd-guidance
        Accept-Encoding: gzip, deflate
        """
    logger.request(info)