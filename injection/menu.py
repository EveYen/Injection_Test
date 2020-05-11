# TODO: design input format
import argparse

def check_method(value):
    if str(value).upper() in ['POST', 'GET', 'PUT', 'DELETE']:
        return str(value).upper()
    raise argparse.ArgumentTypeError('Invalid value! Use the right request methd.')

def check_debug_level(value):
    if str(value) in ['0', '1', '2', '3', '4', '5']:
        return int(value)
    raise argparse.ArgumentTypeError('Invalid value! Use 0~5 to set debug level: REQUEST=0, DEBUG=1, INFO=2, WARNING=3, ERROR=4, CRITICAL=5.')

def parse_args():
    parser = argparse.ArgumentParser(description='Injection tool')

    general_group = parser.add_argument_group('Request information', 'Specify the detail info for target injection url.')
    general_group.add_argument('-U', '--url', required=True, type=str, help='Targrt URL')
    general_group.add_argument('-M', '--method', required=True, type=check_method, help='The request method')
    general_group.add_argument('-P', '--payload', type=str, help='The request payload')
    general_group.add_argument('-H', '--headers', type=str, default=None, help='The request headers')

    general_group.add_argument('-debug', '--debug_level', type=check_debug_level, default=4, help='Debug level, REQUEST=0, DEBUG=1, INFO=2, WARNING=3, ERROR=4, CRITICAL=5')
    general_group.add_argument('-task_id', dest="task_id",type=str, help='Task ID for Burpsuite to control.')

    args = parser.parse_args()
    return args