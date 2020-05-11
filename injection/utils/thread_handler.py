import os
import sys
from utils.config import Config
from utils.debug_module import Log

CONFIG_ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "../config"))

class ThreadHandler(object):
    def __init__(self):
        self.config = None

    def create_thread_control_file(self, task_id):
        file_name = "task_{}.ini".format(task_id)
        file_path = os.path.join(CONFIG_ROOT, file_name)
        if not os.path.isfile(file_path):
            self.config = Config(file_path)
            self.config.add_new_section("Control")
            self.config.add_new_key("Control", "ExitFlag")
            self.config.set_value("Control", "ExitFlag", "False")
        else:
            self.config = Config(file_path)

    @property
    def exit_flag(self):
        self.config.reload()
        return eval(self.config.get_value("Control", "ExitFlag"))

    @exit_flag.setter
    def exit_flag(self, flag):
        self.config.set_value("Control", "ExitFlag", str(bool(flag)))

    def is_exit(self):
        if self.exit_flag:
            Log.critical('Force Exit this thread')
            sys.exit(0)

SelfThread = ThreadHandler()

def set_thread_exit():
    SelfThread.exit_flag(True)
