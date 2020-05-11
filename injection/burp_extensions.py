import re
import os
import sys
import time
import json
import hashlib
import threading
import subprocess
import ConfigParser
import shutil

#import multiprocessing

from burp import ITab
from burp import IBurpExtender, IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IExtensionStateListener
from burp import IMessageEditorTab
from burp import IMessageEditorTabFactory
from javax import swing
from javax.swing import JOptionPane
from javax.swing import SortOrder # for setting table sort order ascending descending unsorted
from javax.swing.table import DefaultTableModel
from javax.swing.table import TableRowSorter # for setting table sort order ascending descending unsorted
from javax.swing import JFileChooser # for importing and exporting dialog boxes
from javax.swing import JFrame # for importing and exporting dialog boxes
from javax.swing.filechooser import FileNameExtensionFilter # for importing and exporting
from java import awt
from java.awt import Font
from java.awt import Color
from java.awt import GridBagLayout



from run import Scan

debug_name2int = {
    'REQUEST INFO': 0,
    'DEBUG': 1,
    'INFO': 2,
    'WARNING': 3,
    'ERROR': 4,
    'CRITICAL': 5
}
debug_level = debug_name2int.keys()
METHODS = ['GET', 'POST', 'PUT', 'DELETE']
debuglog_path = os.path.normpath(os.path.join(os.path.dirname(os.getcwd()), 'injection', 'logs'))
flag_path = os.path.normpath(os.path.join(os.path.dirname(os.getcwd()), 'injection', 'config'))

class RunScan(object):
    """docstring for RunScan"""
    def __init__(self, task_id):
        super(RunScan, self).__init__()
        self.task_id = task_id
        self.config_path = os.path.join(flag_path, "task_{}.ini".format(self.task_id))
        self.log_folder = os.path.join(debuglog_path, self.task_id)
        self.request_content = None
        self.overview_list = None

    def run_scan(self, target_url, method, header, payload, debug_level):
        subprocess.Popen(["python", "run.py", "-U", str(target_url), "-M", str(method), "-P", str(payload), "-H", str(header), "-debug", str(debug_level), "-task_id", self.task_id])

    def stop_scan(self):
        config = ConfigParser.RawConfigParser()
        config.read(self.config_path)
        config.set("Control", "ExitFlag", "True")
        with open(self.config_path, 'w') as configfile:
            config.write(configfile)

    def get_progress(self):
        report_file = os.path.join(self.log_folder, "Injection_test_report.log")
        #print report_file
        if os.path.isfile(report_file):
            with open(report_file, 'r') as report:
                data = report.read()
        else:
            data = "The request related data has been deleted already!"
        return data

    def delete_logs(self):
        shutil.rmtree(self.log_folder)
        os.remove(self.config_path)

    def read_result(self):
        self.request_content = None
        request_path = os.path.join(self.log_folder, "Injection_test_burpinfo.log")
        #print request_path
        if os.path.isfile(request_path):
            with open(request_path, 'r') as requestfile:
                all_request = requestfile.readlines()
            self.request_content = self.parse_request_content(all_request)
            return self.request_content
        else:
            return None

    def parse_request_content(self, all_request):
        result = []
        for index, each_request in enumerate(all_request):
            current_request = eval(each_request)
            current_request['id'] = index + 1
            result.append(current_request)
        return result


class BurpExtender(IBurpExtender, IContextMenuFactory, ITab, IExtensionStateListener):
    ''' Implements IBurpExtender for hook into burp and inherit base classes.
     Implement IMessageEditorTabFactory to access createNewInstance.
    '''
    threads = {}
    # implement Tab title
    def getTabCaption(self):
        return 'CMDinjection'

    def getUiComponent(self):
        return self._jConfigTab

    # implement UI components
    def registerExtenderCallbacks(self, callbacks):

        sys.stdout = callbacks.getStdout()
        self._callbacks = callbacks
        callbacks.setExtensionName("CMDinjection")
        callbacks.registerExtensionStateListener(self)
        self._helpers = callbacks.getHelpers()
        self.is_logger_init = False
        callbacks.registerContextMenuFactory(self)

        self._jConfigTab = swing.JTabbedPane()
        self.arrange_request_tab()
        self.arrange_detail_tab()
        
        callbacks.customizeUiComponent(self._jConfigTab)
        callbacks.addSuiteTab(self)
        return

    def arrange_request_tab(self):
        self._jRequestPanel = swing.JPanel()
        self._jRequestPanel.setLayout(None)
        self._jRequestPanel.setPreferredSize(awt.Dimension(1368,1368))

        self._jLabelDecpription1 = swing.JLabel("Command Injection")
        self._jLabelDecpription1.setFont(Font(Font.DIALOG, Font.BOLD, 40))
        self._jLabelDecpription1.setForeground(Color.PINK)
        self._jLabelDecpription1.setBounds(10, 10, 800, 50)
        self._jRequestPanel.add(self._jLabelDecpription1)

        self._jLabelDecpription2 = swing.JLabel()
        self._jLabelDecpription2.setText("Input a request information and your settings.")
        self._jLabelDecpription2.setBounds(10, 70, 300, 20)
        self._jRequestPanel.add(self._jLabelDecpription2)

        self._jLabelScanIPListen = swing.JLabel()
        self._jLabelScanIPListen.setText('URL:')
        self._jLabelScanIPListen.setBounds(10, 100, 150, 30)
        self._jRequestPanel.add(self._jLabelScanIPListen)

        self._jTextFieldScanURL = swing.JTextField()
        self._jTextFieldScanURL.setBounds(120, 100, 500, 30)
        self._jRequestPanel.add(self._jTextFieldScanURL)

        # Method
        self._jLabelScanMethod = swing.JLabel()
        self._jLabelScanMethod.setText('Set method:')
        self._jLabelScanMethod.setBounds(10, 140, 150, 30)
        self._jRequestPanel.add(self._jLabelScanMethod)

        self._jComboScanMethod = swing.JComboBox(METHODS)
        self._jComboScanMethod.setSelectedIndex(0)
        self._jComboScanMethod.setBounds(120, 140, 500, 30)
        self._jRequestPanel.add(self._jComboScanMethod)

        # Payloads
        self._jLabelScanPayload = swing.JLabel()
        self._jLabelScanPayload.setText('Post Data:')
        self._jLabelScanPayload.setBounds(10, 180, 150, 30)
        self._jRequestPanel.add(self._jLabelScanPayload)

        self._jTextAreaScanPayload = swing.JTextArea()
        self._jTextAreaScanPayload.setLineWrap(True)
        self._jTextAreaScanPayload.setEditable(True)
        self._jScrollPanePayload = swing.JScrollPane(self._jTextAreaScanPayload)
        self._jScrollPanePayload.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jScrollPanePayload.setBounds(120, 180, 500, 100)
        self._jRequestPanel.add(self._jScrollPanePayload)

        # Headers Area
        self._jLabelScanCookies = swing.JLabel()
        self._jLabelScanCookies.setText('Cookies:')
        self._jLabelScanCookies.setBounds(10, 290, 150, 30)
        self._jRequestPanel.add(self._jLabelScanCookies)

        self._jTextFieldCookies = swing.JTextField()
        self._jTextFieldCookies.setBounds(120, 290, 500, 30)
        self._jRequestPanel.add(self._jTextFieldCookies)

        self._jCheckCookies = swing.JCheckBox('Test this header.')
        self._jCheckCookies.setBounds(620, 290, 150, 30)
        self._jRequestPanel.add(self._jCheckCookies)

        self._jLabelScanReferer = swing.JLabel()
        self._jLabelScanReferer.setText('Referer:')
        self._jLabelScanReferer.setBounds(10, 330, 150, 30)
        self._jRequestPanel.add(self._jLabelScanReferer)

        self._jTextFieldReferer = swing.JTextField()
        self._jTextFieldReferer.setBounds(120, 330, 500, 30)
        self._jRequestPanel.add(self._jTextFieldReferer)

        self._jCheckReferer = swing.JCheckBox('Test this header.')
        self._jCheckReferer.setBounds(620, 330, 150, 30)
        self._jRequestPanel.add(self._jCheckReferer)

        self._jLabelScanUserAgent = swing.JLabel()
        self._jLabelScanUserAgent.setText('User-Agent:')
        self._jLabelScanUserAgent.setBounds(10, 370, 150, 30)
        self._jRequestPanel.add(self._jLabelScanUserAgent)

        self._jTextFieldUserAgent = swing.JTextField()
        self._jTextFieldUserAgent.setBounds(120, 370, 500, 30)
        self._jRequestPanel.add(self._jTextFieldUserAgent)

        self._jCheckUserAgent = swing.JCheckBox('Test this header.')
        self._jCheckUserAgent.setBounds(620, 370, 150, 30)
        self._jRequestPanel.add(self._jCheckUserAgent)

        self._jLabelScanHeader = swing.JLabel()
        self._jLabelScanHeader.setText('Custom headers:')
        self._jLabelScanHeader.setBounds(10, 410, 150, 30)
        self._jRequestPanel.add(self._jLabelScanHeader)

        self._jTextAreaScanHeader = swing.JTextArea()
        self._jTextAreaScanHeader.setLineWrap(True)
        self._jTextAreaScanHeader.setEditable(True)
        self._jScrollPaneHeader = swing.JScrollPane(self._jTextAreaScanHeader)
        self._jScrollPaneHeader.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jScrollPaneHeader.setBounds(120, 410, 500, 100)
        self._jRequestPanel.add(self._jScrollPaneHeader)

        self._jButtonTestConnection = swing.JButton('Test Connection', actionPerformed=self.test_connection)
        self._jButtonTestConnection.setBounds(90, 560, 150, 30)
        self._jRequestPanel.add(self._jButtonTestConnection)

        self._jButtonStartScan = swing.JButton('Send', actionPerformed=self.thread_run_scan)
        self._jButtonStartScan.setBounds(240, 560, 150, 30)
        self._jRequestPanel.add(self._jButtonStartScan)

        self._jButtonStartScan = swing.JButton('Clear', actionPerformed=self.clear)
        self._jButtonStartScan.setBounds(390, 560, 150, 30)
        self._jRequestPanel.add(self._jButtonStartScan)
        
        '''
        self._jLabelScanHeader = swing.JLabel()
        self._jLabelScanHeader.setText('Debug level:')
        self._jLabelScanHeader.setBounds(10, 520, 150, 30)
        self._jRequestPanel.add(self._jLabelScanHeader)

        self._JComboDebugLevel = swing.JComboBox(debug_level)
        self._JComboDebugLevel.setSelectedIndex(0)
        self._JComboDebugLevel.setBounds(120, 520, 150, 30)
        self._jRequestPanel.add(self._JComboDebugLevel)

        # TODO: remove this testing button after developement
        self._jButtonTestData = swing.JButton('Test Data', actionPerformed=self.add_test_data)
        self._jButtonTestData.setBounds(90, 600, 150, 30)
        self._jRequestPanel.add(self._jButtonTestData)
        '''

        #self._JBarProgress = swing.JProgressBar(0, 100, value=50, stringPainted=True)
        #self._JBarProgress.setBounds(10, 580, 600, 20)

        self._jConfigTab.addTab("Request", self._jRequestPanel)

    def arrange_detail_tab(self):
        self._jDetailPanel = swing.JPanel()
        self._jDetailPanel.setLayout(None)
        self._jDetailPanel.setPreferredSize(awt.Dimension(1368,1368))

        self._jLabelThreadTitle = swing.JLabel("Select a scan thread:")
        self._jLabelThreadTitle.setFont(Font(Font.DIALOG, Font.BOLD, 12))
        self._jLabelThreadTitle.setForeground(Color.BLACK)
        self._jLabelThreadTitle.setBounds(10, 10, 500, 20)
        self._jDetailPanel.add(self._jLabelThreadTitle)

        self._JComboThreads = swing.JComboBox([''])
        self._JComboThreads.setSelectedIndex(0)
        self._JComboThreads.setBounds(10, 30, 500, 30)
        self._jDetailPanel.add(self._JComboThreads)

        self._jButtonProgress = swing.JButton('Get Progress', actionPerformed=self.get_progress)
        self._jButtonProgress.setBounds(15, 70, 115, 30)
        self._jDetailPanel.add(self._jButtonProgress)

        self._jButtonStopScan = swing.JButton('Stop Scan', actionPerformed=self.stop_scan)
        self._jButtonStopScan.setBounds(140, 70, 115, 30)
        self._jDetailPanel.add(self._jButtonStopScan)

        self._jButtonDeleteLog = swing.JButton('Delete Logs', actionPerformed=self.delete_log)
        self._jButtonDeleteLog.setBounds(265, 70, 115, 30)
        self._jDetailPanel.add(self._jButtonDeleteLog)

        self._jButtonGetDetail = swing.JButton('Get detail', actionPerformed=self.get_detail)
        self._jButtonGetDetail.setBounds(390, 70, 115, 30)
        self._jDetailPanel.add(self._jButtonGetDetail)

        self._jLabelProgressTitle = swing.JLabel("Progress")
        self._jLabelProgressTitle.setFont(Font(Font.DIALOG, Font.BOLD, 12))
        self._jLabelProgressTitle.setForeground(Color.BLACK)
        self._jLabelProgressTitle.setBounds(10, 110, 500, 20)
        self._jDetailPanel.add(self._jLabelProgressTitle)

        self._jTextAreaScanProgress = swing.JTextArea()
        self._jTextAreaScanProgress.setLineWrap(True)
        self._jTextAreaScanProgress.setEditable(False)
        self._jScrollScanProgress = swing.JScrollPane(self._jTextAreaScanProgress)
        self._jScrollScanProgress.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jScrollScanProgress.setBounds(10, 130, 500, 500)
        self._jDetailPanel.add(self._jScrollScanProgress)

        self._jLabelInjectRequestTitle = swing.JLabel("All requests, select to see the request detail.")
        self._jLabelInjectRequestTitle.setFont(Font(Font.DIALOG, Font.BOLD, 12))
        self._jLabelInjectRequestTitle.setForeground(Color.BLACK)
        self._jLabelInjectRequestTitle.setBounds(550, 10, 700, 20)
        self._jDetailPanel.add(self._jLabelInjectRequestTitle)

        self.table_data = [['1a','1b', '1c'], ['2a','2b', '2c']]
        self.table_header = ['#', 'Inject_type', 'Result','Seperator', 'Command', 'Keys']
        self.table_model = CustomDefaultTableModel(None, self.table_header)
        self._jTextAreaInjectRequest = CustomTable(self, self.table_model)
        self._jTextAreaInjectRequest.setRowSorter(CustomTableRowSorter(self.table_model))
        self._jScrollInjectReques = swing.JScrollPane(self._jTextAreaInjectRequest)
        self._jScrollInjectReques.setVerticalScrollBarPolicy(swing.JScrollPane.VERTICAL_SCROLLBAR_ALWAYS)
        self._jScrollInjectReques.setBounds(550, 30, 700, 200)
        self._jDetailPanel.add(self._jScrollInjectReques)

        self._dictionaryOfTextAreas = {}

        self._request_detail_title = swing.JLabel("Request Detail")
        self._request_detail_title.setFont(Font(Font.DIALOG, Font.BOLD, 12))
        self._request_detail_title.setForeground(Color.BLACK)
        self._request_detail_title.setBounds(550, 240, 340, 20)
        self._jDetailPanel.add(self._request_detail_title)

        self._dictionaryOfTextAreas['Request'] = swing.JTextArea()
        self._dictionaryOfTextAreas['Request'].setEditable(False)
        self._request_detail_scroll_pane = swing.JScrollPane(self._dictionaryOfTextAreas['Request'])
        self._request_detail_scroll_pane.setBounds(550, 260, 340, 200)
        self._jDetailPanel.add(self._request_detail_scroll_pane)

        self._response_detail_title = swing.JLabel("Response Detail")
        self._response_detail_title.setFont(Font(Font.DIALOG, Font.BOLD, 12))
        self._response_detail_title.setForeground(Color.BLACK)
        self._response_detail_title.setBounds(910, 240, 340, 20)
        self._jDetailPanel.add(self._response_detail_title)

        self._dictionaryOfTextAreas['Response'] = swing.JTextArea()
        self._dictionaryOfTextAreas['Response'].setEditable(False)
        self._response_detail_scroll_pane = swing.JScrollPane(self._dictionaryOfTextAreas['Response'])
        self._response_detail_scroll_pane.setBounds(910, 260, 340, 200)
        self._jDetailPanel.add(self._response_detail_scroll_pane)

        self._result_detail_title = swing.JLabel("Injection Result")
        self._result_detail_title.setFont(Font(Font.DIALOG, Font.BOLD, 12))
        self._result_detail_title.setForeground(Color.BLACK)
        self._result_detail_title.setBounds(550, 460, 700, 20)
        self._jDetailPanel.add(self._result_detail_title)

        self._dictionaryOfTextAreas['Result'] = swing.JTextArea()
        self._dictionaryOfTextAreas['Result'].setBounds(550, 480, 700, 50)
        self._jDetailPanel.add(self._dictionaryOfTextAreas['Result'])

        self._jButtonDownloadLogs = swing.JButton('Download logs', actionPerformed=self.download_all_logs)
        self._jButtonDownloadLogs.setBounds(1000, 540, 115, 30)
        self._jDetailPanel.add(self._jButtonDownloadLogs)

        self._jConfigTab.addTab("Detail", self._jDetailPanel)

    def createMenuItems(self, invocation):
        menu = []
        # Which part of the interface the user selects
        ctx = invocation.getInvocationContext()
        # Message Viewer Req will show menu item if selected by the user
        if ctx == 0 or ctx == 2:
          menu.append(swing.JMenuItem("Commnad Injection", None, actionPerformed=lambda x, inv=invocation: self.add_current_request(inv)))
        return menu if menu else None

    # TODO: remove this testing button after developement
    def add_test_data(self, button):
        self._jTextFieldScanURL.setText('https://127.0.0.1/injectable ')
        self._jTextAreaScanPayload.setText('{"key": "value"}')
        self._jComboScanMethod.setSelectedIndex(METHODS.index('POST'))
        self._jTextAreaScanHeader.setText('{"Content-Type": "application/json"}')

    # support add intercepted request to test
    def add_current_request(self, invocation):
        try:
            invMessage = invocation.getSelectedMessages()
            message = invMessage[0]
            reqInfo = self._helpers.analyzeRequest(message)
            
            url = str(reqInfo.getUrl())
            data = self._helpers.bytesToString(message.getRequest()[reqInfo.getBodyOffset():])
            method = str(reqInfo.getMethod()).upper()
            headers = self.parse_headers(list(reqInfo.getHeaders()))

            self._jTextFieldScanURL.setText(url)
            self._jTextAreaScanPayload.setText(data)
            self._jComboScanMethod.setSelectedIndex(METHODS.index(method))
            self._jTextFieldUserAgent.setText(headers.pop('User-Agent', ''))
            self._jTextFieldReferer.setText(headers.pop('Referer', ''))
            self._jTextFieldCookies.setText(headers.pop('Cookie', ''))
            # Some excluded header
            headers.pop('Origin', '')
            headers.pop('Accept', '')
            headers.pop('Host', '')
            headers.pop('Pragma', '')
            headers.pop('Expires', '')
            headers.pop('Cache-Control', '')
            headers.pop('Connection', '')
            headers.pop('X-Requested-With', '')
            headers.pop('Content-Length', '')
            self._jTextAreaScanHeader.setText(json.dumps(headers))

        except:
            print 'Failed to add data to scan tab.'

    def get_logger_level(self):
        #level = self._JComboDebugLevel.getSelectedItem()
        level = "DEBUG"
        return debug_name2int[level]

    def parse_headers(self, headers):
        result_headers = {}
        for entry in headers:
            if ': ' in entry:
                key = entry.split(': ')[0]
                value = entry.split(': ')[-1]
                result_headers[key] = value
        return result_headers

    def thread_run_scan(self, button):
        target_url, method, header, payload = self.get_test_info()
        thread_md5 = self.gen_task_id(target_url, method, header, payload)
        thread_name = target_url + '_' + thread_md5

        if not hasattr(self, 'threads'):
            self.threads = {}

        current_scan = RunScan(thread_md5)
        current_scan.run_scan(target_url, method, header, payload, self.get_logger_level())

        self.threads[thread_name] = current_scan

        self._JComboThreads.addItem(thread_name)
        result_string = 'The scan thread name is {}\nYou can check progress/stop/delete at Detail Tab.'.format(thread_name)
        JOptionPane.showMessageDialog(self._jRequestPanel, result_string, 'The scan is started!', JOptionPane.INFORMATION_MESSAGE)

    def gen_task_id(self, target_url, method, header, payload):
        md5_obj = hashlib.md5()
        md5_obj.update(target_url)
        md5_obj.update(method)
        md5_obj.update(header)
        md5_obj.update(payload)
        md5_obj.update(str(time.time()))
        return str(md5_obj.hexdigest())

    def test_connection(self, button):
        target_url, method, header, payload = self.get_test_info()

        scan = Scan(70)
        response_info = scan.test_conncetion(target_url, method, header, payload)
        header_pretty = ''
        for header in response_info['res_headers']:
            header_pretty += '\n\t\t\t' + header[0] + ': ' + header[1]
        result_string = """Request Result:\nStatus: {status}\nHeader: {header}\nBody: {body}\nTotal Time: {time}""".format(status=response_info['res_status'], header=header_pretty, body=response_info['res_body'], time=response_info['res_time'])
        JOptionPane.showMessageDialog(self._jRequestPanel, result_string, 'Test connection result', JOptionPane.INFORMATION_MESSAGE)

    def clear(self, button):
        self._jTextFieldScanURL.setText('')
        self._jComboScanMethod.setSelectedIndex(0)
        self._jTextAreaScanPayload.setText('')
        self._jTextFieldCookies.setText('')
        self._jTextFieldReferer.setText('')
        self._jTextFieldUserAgent.setText('')
        self._jTextAreaScanHeader.setText('')

    def get_progress(self, button):
        thread_name = self._JComboThreads.getSelectedItem()
        target_scan = self.threads[thread_name]
        self._jTextAreaScanProgress.setText(target_scan.get_progress())

    def stop_scan(self, button):
        thread_name = self._JComboThreads.getSelectedItem()
        target_scan = self.threads[thread_name]
        target_scan.stop_scan()

    def delete_log(self, button):
        thread_name = self._JComboThreads.getSelectedItem()
        target_scan = self.threads[thread_name]
        target_scan.delete_logs()
        self._JComboThreads.removeItem(thread_name)
        self._jTextAreaScanProgress.setText('')
        del self.threads[thread_name]

    def get_detail(self, button):
        thread_name = self._JComboThreads.getSelectedItem()
        target_scan = self.threads[thread_name]
        # clear table row
        self.table_model.setRowCount(0)
        # add all result rows
        self.result_data = target_scan.read_result()
        for row_result in self.result_data:
            # '#', 'Inject_type', 'Result','Seperator', 'Command', 'Keys')
            self.table_model.addRow([row_result['id'], row_result['inject_method'], row_result['result'], row_result['seperator'], row_result['command'], row_result['inject_key']])

    def get_request_print_format(self, data):
        log = data['req_method'].upper() + ' '
        log += data['req_path'] + ' '
        version_info = 'HTTP/1.0' if data['version']==10 else 'HTTP/1.1'
        log += version_info + '\n'
        for header, value in data['req_headers'].items():
            log += '{}s: {}\n'.format(header, value)
        log += '\n' + str(data['req_body']) + '\n\n'
        return log

    def get_response_print_format(self, data):
        log = data['req_method'].upper() + ' '
        log += data['req_path'] + ' '
        version_info = 'HTTP/1.0' if data['version']==10 else 'HTTP/1.1'
        log += version_info + '\n'
        for header, value in data['res_headers']:
            log += '{}s: {}\n'.format(header, value)
        log += '\n' + str(data['res_body'])
        log += '\nTotal request time: ' + str(data['res_time'])

        return log

    def get_result_print_format(self, data):
        if data['result']:
            return 'The key {} in {} is Injectable.'.format(data['inject_key'], data['target'])
        return 'Not injectable for this request combination.'

    def get_test_info(self):
        target_url = self._jTextFieldScanURL.getText()
        method = self._jComboScanMethod.getSelectedItem()
        print method
        payload = self._jTextAreaScanPayload.getText()
        header = self._jTextAreaScanHeader.getText() or '{}'

        header_json = json.loads(header)

        if self._jCheckUserAgent.isSelected() and self._jTextFieldUserAgent.getText():
            header_json['User-Agent'] = self._jTextFieldUserAgent.getText()

        if self._jCheckReferer.isSelected() and self._jTextFieldReferer.getText():
            header_json['Referer'] = self._jTextFieldReferer.getText()

        if self._jCheckCookies.isSelected() and self._jTextFieldCookies.getText():
            header_json['Cookie'] = self._jTextFieldCookies.getText()

        return target_url, method, json.dumps(header_json), payload

    def extensionUnloaded(self):
        for name, thread_class in self.threads.items():
            thread_class.delete_logs()

    def createDialogBoxForImportExport(self, dialogTitle, extensionFilter, buttonText):

        # create frame
        frameImportExportDialogBox = JFrame()

        # try to load the last used directory
        try:
            # load the directory for future imports/exports
            fileChooserDirectory = self._callbacks.loadExtensionSetting("fileChooserDirectory")

        # there is not a last used directory
        except:
            # set the last used directory to blank
            fileChooserDirectory = ""

        # create file chooser
        fileChooserImportExportDialogBox = JFileChooser(fileChooserDirectory)

        # set dialog title
        fileChooserImportExportDialogBox.setDialogTitle(dialogTitle)

        # create extension filter
        filterImportExportDialogBox = FileNameExtensionFilter(extensionFilter[0], extensionFilter[1])

        # set extension filter
        fileChooserImportExportDialogBox.setFileFilter(filterImportExportDialogBox)

        # show dialog box and get value
        valueFileChooserImportExportDialogBox = fileChooserImportExportDialogBox.showDialog(frameImportExportDialogBox, buttonText)

        # check if a file was not selected
        if valueFileChooserImportExportDialogBox != JFileChooser.APPROVE_OPTION:
        
            # return no path/file selected
            return False, "No Path/File"

        # get the directory
        fileChooserDirectory = fileChooserImportExportDialogBox.getCurrentDirectory()

        # store the directory for future imports/exports
        self._callbacks.saveExtensionSetting("fileChooserDirectory", str(fileChooserDirectory))

        # get absolute path of file
        fileChosenImportExportDialogBox = fileChooserImportExportDialogBox.getSelectedFile().getAbsolutePath()

        # split name and extension
        fileNameImportExportDialogBox, fileExtensionImportExportDialogBox = os.path.splitext(fileChosenImportExportDialogBox)

        # check if file does not have an extention
        if fileExtensionImportExportDialogBox == "":

            # add extension to file
            fileChosenImportExportDialogBox = fileChosenImportExportDialogBox + extensionFilter[2]

        # return dialog box value and path/file
        return True, fileChosenImportExportDialogBox

    def download_all_logs(self, button):

        # set dialog options
        dialogBoxTitle = "Export All logs"
        dialogBoxExtensionFilter = ["TEXT FILES", ["txt"], ".txt"]
        dialogBoxButtonText = "Export"

        # get the selected file
        fileChosen, fileImportExport = self.createDialogBoxForImportExport(dialogBoxTitle, dialogBoxExtensionFilter, dialogBoxButtonText)

        # return if user exited dialog box
        if fileChosen == False:
            return
        try:
            task_id = self._JComboThreads.getSelectedItem().split('_')[-1]
            source_path = os.path.join(debuglog_path, task_id, "Injection_test_request.log")

            # open the file
            shutil.copy2(source_path, fileImportExport)
        except:
            JOptionPane.showMessageDialog(self._jDetailPanel, 'Download Fail!\n Please select a existed process or make sure the detail log is not deleted manually.', 'Warning', JOptionPane.INFORMATION_MESSAGE)
        # return
        return

class CustomTable(swing.JTable):
    def __init__(self, extender, tableModel):
        self.extender = extender
        self.tableModel = tableModel
        self.setModel(tableModel)

    def changeSelection(self, row, column, toggle, extend):

        modelRowIndex = self.convertRowIndexToModel(row)

        swing.JTable.changeSelection(self, row, column, toggle, extend)

        selectedId = self.getValueAt(row, 0)

        data = self.extender.result_data[selectedId - 1]

        self.extender._dictionaryOfTextAreas['Request'].setText(self.extender.get_request_print_format(data))
        self.extender._dictionaryOfTextAreas['Response'].setText(self.extender.get_response_print_format(data))
        self.extender._dictionaryOfTextAreas['Result'].setText(self.extender.get_result_print_format(data))

#
# extend DefaultTableModel to make table cells uneditable
#

class CustomDefaultTableModel(DefaultTableModel):

    # override isCellEditable
    def isCellEditable(self, row, column):

        # make cell uneditable
        return False

#
# extend TableRowSorter to toggle sorting (ascending, descending, unsorted)
#

class CustomTableRowSorter(TableRowSorter):

    # override toggleSortOrder
    def toggleSortOrder(self, column):

        # check if valid column 
        if column >= 0:

            # get the sort keys
            keys = self.getSortKeys()

            # check if the sort keys are not empty
            if keys.isEmpty() == False:

                # get the sort key
                sortKey = keys.get(0)

                # check if the column clicked is sorted in descending order
                if sortKey.getColumn() == column and sortKey.getSortOrder() == SortOrder.DESCENDING:

                    # clear sorting
                    self.setSortKeys(None)

                    # do not continue
                    return

        # toggle default toggleSortOrder
        TableRowSorter.toggleSortOrder(self, column)
