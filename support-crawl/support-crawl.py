# coding: utf-8
from burp import IBurpExtender
from burp import IParameter
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import Clipboard, StringSelection
import random
import string

class BurpExtender(IBurpExtender, IContextMenuFactory, IContextMenuInvocation):
    def __init__(self):
        self.extentionName  = "Support Crawl"
        self.menuName       = "Parameter Check"
        self.comp_color     = "none" # red, magenta, yellow, green, cyan, blue, pink, purple, gray, none=white
        self.comment        = "No.{} is equal to No.{}"
        self.rdb            = RequestDictDB()
        self.rcmp           = RequestComparsion()

    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        menu = []
        menu.append(JMenuItem(self.menuName, actionPerformed=lambda x, inv=invocation: self.parameterCheck(inv)))
        return menu

    def parameterCheck(self, inv):
        for idx, messageInfo in enumerate(inv.getSelectedMessages()):
            requestInfo     = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
            url             = requestInfo.getUrl()
            method          = requestInfo.getMethod()
            parameters      = requestInfo.getParameters()
            method_url      = '{}{}://{}{}'.format(method, url.getProtocol(), url.getHost(), url.getPath())

            messageInfo.setComment("No.{}".format(idx + 1))
            for rkey, saved_request in self.rdb.get_request_info(method_url).items():
                if self.rcmp.comparsion_parameter(parameters, saved_request['Parameters']):
                    messageInfo.setComment(self.comment.format(idx+1, saved_request['Request number']))
                    break

            self.rdb.set_request(idx+1, requestInfo)
        self.rdb.delete_requests()

class RequestComparsion():
    # ヘッダーの比較
    def comparsion_header(self, current_headers, headers):
        cheaders = {}
        for current_header in current_headers:
            ch = current_header.split(": ", 1)
            if len(ch) == 2 and ch[0] != "Cookie":
                cheaders[ch[0]] = ch[1]
        return cheaders == headers
    
    # パラメータの比較
    def comparsion_parameter(self, current_parameters, parameters):
        cparameters = {}
        for current_parameter in current_parameters:
            if current_parameter.getType() != IParameter.PARAM_COOKIE:
                cparameters[current_parameter.getName()] = current_parameter.getValue()
        return cparameters == parameters

    # クッキーの比較
    def comparsion_cookies(self, current_cookies, cookies):
        ccookies = {}
        for current_cookie in current_cookies:
            if current_cookie.getType() == IParameter.PARAM_COOKIE:
                ccookies[current_cookie.getName()] = current_cookie.getValue()
        return ccookies == cookies 

class RequestDictDB():
    def __init__(self):
        self.__REQUEST_DATA = {}

    def set_request(self, idx, requestInfo):
        url             = requestInfo.getUrl()
        method          = requestInfo.getMethod()
        headers         = requestInfo.getHeaders()
        parameters      = requestInfo.getParameters()
        randomstr       = "".join([random.choice(string.ascii_lowercase + string.digits) for i in range(5)])
        method_url      = '{}{}://{}{}#{}'.format(method, url.getProtocol(), url.getHost(), url.getPath(), randomstr)

        self.__REQUEST_DATA[method_url] = {"Request number": 0, "Headers": {}, "Cookies": {}, "Parameters": {}}
        self.__REQUEST_DATA[method_url]['Request number'] = idx
        self.__set_headers(method_url, headers)
        self.__set_parameters(method_url, parameters)
        self.__set_cookies(method_url, parameters)

    def __set_headers(self, key, headers):
        data = self.__REQUEST_DATA[key]['Headers']
        for header in headers:
            h = header.split(": ", 1)
            if len(h) == 2 and h[0] != "Cookie":
                data[h[0]] = h[1]

    def __set_parameters(self, key, parameters):
        data = self.__REQUEST_DATA[key]['Parameters']
        for parameter in parameters:
            if parameter.getType() != IParameter.PARAM_COOKIE:
                data[parameter.getName()] = parameter.getValue()

    def __set_cookies(self, key, cookies):
        data = self.__REQUEST_DATA[key]['Cookies']
        for cookie in cookies:
            if cookie.getType() == IParameter.PARAM_COOKIE:
                data[cookie.getName()] = cookie.getValue()

    def get_request_info(self, key):
        return dict(filter(lambda key_value: key+"#" in key_value[0], self.__REQUEST_DATA.items()))

    def exists_request(self, key):
        return key in self.__REQUEST_DATA.keys()
    
    def delete_requests(self):
        self.__REQUEST_DATA.clear()