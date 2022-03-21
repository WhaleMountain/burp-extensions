# coding: UTF-8

from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from java.io import PrintWriter, File
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import Clipboard, StringSelection

class BurpExtender(IBurpExtender, IProxyListener, IContextMenuFactory, IContextMenuInvocation):
    def __init__(self):
        self.extentionName = "Support Crawl"
        self.menuName = "Copy Request TSV (FULL)"
        self.rdb = RequestDictDB()
        self.rcmp = RequestComparison()
        self.cptsv = CopyToTsv()

    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True) #self._stdout.println()

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerContextMenuFactory(self)
        callbacks.registerProxyListener(self)

    def processProxyMessage(self, messageIsRequest, message):
        if not messageIsRequest:
            return

        messageInfo = message.getMessageInfo()
        requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        url             = requestInfo.getUrl()
        method          = requestInfo.getMethod()
        headers         = requestInfo.getHeaders()
        parameters      = requestInfo.getParameters()
        method_url      = '{}{}://{}{}'.format(method, url.getProtocol(), url.getHost(), url.getPath())

        if not self._callbacks.isInScope(url):
            return

    def createMenuItems(self, invocation):
        menu = []
        menu.append(JMenuItem(self.menuName, actionPerformed=lambda x, inv=invocation: self.copyToTsv(inv)))
        return menu
    
    def copyToTsv(self, inv):
        tsv = ""
        for messageInfo in inv.getSelectedMessages():
            requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
            tsv += self.cptsv.makeTsv(requestInfo)
        self.cptsv.copyTsv(tsv)

class CopyToTsv():
    def __init__(self):
        self.toolkit = Toolkit.getDefaultToolkit()
        self.clipboard = self.toolkit.getSystemClipboard()
        self.tsv_head = "\"{method}\"\t\"{uri}\"\t\"-\"\t\"-\"\t\"-\"\n"
        self.tsv_data = "\"\"\t\"\"\t\"{kind}\"\t\"{key}\"\t\"{value}\"\n"

    def makeTsv(self, requestInfo):
        url             = requestInfo.getUrl()
        method          = requestInfo.getMethod()
        headers         = requestInfo.getHeaders()
        parameters      = requestInfo.getParameters()
        turl      = '{}://{}{}'.format(url.getProtocol(), url.getHost(), url.getPath())

        tsv = self.tsv_head.format(method=method, uri=turl)

        for idx, path in enumerate(url.getPath().split("/")):
            if path == "":
                continue
            tsv += self.tsv_data.format(kind="Path", key=idx, value=path)

        for header in headers:
            h = header.split(": ", 1)
            if len(h) == 2 and h[0] != "Cookie":
                tsv += self.tsv_data.format(kind="Header", key=h[0], value=h[1].encode('utf-8'))

        for parameter in parameters:
            if parameter.getType() == IParameter.PARAM_COOKIE:
                tsv += self.tsv_data.format(kind="Cookie", key=parameter.getName(), value=parameter.getValue().encode('utf-8'))
            elif parameter.getType() == IParameter.PARAM_URL:
                tsv += self.tsv_data.format(kind="URL", key=parameter.getName(), value=parameter.getValue().encode('utf-8'))
            elif parameter.getType() == IParameter.PARAM_BODY:
                tsv += self.tsv_data.format(kind="Body", key=parameter.getName(), value=parameter.getValue().encode('utf-8'))
            elif parameter.getType() == IParameter.PARAM_JSON:
                tsv += self.tsv_data.format(kind="Body", key="jsonData["+parameter.getName()+"]", value=parameter.getValue().encode('utf-8'))
            else:
                tsv += self.tsv_data.format(kind="Unknown", key=parameter.getName(), value=parameter.getValue().encode('utf-8'))
        return tsv
        
    def copyTsv(self, tsv):
        selection = StringSelection(tsv)
        self.clipboard.setContents(selection, selection)

class RequestComparison():
    # ヘッダー数の比較
    # 現在リクエストヘッダーが多いと True
    def comparison_length_header(self, current_headers, headers):
        cheader = {}
        for current_header in current_headers:
            ch = current_header.split(": ", 1)
            if len(ch) == 2 and h[0] != "Cookie":
                cheader[ch[0]] = ch[1]
        return len(cheader) > len(headers)
    
    # パラメータ数の比較
    # 現在リクエストパラメータが多いと True
    def comparison_length_parameter(self, current_parameters, parameters):
        cparameter = {}
        for current_parameter in current_parameters:
            if current_parameter.getType() != IParameter.PARAM_COOKIE:
                cparameter[current_parameter.getName()] = current_parameter.getValue()
        return len(cparameter) > len(parameters)

    # クッキー数の比較
    # 現在リクエストクッキーが多いと True
    def comparison_length_cookie(self, current_cookies, cookies):
        ccookie = {}
        for current_cookie in current_cookies:
            if current_cookie.getType() == IParameter.PARAM_COOKIE:
                ccookie[current_cookie.getName()] = current_cookie.getValue()
        return len(ccookie) > len(cookies)

    # ヘッダー値の比較
    # 現在リクエストヘッダー値が1つでも違うと True
    def comparison_value_header(self, current_headers, headers):
        for current_header in current_headers:
            ch = current_header.split(": ", 1)
            if len(ch) == 2 and h[0] != "Cookie":
                if ch[0] in headers.keys():
                    return ch[1] != headers[ch[0]]
        return False
    
    # パラメータ値の比較
    # 現在リクエストパラメータ値が1つでも違うと True
    def comparison_value_parameter(self, current_parameters, parameters):
        for current_parameter in current_parameters:
            if current_parameter.getType() != IParameter.PARAM_COOKIE:
                if current_parameter.getName() in parameters.keys():
                    return current_parameter.getValue() != parameters[current_parameter.getName()]
        return False

    # クッキー値の比較
    # 現在リクエストクッキー値が1つでも違うと True
    def comparison_value_cookie(self, current_cookies, cookies):
        for current_cookie in current_cookies:
            if current_cookie.getType() == IParameter.PARAM_COOKIE:
                if current_cookie.getName() in cookies.keys():
                    return current_cookie.getValue() != cookies[current_cookie.getName()]
        return False

class RequestDictDB():
    def __init__(self):
        self.__REQUEST_DATA = {}

    def set_request(self, key):
        self.__REQUEST_DATA[key] = {"Headers": {}, "Cookies": {}, "Parameters": {}, "Copyed": False}

    def set_headers(self, key, headers):
        data = self.__REQUEST_DATA[key]['Headers']
        for header in headers:
            h = header.split(": ", 1)
            if len(h) == 2 and h[0] != "Cookie":
                data[h[0]] = h[1]

    def set_parameters(self, key, parameters):
        data = self.__REQUEST_DATA[key]['Parameters']
        for parameter in parameters:
            if parameter.getType() != IParameter.PARAM_COOKIE:
                data[parameter.getName()] = parameter.getValue()

    def set_cookies(self, key, cookies):
        data = self.__REQUEST_DATA[key]['Cookies']
        for cookie in cookies:
            if cookie.getType() == IParameter.PARAM_COOKIE:
                data[cookie.getName()] = cookie.getValue()

    def set_copy(self, key):
        pass

    def get_request_info(self, key):
        return self.__REQUEST_DATA[key]

    def exists_request(self, key):
        return key in self.__REQUEST_DATA.keys()