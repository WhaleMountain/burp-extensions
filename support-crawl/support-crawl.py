# coding: UTF-8

from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import Clipboard, StringSelection

class BurpExtender(IBurpExtender, IProxyListener, IContextMenuFactory, IContextMenuInvocation):
    def __init__(self):
        self.extentionName = "Support Crawl"
        self.menuName = "Copy Request TSV (FULL)"
        self.comp_color = "gray"
        self.copy_color = 'pink'
        self.comment = "Already copied"
        self.rdb = RequestDictDB()
        self.rcmp = RequestComparison()
        self.cptsv = CopyToTsv()

    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()

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
        
        if self.rdb.exists_request(method_url):
            saved_request = self.rdb.get_request_info(method_url)
            if (self.rcmp.comparsion_header(headers, saved_request['Headers'])
            and self.rcmp.comparsion_parameter(parameters, saved_request['Parameters'])
            and self.rcmp.comparsion_cookies(parameters, saved_request['Cookies'])):
                messageInfo.setHighlight(self.comp_color)
                messageInfo.setComment(self.comment)

    def createMenuItems(self, invocation):
        menu = []
        menu.append(JMenuItem(self.menuName, actionPerformed=lambda x, inv=invocation: self.copyToTsv(inv)))
        return menu
    
    def copyToTsv(self, inv):
        tsv = ""
        for messageInfo in inv.getSelectedMessages():
            requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
            tsv += self.cptsv.makeTsv(requestInfo)
            self.rdb.set_request(requestInfo)
            messageInfo.setHighlight(self.copy_color)
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

    # ヘッダー数の比較
    # 現在リクエストヘッダーが多いと True
    def comparison_number_header(self, current_headers, headers):
        cheaders = {}
        for current_header in current_headers:
            ch = current_header.split(": ", 1)
            if len(ch) == 2 and ch[0] != "Cookie":
                cheaders[ch[0]] = ch[1]
        return len(cheaders) > len(headers)
    
    # パラメータ数の比較
    # 現在リクエストパラメータが多いと True
    def comparison_number_parameter(self, current_parameters, parameters):
        cparameters = {}
        for current_parameter in current_parameters:
            if current_parameter.getType() != IParameter.PARAM_COOKIE:
                cparameters[current_parameter.getName()] = current_parameter.getValue()
        return len(cparameters) > len(parameters)

    # クッキー数の比較
    # 現在リクエストクッキーが多いと True
    def comparison_number_cookie(self, current_cookies, cookies):
        ccookies = {}
        for current_cookie in current_cookies:
            if current_cookie.getType() == IParameter.PARAM_COOKIE:
                ccookies[current_cookie.getName()] = current_cookie.getValue()
        return len(ccookies) > len(cookies)

    # ヘッダー値の比較
    # 現在リクエストヘッダー値が1つでも違うと True
    def comparison_value_header(self, current_headers, headers):
        for current_header in current_headers:
            ch = current_header.split(": ", 1)
            if len(ch) == 2 and ch[0] != "Cookie":
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

    def set_request(self, requestInfo):
        url             = requestInfo.getUrl()
        method          = requestInfo.getMethod()
        headers         = requestInfo.getHeaders()
        parameters      = requestInfo.getParameters()
        method_url      = '{}{}://{}{}'.format(method, url.getProtocol(), url.getHost(), url.getPath())

        self.__REQUEST_DATA[method_url] = {"Headers": {}, "Cookies": {}, "Parameters": {}, "Copyed": True}
        self.set_headers(method_url, headers)
        self.set_parameters(method_url, parameters)
        self.set_cookies(method_url, parameters)

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
        self.__REQUEST_DATA[key]['Copyed'] = True

    def get_request_info(self, key):
        return self.__REQUEST_DATA[key]

    def exists_request(self, key):
        return key in self.__REQUEST_DATA.keys()