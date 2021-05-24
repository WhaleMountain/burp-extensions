# coding: UTF-8

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IParameter
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
    extentionName       = "Filter Unique Requests"
    color               = "cyan" # red, magenta, yellow, green, cyan, blue, pink, purple, black
    uniqueRequests      = {} # Key: request url, value: request params
    
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        self._stdout = PrintWriter(callbacks.getStdout(), True)
        #self._stdout.println(param.getValue())

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerHttpListener(self)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # リクエストのみ
        if not messageIsRequest:
            return

        requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        url = requestInfo.getUrl()
        params = requestInfo.getParameters()
        
        # 対象スコープでない場合は無視
        if not self._callbacks.isInScope(url):
            return

        query = ""
        for param in params:
            if param.getType() == IParameter.PARAM_JSON and param.getName() == "query":
                query = param.getValue()     

        if url in self.uniqueRequests.keys():
            if query not in self.uniqueRequests[url]:
                self.uniqueRequests[url].append(query)
                messageInfo.setHighlight(self.color)
        else:
            self.uniqueRequests[url] = [query]
            messageInfo.setHighlight(self.color)