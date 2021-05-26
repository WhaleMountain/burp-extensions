# coding: UTF-8

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener
from burp import IParameter
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
    extentionName       = "Filter Graphql Request"
    color               = "cyan" # red, magenta, yellow, green, cyan, blue, pink, purple, black
    graphqlRequests     = [] # Key: url, value: { method: query }
    
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerHttpListener(self)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # リクエストのみ
        if not messageIsRequest:
            return

        requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        url     = requestInfo.getUrl()
        method  = requestInfo.getMethod()
        params  = requestInfo.getParameters()
        
        # 対象スコープでない場合は無視
        if not self._callbacks.isInScope(url):
            return

        # Graphql ハンター
        if "/graphql" not in url.toString():
            return

        query = ""
        for param in params:
            if param.getType() == IParameter.PARAM_JSON and param.getName() == "query":
                query = param.getValue()

        if query != "" and query not in self.graphqlRequests:
            self.graphqlRequests.append(query)
            messageInfo.setHighlight(self.color)
