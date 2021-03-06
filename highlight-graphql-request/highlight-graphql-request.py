# coding: UTF-8

from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IProxyListener):
    def __init__(self):
        self.extentionName       = "Highlight GraphQL Request"
        self.color               = "cyan" # red, magenta, yellow, green, cyan, blue, pink, purple, gray
        self.endpoint            = "graphql"
        self.graphqlQuery        = set()
    
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True)

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerProxyListener(self)

        # Burp起動時にHttp Historyを読み込ませたい場合 下3行のコメントを外す
        #for messageInfo in callbacks.getProxyHistory():
        #    requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        #    self.uniqueRequest(requestInfo)
    
    def processProxyMessage(self, messageIsRequest, message):
        # リクエストのみ
        if not messageIsRequest:
            return

        messageInfo = message.getMessageInfo()
        requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        if self.uniqueRequest(requestInfo):
            messageInfo.setHighlight(self.color)

    # ユニークなGraphQLのQueryならTrueを返す
    def uniqueRequest(self, requestInfo):
        url     = requestInfo.getUrl()
        method  = requestInfo.getMethod()
        params  = requestInfo.getParameters()
        
        # 対象スコープでない場合は無視
        if not self._callbacks.isInScope(url):
            return False

        # Only GraphQL
        if self.endpoint not in url.toString():
            return False

        query = ""
        for param in params:
            if param.getType() == IParameter.PARAM_JSON and param.getName() == "query":
                query = param.getValue()

        if query != "" and query not in self.graphqlQuery:
            self.graphqlQuery.add(query)
            return True
        
        return False

