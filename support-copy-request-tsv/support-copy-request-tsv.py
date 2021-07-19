# coding: UTF-8

from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from java.io import PrintWriter

class BurpExtender(IBurpExtender, IProxyListener):
    extentionName        = "Support Copy Request TSV"
    color                = "gray" # red, magenta, yellow, green, cyan, blue, pink, purple, gray
    comment              = "#{} has equal or more parameters"
    proxyHistCounter     = 0
    historyRequests      = {} # {Method+URL: {ref: getMessageReference(), parameters: getParameters()}}
    histRequestRefKey    = "ref"
    histRequestParamKey    = "parameters"
    
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True) #self._stdout.println()

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerProxyListener(self)

        self.proxyHistCounter = len(callbacks.getProxyHistory())
        self._stdout.println('Start offset: {}'.format(self.proxyHistCounter))

    def processProxyMessage(self, messageIsRequest, message):
        # リクエストのみ
        if not messageIsRequest:
            return
        
        self.proxyHistCounter += 1
        messageInfo = message.getMessageInfo()
        self.comparisonRequest(self.proxyHistCounter, messageInfo)

    # リクエストの比較を行う
    def comparisonRequest(self, messageRef, messageInfo):
        requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        url         = requestInfo.getUrl()
        method      = requestInfo.getMethod()
        params      = requestInfo.getParameters()
        method_url  = method+str(url)
        # 対象スコープでない場合は無視
        if not self._callbacks.isInScope(url):
            return

        someRequestInfo = self.getSomeRequest(method_url)
        # 未取得のリクエストならhistoryRequestsに保存する
        if someRequestInfo == "":
            self.historyRequests[method_url] = {self.histRequestRefKey: messageRef, self.histRequestParamKey: params}
            return
        
        # どのリクエストがパラメータが多いか比較する
        if len(someRequestInfo[self.histRequestParamKey]) < len(params):
            self.setHighlightAndComment(self._callbacks.getProxyHistory()[someRequestInfo[self.histRequestRefKey]], messageRef)
            self.historyRequests[method_url] = {self.histRequestRefKey: messageRef, self.histRequestParamKey: params}
        else:
            self.setHighlightAndComment(messageInfo, someRequestInfo[self.histRequestRefKey])

    # historyRequestsから値を取得する
    def getSomeRequest(self, key):
        try:
            return self.historyRequests[key]
        except KeyError:
            return ""

    def setHighlightAndComment(self, messageInfo, ref):
        messageInfo.setHighlight(self.color)
        messageInfo.setComment(self.comment.format(ref))
            
