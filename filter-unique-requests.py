# coding: UTF-8

from burp import IBurpExtender
from burp import IHttpListener
from burp import IProxyListener

class BurpExtender(IBurpExtender, IHttpListener, IProxyListener):
    extentionName       = "Filter Unique Requests"
    color               = "cyan" # red, magenta, yellow, green, cyan, blue, pink, purple, black
    uniqueRequestUrls   = []
    
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerHttpListener(self)
    
    def processHttpMessage(self, toolFlag, messageIsRequest, messageInfo):
        # リクエストのみ
        if not messageIsRequest:
            return

        requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        url = requestInfo.getUrl()
        
        # 対象スコープでない場合は無視
        if not self._callbacks.isInScope(url):
            return
        
        # uniqueRequestUrls にないリクエストを送信したら、そのヒストリーの行をハイライトする
        if url not in self.uniqueRequestUrls:
            self.uniqueRequestUrls.append(url)
            messageInfo.setHighlight(self.color)