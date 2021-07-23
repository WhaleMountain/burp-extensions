# coding: UTF-8

from burp import ITab
from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from java.io import PrintWriter
from javax.swing import JPanel, JButton, JProgressBar
from java.awt import BorderLayout
from java.awt.event import ActionListener

class BurpExtender(IBurpExtender, IProxyListener, ITab, ActionListener):
    def __init__(self):
        self.extentionName        = "Support Copy Request TSV"
        self.color                = "gray" # red, magenta, yellow, green, cyan, blue, pink, purple, gray
        self.comment              = "#{} has equal or greater parameters"
        self.proxyHistCounter     = 0
        self.historyRequests      = {} # {Method+URL: {ref: getMessageReference(), parameters: getParameters()}}
        self.histRequestRefKey    = "ref"
        self.histRequestParamKey  = "parameters"
        #self.extensionLoaded()
        # create panels
        self._main_panel      = JPanel(BorderLayout())
        self._button_panel    = JPanel()

        # create buttons
        self._btn1 = JButton("0")
        self._btn1.addActionListener(self)
        self._button_panel.add(self._btn1)

        # add panels to the main_panel
        self._main_panel.add(self._button_panel, BorderLayout.PAGE_START)

    def getTabCaption(self):
        return "Support Copy Request TSV"

    def getUiComponent(self):
        return self._main_panel

    def actionPerformed(self, event):
        if event.getSource() is self._btn1:
            self._btn1.text = str(int(self._btn1.text) + 1)
    
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True) #self._stdout.println()

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerProxyListener(self)
        callbacks.addSuiteTab(self)

    def extensionLoaded(self):
        proxyHistory = self._callbacks.getProxyHistory()
        self.proxyHistCounter = len(proxyHistory)
        self._stdout.println('Start offset: {}'.format(self.proxyHistCounter))

        for idx, messageInfo in enumerate(proxyHistory):
            requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
            url         = requestInfo.getUrl()
            method      = requestInfo.getMethod()
            params      = requestInfo.getParameters()
            method_url  = '{}{}://{}{}'.format(method, url.getProtocol(), url.getHost(), url.getPath())
            # 対象スコープでない場合は無視
            if not self._callbacks.isInScope(url):
                continue

            someRequestInfo = self.getSomeRequest(method_url)
            # 未取得のリクエストならhistoryRequestsに保存する
            if someRequestInfo == None:
                self.historyRequests[method_url] = {self.histRequestRefKey: idx + 1, self.histRequestParamKey: params}
                continue
            
            # どのリクエストがパラメータが多いか比較する
            if len(someRequestInfo[self.histRequestParamKey]) < len(params):
                self.historyRequests[method_url] = {self.histRequestRefKey: idx + 1, self.histRequestParamKey: params}

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
        method_url  = '{}{}://{}{}'.format(method, url.getProtocol(), url.getHost(), url.getPath())
        # 対象スコープでない場合は無視
        if not self._callbacks.isInScope(url):
            return

        someRequestInfo = self.getSomeRequest(method_url)
        # 未取得のリクエストならhistoryRequestsに保存する
        if someRequestInfo == None:
            self.historyRequests[method_url] = {self.histRequestRefKey: messageRef, self.histRequestParamKey: params}
            return
        
        # どのリクエストがパラメータが多いか比較する
        if len(someRequestInfo[self.histRequestParamKey]) < len(params):
            self.setHighlightAndComment(self._callbacks.getProxyHistory()[someRequestInfo[self.histRequestRefKey] - 1], messageRef)
            self.historyRequests[method_url] = {self.histRequestRefKey: messageRef, self.histRequestParamKey: params}
        else:
            self.setHighlightAndComment(messageInfo, someRequestInfo[self.histRequestRefKey])

    # historyRequestsから値を取得する
    def getSomeRequest(self, key):
        try:
            return self.historyRequests[key]
        except KeyError:
            return None

    def setHighlightAndComment(self, messageInfo, ref):
        messageInfo.setHighlight(self.color)
        messageInfo.setComment(self.comment.format(ref))
            
