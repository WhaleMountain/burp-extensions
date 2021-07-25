# coding: UTF-8

from burp import ITab
from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from java.io import PrintWriter
from javax.swing import JPanel, JButton, JLabel, JMenuItem
from java.awt import GridLayout
from java.awt.event import ActionListener

class BurpExtender(IBurpExtender, IProxyListener, ITab, ActionListener, IContextMenuFactory, IContextMenuInvocation):
    def __init__(self):
        self.extentionName        = "Support Copy Request TSV"
        self.menuName1            = "Sup cprTSV (Check)"
        self.menuName2            = "Sup cprTSV (Clear)"
        self.color                = "gray" # red, magenta, yellow, green, cyan, blue, pink, purple, gray
        self.comment              = "#{} has equal or greater parameters"
        self.proxyHistCounter     = 0
        self.historyRequests      = {} # {Method+URL: {ref: getMessageReference(), parameters: getParameters()}}
        self.histRequestRefKey    = "ref"
        self.histRequestParamKey  = "parameters"
        # create panels
        self._main_panel  = JPanel()
        self._main_panel.setLayout(None)
        listener_panel    = JPanel()
        listener_panel.setBounds(5, 50, 300, 50)
        check_panel       = JPanel()
        check_panel.setBounds(9, 100, 300, 50)
        clear_panel       = JPanel()
        clear_panel.setBounds(16, 150, 300, 50)

        # create buttons
        listener_label = JLabel("ProxyListener")
        listener_panel.add(listener_label)

        self._start_listener_btn = JButton("Start")
        self._start_listener_btn.addActionListener(self)
        listener_panel.add(self._start_listener_btn)

        self._stop_listener_btn = JButton("Stop and Reset")
        self._stop_listener_btn.addActionListener(self)
        self._stop_listener_btn.setEnabled(False)
        listener_panel.add(self._stop_listener_btn)

        check_label = JLabel("Check all Proxy HTTP history")
        self._check_btn = JButton("Check")
        self._check_btn.addActionListener(self)
        check_panel.add(check_label)
        check_panel.add(self._check_btn)

        clear_label = JLabel("Clear all highlight and comment")
        self._clear_btn = JButton("Clear")
        self._clear_btn.addActionListener(self)
        clear_panel.add(clear_label)
        clear_panel.add(self._clear_btn)

        # add panels to the main_panel
        self._main_panel.add(listener_panel)
        self._main_panel.add(check_panel)
        self._main_panel.add(clear_panel)

    def getTabCaption(self):
        return "Support Copy Request TSV"

    def getUiComponent(self):
        return self._main_panel

    def actionPerformed(self, event):
        if event.getSource() is self._start_listener_btn:
            self._start_listener_btn.setEnabled(False)
            self._stop_listener_btn.setEnabled(True)

            self.proxyHistCounter = len(self._callbacks.getProxyHistory())
            self._callbacks.registerProxyListener(self)
            
        elif event.getSource() is self._stop_listener_btn:
            self._start_listener_btn.setEnabled(True)
            self._stop_listener_btn.setEnabled(False)

            self.historyRequests.clear()
            self.proxyHistCounter = 0
            self._callbacks.removeProxyListener(self)

        elif event.getSource() is self._check_btn:
            for idx, messageInfo in enumerate(self._callbacks.getProxyHistory()):
                self.comparisonRequest(idx + 1, messageInfo)

        elif event.getSource() is self._clear_btn:
            self.historyRequests.clear()
            self.proxyHistCounter = 0
            for messageInfo in self._callbacks.getProxyHistory():
                if messageInfo.getHighlight() == self.color and messageInfo.getComment() != "":
                    self.clearHighlightAndComment(messageInfo)
    
    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True) #self._stdout.println()

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

    def processProxyMessage(self, messageIsRequest, message):
        # リクエストのみ
        if not messageIsRequest:
            return
        
        self.proxyHistCounter += 1
        messageInfo = message.getMessageInfo()
        self.comparisonRequest(self.proxyHistCounter, messageInfo)

    def createMenuItems(self, invocation):
        menu = []
        menu.append(JMenuItem(self.menuName1, actionPerformed=lambda x, inv=invocation: self.menu_action_check(inv)))
        menu.append(JMenuItem(self.menuName2, actionPerformed=lambda x, inv=invocation: self.menu_action_clear(inv)))
        return menu

    # 選択されたリクエストの比較を行う
    def menu_action_check(self, inv):
        self.historyRequests.clear()
        self.proxyHistCounter = 0
        for idx, messageInfo in enumerate(inv.getSelectedMessages()):
            self.comparisonRequest(idx + 1, messageInfo)
    
    # 選択されたリクエストのhighlightとCommentを削除する
    def menu_action_clear(self, inv):
        for messageInfo in inv.getSelectedMessages():
            if messageInfo.getHighlight() == self.color and messageInfo.getComment() != "":
                self.clearHighlightAndComment(messageInfo)    

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

    # highlightとCommentをセットする
    def setHighlightAndComment(self, messageInfo, ref):
        messageInfo.setHighlight(self.color)
        messageInfo.setComment(self.comment.format(ref))

    # highlightとCommentを削除する
    def clearHighlightAndComment(self, messageInfo):
        messageInfo.setHighlight(None)
        messageInfo.setComment("")
