# coding: UTF-8

from burp import ITab
from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from java.io import PrintWriter
from javax.swing import JPanel, JScrollPane, JButton, JLabel, JMenuItem, JComboBox, JTable, JTextField, JFileChooser
from javax.swing.table import TableModel
from javax.swing.table import DefaultTableModel
from java.awt import GridLayout, Dimension, Color
from java.awt.event import ActionListener
import json

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
        self.ignoreUrlList        = []

        # create panels
        self._main_panel    = JPanel()
        self._main_panel.setLayout(None)
        listener_panel      = JPanel()
        listener_panel.setBounds(28, 50, 300, 50)
        check_panel         = JPanel()
        check_panel.setBounds(9, 100, 300, 50)
        clear_panel         = JPanel()
        clear_panel.setBounds(16, 150, 300, 50)
        highlight_panel     = JPanel()
        highlight_panel.setBounds(16, 200, 300, 50)
        ignore_add_panel        = JPanel()
        ignore_add_panel.setBounds(-60, 250, 700, 50)
        ignore_table_btn_panel = JPanel()
        ignore_table_btn_panel.setBounds(173, 300, 400, 50)
        ignore_table_panel  = JScrollPane()
        ignore_table_panel.setBounds(40, 350, 500, 300)

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

        highlight_label = JLabel("Highlight Color")
        self._highlight_colors = ["gray", "white", "red", "orange", "yellow", "green", "cyan", "blue", "pink", "magenta"]
        self._highlight_dropdown = JComboBox(self._highlight_colors)
        self._highlight_set_btn = JButton("Set")
        self._highlight_set_btn.addActionListener(self)
        highlight_panel.add(highlight_label)
        highlight_panel.add(self._highlight_dropdown)
        highlight_panel.add(self._highlight_set_btn)

        ignore_label = JLabel("Ignore to URLs")
        self._ignore_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "LINK", "UNLINK"]
        self._ignore_dropdown = JComboBox(self._ignore_methods)
        self._ignore_text = JTextField(20)
        self._ignore_add_btn = JButton("Add")
        self._ignore_add_btn.addActionListener(self)
        ignore_add_panel.add(ignore_label)
        ignore_add_panel.add(self._ignore_dropdown)
        ignore_add_panel.add(self._ignore_text)
        ignore_add_panel.add(self._ignore_add_btn)

        self._ignore_table_model = IgnoreTable([], ["Method", "URL"])
        self._ignore_table = JTable(self._ignore_table_model)
        ignore_table_panel.add(self._ignore_table)
        ignore_table_panel.setPreferredSize(Dimension(300,100))
        ignore_table_panel.getViewport().setView((self._ignore_table))

        self._ignore_list_export_btn = JButton("Export")
        self._ignore_list_import_btn = JButton("Import")
        self._ignore_remove_btn = JButton("Remove")
        self._ignore_remove_all_btn = JButton("Remove All")
        self._ignore_list_export_btn.addActionListener(self)
        self._ignore_list_import_btn.addActionListener(self)
        self._ignore_remove_btn.addActionListener(self)
        self._ignore_remove_all_btn.addActionListener(self)
        ignore_table_btn_panel.add(self._ignore_list_export_btn)
        ignore_table_btn_panel.add(self._ignore_list_import_btn)
        ignore_table_btn_panel.add(self._ignore_remove_btn)
        ignore_table_btn_panel.add(self._ignore_remove_all_btn)

        self._ignore_file_chooser = JFileChooser()
        self._ignore_file_chooser.setFileSelectionMode(JFileChooser.FILES_ONLY)

        # add panels to the main_panel
        self._main_panel.add(listener_panel)
        self._main_panel.add(check_panel)
        self._main_panel.add(clear_panel)
        self._main_panel.add(highlight_panel)
        self._main_panel.add(ignore_add_panel)
        self._main_panel.add(ignore_table_btn_panel)
        self._main_panel.add(ignore_table_panel)

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

        elif event.getSource() is self._highlight_set_btn:
            select_color = self._highlight_colors[self._highlight_dropdown.selectedIndex]
            if select_color == "white":
                self.color = None
            else:
                self.color = select_color

        elif event.getSource() is self._ignore_add_btn:
            select_method = self._ignore_methods[self._ignore_dropdown.selectedIndex]
            url           = self._ignore_text.getText()
            method_url    = '{}{}'.format(select_method, url)

            # URLが空またはすでに追加済みなら追加しない。
            if url == "" or method_url in self.ignoreUrlList:
                return

            self._ignore_text.setText("")
            self._ignore_table_model.addRow([select_method, url])
            self.ignoreUrlList.append(method_url)

        elif event.getSource() is self._ignore_remove_btn:
            rowNo   = self._ignore_table.getSelectedRow()
            method  = self._ignore_table_model.getValueAt(rowNo, 0)
            url     = self._ignore_table_model.getValueAt(rowNo, 1)
            if rowNo >= 0: # 何も選択されていない時 -1 になるため
                self._ignore_table_model.removeRow(rowNo)
            self.ignoreUrlList.remove('{}{}'.format(method, url))
        
        elif event.getSource() is self._ignore_remove_all_btn:
            for rowNo in xrange(self._ignore_table.getRowCount()):
                self._ignore_table_model.removeRow(0)
            del self.ignoreUrlList[:] # clear がつかなかったので del を使う

        elif event.getSource() is self._ignore_list_export_btn:
            self._ignore_file_chooser.showSaveDialog(event.getSource())
            export_file_path = self._ignore_file_chooser.getSelectedFile().getAbsolutePath()
            export_data = []
            for rowNo in xrange(self._ignore_table_model.getRowCount()):
                data = {
                    "method": self._ignore_table_model.getValueAt(rowNo, 0),
                    "url": self._ignore_table_model.getValueAt(rowNo, 1)
                }
                export_data.append(data)
            with open(export_file_path, 'w') as f:
                f.write(json.dumps(export_data))
        
        elif event.getSource() is self._ignore_list_import_btn:
            self._ignore_file_chooser.showOpenDialog(event.getSource())
            import_file_path = self._ignore_file_chooser.getSelectedFile().getAbsolutePath()
            with open(import_file_path, 'r') as f:
                import_data = json.loads(f.read())
            for data in import_data:
                method      = data["method"]
                url         = data["url"]
                method_url  = '{}{}'.format(method, url)
                self._ignore_table_model.addRow([method, url])
                self.ignoreUrlList.append(method_url)

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

        # 無視リストに記載があれば無視
        if self.isIgnoreList(method_url):
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

    # 無視リストに存在するか 存在する -> True, 存在しない -> False
    def isIgnoreList(self, method_url):
        return method_url in self.ignoreUrlList

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

class IgnoreTable(DefaultTableModel):
    def __init__(self, data, headings):
        DefaultTableModel.__init__(self, data, headings)

    def isCellEditable(self, row, column):
        return False