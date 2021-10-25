# coding: UTF-8

from burp import ITab
from burp import IBurpExtender
from burp import IProxyListener
from burp import IParameter
from burp import IBurpExtenderCallbacks
from burp import IContextMenuFactory
from burp import IContextMenuInvocation
from java.io import PrintWriter
from javax.swing import JPanel, JScrollPane, JButton, JLabel, JMenuItem, JComboBox, JTable, JTextField, JFileChooser, JOptionPane
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.table import TableModel
from javax.swing.table import DefaultTableModel
from java.awt import Dimension, Color
from java.awt.event import ActionListener
import json
import re

class BurpExtender(IBurpExtender, IProxyListener, ITab, ActionListener, IContextMenuFactory, IContextMenuInvocation):
    def __init__(self):
        self.extentionName        = "Support Copy Request TSV"
        self.menuName1            = "Sup cprTSV (Check)"
        self.menuName2            = "Sup cprTSV (Clear)"
        self.menuName3            = "Sup cprTSV (Ignore)"
        self.color                = "gray" # red, magenta, yellow, green, cyan, blue, pink, purple, gray
        self.comment              = "No.{}, <= #{} "
        self.compInfos            = {} # {Method+URL: {reference: getMessageReference(), messageInfo: getMessageInfo()}}
        self.compReferenceKey     = "reference"
        self.compMessageKey       = "messageInfo"

        self.ignoreUrlList        = set()

        # URLの正規表現
        url_pattern = "https?://"
        self.url_regex = re.compile(url_pattern)

        # コメント削除用の正規表現
        comment_pattern = self.comment.format("\d+", "\d*")
        self.comment_regex = re.compile(comment_pattern)

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
        self._ignore_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD", "TRACE", "CONNECT"]
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
        self._ignore_file_chooser.setAcceptAllFileFilterUsed(False)
        extFilter = FileNameExtensionFilter("JSON files (*.json)", ["json"])
        self._ignore_file_chooser.addChoosableFileFilter(extFilter)

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
            self._callbacks.registerProxyListener(self)
            
        elif event.getSource() is self._stop_listener_btn:
            self._start_listener_btn.setEnabled(True)
            self._stop_listener_btn.setEnabled(False)
            self.compInfos.clear()
            self._callbacks.removeProxyListener(self)

        elif event.getSource() is self._check_btn:
            for idx, messageInfo in enumerate(self._callbacks.getProxyHistory()):
                self.comparisonRequest(idx + 1, messageInfo)

        elif event.getSource() is self._clear_btn:
            self.compInfos.clear()
            for messageInfo in self._callbacks.getProxyHistory():
                try:
                    if self.comment_regex.match(messageInfo.getComment()) != None:
                        self.clearHighlightAndComment(messageInfo, messageInfo.getHighlight() == self.color)
                except TypeError:
                    continue

        elif event.getSource() is self._highlight_set_btn:
            select_color = self._highlight_colors[self._highlight_dropdown.selectedIndex]
            if select_color == "white":
                self.color = None
            else:
                self.color = select_color

        elif event.getSource() is self._ignore_add_btn:
            method = self._ignore_methods[self._ignore_dropdown.selectedIndex]
            url    = self._ignore_text.getText()
            if self.addIgnoreUrlList(method, url):
                self._ignore_text.setText("")

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
            self.ignoreUrlList.clear()

        elif event.getSource() is self._ignore_list_export_btn:
            self._ignore_file_chooser.showSaveDialog(event.getSource())
            export_file_path = self._ignore_file_chooser.getSelectedFile().getAbsolutePath()
            file_ext = self._ignore_file_chooser.getSelectedFile().getName().split(".")[-1]
            if file_ext.lower() != "json":
                export_file_path = '{}.json'.format(export_file_path)

            # 上書き保存の確認
            if self._ignore_file_chooser.getSelectedFile().exists():
                message = "{} already exists.\nDo you want to replace it?".format(export_file_path)
                ans = JOptionPane.showConfirmDialog(None, message, "Save As", JOptionPane.YES_NO_OPTION)
                if (ans == JOptionPane.NO_OPTION):
                    return
            
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
                self.addIgnoreUrlList(method, url)

    def	registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers   = callbacks.getHelpers()
        self._stdout    = PrintWriter(callbacks.getStdout(), True) #self._stdout.println()

        # ---- Warning 定数の気持ち〜 -----
        self.HISTORY_REFERENCE_OFFSET = len(callbacks.getProxyHistory())
        # ------------------------------

        callbacks.setExtensionName(self.extentionName)
        callbacks.registerContextMenuFactory(self)
        callbacks.addSuiteTab(self)

    def processProxyMessage(self, messageIsRequest, message):
        # リクエストのみ
        if not messageIsRequest:
            return
        
        messageInfo = message.getMessageInfo()
        self.comparisonRequest(self.HISTORY_REFERENCE_OFFSET + message.getMessageReference() + 1, messageInfo)

    def createMenuItems(self, invocation):
        menu = []
        menu.append(JMenuItem(self.menuName1, actionPerformed=lambda x, inv=invocation: self.menu_action_check(inv)))
        menu.append(JMenuItem(self.menuName2, actionPerformed=lambda x, inv=invocation: self.menu_action_clear(inv)))
        menu.append(JMenuItem(self.menuName3, actionPerformed=lambda x, inv=invocation: self.menu_action_ignore(inv)))
        return menu

    # 選択されたリクエストの比較を行う
    def menu_action_check(self, inv):
        #self.historyRequests.clear()
        self.compInfos.clear()
        for idx, messageInfo in enumerate(inv.getSelectedMessages()):
            self.comparisonRequest(idx + 1, messageInfo)
    
    # 選択されたリクエストのhighlightとCommentを削除する
    def menu_action_clear(self, inv):
        for messageInfo in inv.getSelectedMessages():
            try:
                if self.comment_regex.match(messageInfo.getComment()) != None:
                    self.clearHighlightAndComment(messageInfo, messageInfo.getHighlight() == self.color)
            except TypeError:
                continue   

    # 選択されたリクエストをIgnoreに追加する
    def menu_action_ignore(self, inv):
        for messageInfo in inv.getSelectedMessages():
            requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
            jurl        = requestInfo.getUrl()
            url         = '{}://{}{}'.format(jurl.getProtocol(), jurl.getHost(), jurl.getPath())
            self.addIgnoreUrlList(requestInfo.getMethod(), url)

    # リクエストの比較を行う
    def comparisonRequest(self, messageRef, messageInfo):
        requestInfo = self._helpers.analyzeRequest(messageInfo.getHttpService(), messageInfo.getRequest())
        url         = requestInfo.getUrl()
        method      = requestInfo.getMethod()
        headers     = requestInfo.getHeaders()
        params      = requestInfo.getParameters()
        method_url  = '{}{}://{}{}'.format(method, url.getProtocol(), url.getHost(), url.getPath())
        # 対象スコープでない場合は無視
        if not self._callbacks.isInScope(url):
            return 

        # 無視リストに記載があれば無視
        if self.isIgnoreList(method_url):
            return

        compInfo = self.getCompInfo(method_url) # 比較するリクエストの取得
        # 未取得のリクエストならhistoryRequestsに保存する
        if compInfo == None:
            messageInfo.setComment(self.comment.format(messageRef, ""))
            self.compInfos[method_url] = {self.compReferenceKey: messageRef, self.compMessageKey: messageInfo}
            return

        compMessageInfo = compInfo[self.compMessageKey]
        compRequestInfo = self._helpers.analyzeRequest(compMessageInfo.getHttpService(), compMessageInfo.getRequest())
        compParams      = compRequestInfo.getParameters()
        compHeaders     = compRequestInfo.getHeaders()
        
        # パラメータ数の比較
        if len(compParams) < len(params):
            self.setHighlightAndComment(compMessageInfo, compInfo[self.compReferenceKey], messageRef)
            messageInfo.setComment(self.comment.format(messageRef, ""))
            self.compInfos[method_url] = {self.compReferenceKey: messageRef, self.compMessageKey: messageInfo}

        # パラメータ数は同数だが、ヘッダー数が多い場合
        elif len(compParams) == len(params) and len(compHeaders) < len(headers):
            self.setHighlightAndComment(compMessageInfo, compInfo[self.compReferenceKey], messageRef)
            messageInfo.setComment(self.comment.format(messageRef, ""))
            self.compInfos[method_url] = {self.compReferenceKey: messageRef, self.compMessageKey: messageInfo}

        # パラメータ数、ヘッダー数ともに取得済みより劣る
        else:
            self.setHighlightAndComment(messageInfo, messageRef, compInfo[self.compReferenceKey])

    # 無視リストに存在するか 存在する -> True, 存在しない -> False
    def isIgnoreList(self, method_url):
        return method_url in self.ignoreUrlList

    # Ignoreリストに追加する
    def addIgnoreUrlList(self, method, url):
        # URL形式じゃない、またはすでに追加済みなら追加しない。
        method_url = '{}{}'.format(method, url)
        if self.url_regex.match(url) == None or self.isIgnoreList(method_url):
            return False
        
        # 未登録なら追加する
        self._ignore_table_model.addRow([method, url])
        self.ignoreUrlList.add(method_url)
        return True

    # compInfosから値を取得する
    def getCompInfo(self, key):
        try:
            return self.compInfos[key]
        except KeyError:
            return None

    # highlightとCommentをセットする
    def setHighlightAndComment(self, messageInfo, ref, compRef):
        messageInfo.setHighlight(self.color)
        messageInfo.setComment(self.comment.format(ref, compRef))

    # highlightとCommentを削除する
    def clearHighlightAndComment(self, messageInfo, isClearColor):
        if isClearColor:
            messageInfo.setHighlight(None)
        clear_comment = self.comment_regex.sub("", messageInfo.getComment())
        messageInfo.setComment(clear_comment if clear_comment != None else "")

class IgnoreTable(DefaultTableModel):
    def __init__(self, data, headings):
        DefaultTableModel.__init__(self, data, headings)

    def isCellEditable(self, row, column):
        return False