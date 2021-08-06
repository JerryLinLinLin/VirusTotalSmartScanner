# -*- coding: utf-8 -*-

###########################################################################
## Python code generated with wxFormBuilder (version Aug  8 2018)
## http://www.wxformbuilder.org/
##
## PLEASE DO *NOT* EDIT THIS FILE!
###########################################################################

import wx
import wx.xrc
import wx.grid
import wx.adv


###########################################################################
## Class VT_AVScanner
###########################################################################

class VT_AVScanner(wx.Frame):

    def __init__(self, parent):
        wx.Frame.__init__(self, parent, id=wx.ID_ANY, title=u"VirusTotal Smart Scanner", pos=wx.DefaultPosition,
                          size=wx.Size(800, 370), style=wx.CAPTION | wx.CLOSE_BOX | wx.MINIMIZE_BOX | wx.TAB_TRAVERSAL)

        self.SetSizeHints(wx.DefaultSize, wx.DefaultSize)
        self.SetFont(
            wx.Font(wx.NORMAL_FONT.GetPointSize(), wx.FONTFAMILY_DEFAULT, wx.FONTSTYLE_NORMAL, wx.FONTWEIGHT_NORMAL,
                    False, wx.EmptyString))
        self.SetBackgroundColour(wx.Colour(255, 255, 255))

        bSizer7 = wx.BoxSizer(wx.VERTICAL)

        bSizer7.SetMinSize(wx.Size(800, 330))
        self.path_dir = wx.DirPickerCtrl(self, wx.ID_ANY, wx.EmptyString, u"Select a folder", wx.DefaultPosition,
                                         wx.Size(770, -1), wx.DIRP_DEFAULT_STYLE)
        self.path_dir.SetForegroundColour(wx.SystemSettings.GetColour(wx.SYS_COLOUR_INFOTEXT))

        bSizer7.Add(self.path_dir, 0, wx.ALL, 5)

        bSizer71 = wx.BoxSizer(wx.VERTICAL)

        bSizer71.SetMinSize(wx.Size(800, -1))
        wSizer11 = wx.WrapSizer(wx.HORIZONTAL, wx.WRAPSIZER_DEFAULT_FLAGS)

        wSizer11.SetMinSize(wx.Size(800, 30))
        self.scan_but = wx.Button(self, wx.ID_ANY, u"Scan", wx.DefaultPosition, wx.DefaultSize, 0)
        wSizer11.Add(self.scan_but, 0, wx.ALL, 5)

        self.stop_but = wx.Button(self, wx.ID_ANY, u"Stop", wx.DefaultPosition, wx.DefaultSize, 0)
        self.stop_but.Enable(False)

        wSizer11.Add(self.stop_but, 0, wx.ALL, 5)

        self.scan_gauge = wx.Gauge(self, wx.ID_ANY, 100, wx.DefaultPosition, wx.Size(585, -1), wx.GA_HORIZONTAL)
        self.scan_gauge.SetValue(0)
        wSizer11.Add(self.scan_gauge, 1, wx.ALL | wx.EXPAND, 5)

        bSizer71.Add(wSizer11, 1, wx.EXPAND, 5)

        bSizer7.Add(bSizer71, 1, wx.EXPAND, 5)

        self.data_grid = wx.grid.Grid(self, wx.ID_ANY, wx.DefaultPosition, wx.Size(800, 200), 0)

        # Grid
        self.data_grid.CreateGrid(0, 4)
        self.data_grid.EnableEditing(False)
        self.data_grid.EnableGridLines(False)
        self.data_grid.EnableDragGridSize(True)
        self.data_grid.SetMargins(0, 0)

        # Columns
        self.data_grid.SetColSize(0, 150)
        self.data_grid.SetColSize(1, 150)
        self.data_grid.SetColSize(2, 200)
        self.data_grid.SetColSize(3, 270)
        self.data_grid.EnableDragColMove(False)
        self.data_grid.EnableDragColSize(False)
        self.data_grid.SetColLabelSize(30)
        self.data_grid.SetColLabelValue(0, u"Threat")
        self.data_grid.SetColLabelValue(1, u"File")
        self.data_grid.SetColLabelValue(2, u"Path")
        self.data_grid.SetColLabelValue(3, u"sha256")
        self.data_grid.SetColLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        # Rows
        self.data_grid.EnableDragRowSize(False)
        self.data_grid.SetRowLabelSize(0)
        self.data_grid.SetRowLabelAlignment(wx.ALIGN_CENTRE, wx.ALIGN_CENTRE)

        # Label Appearance
        self.data_grid.SetLabelBackgroundColour(wx.Colour(255, 255, 255))

        # Cell Defaults
        self.data_grid.SetDefaultCellAlignment(wx.ALIGN_LEFT, wx.ALIGN_TOP)
        self.m_menu1 = wx.Menu()
        self.m_menuItem1 = wx.MenuItem(self.m_menu1, wx.ID_ANY, u"MyMenuItem", wx.EmptyString, wx.ITEM_NORMAL)
        self.m_menu1.Append(self.m_menuItem1)

        self.data_grid.Bind(wx.EVT_RIGHT_DOWN, self.data_gridOnContextMenu)

        bSizer7.Add(self.data_grid, 0, wx.ALL, 5)

        wSizer4 = wx.WrapSizer(wx.HORIZONTAL, wx.WRAPSIZER_DEFAULT_FLAGS)

        wSizer4.SetMinSize(wx.Size(-1, 30))
        self.remove_but = wx.Button(self, wx.ID_ANY, u"Remove File(s)", wx.DefaultPosition, wx.DefaultSize, 0)
        wSizer4.Add(self.remove_but, 0, wx.ALL, 5)

        self.open_log_folder_but = wx.Button(self, wx.ID_ANY, u"Open Log Folder", wx.DefaultPosition, wx.DefaultSize, 0)
        wSizer4.Add(self.open_log_folder_but, 0, wx.ALL, 5)

        self.open_set_but = wx.Button(self, wx.ID_ANY, u"Settings", wx.DefaultPosition, wx.DefaultSize, 0)
        wSizer4.Add(self.open_set_but, 0, wx.ALL, 5)

        self.about_but = wx.Button(self, wx.ID_ANY, u"About", wx.DefaultPosition, wx.DefaultSize, 0)
        wSizer4.Add(self.about_but, 0, wx.ALL, 5)

        bSizer7.Add(wSizer4, 1, wx.EXPAND, 5)

        self.SetSizer(bSizer7)
        self.Layout()
        self.status_bar = self.CreateStatusBar(1, wx.STB_SIZEGRIP, wx.ID_ANY)

        self.Centre(wx.BOTH)

        # Connect Events
        self.Bind(wx.EVT_CLOSE, self.close_main)
        self.scan_but.Bind(wx.EVT_BUTTON, self.scan_but_click)
        self.stop_but.Bind(wx.EVT_BUTTON, self.stop_but_click)
        self.remove_but.Bind(wx.EVT_BUTTON, self.remove_but_click)
        self.open_log_folder_but.Bind(wx.EVT_BUTTON, self.open_log_folder_but_click)
        self.open_set_but.Bind(wx.EVT_BUTTON, self.open_set_but_click)
        self.about_but.Bind(wx.EVT_BUTTON, self.about_click)

    def __del__(self):
        pass

    # Virtual event handlers, overide them in your derived class
    def close_main(self, event):
        event.Skip()

    def scan_but_click(self, event):
        event.Skip()

    def stop_but_click(self, event):
        event.Skip()

    def remove_but_click(self, event):
        event.Skip()

    def open_log_folder_but_click(self, event):
        event.Skip()

    def open_set_but_click(self, event):
        event.Skip()

    def about_click(self, event):
        event.Skip()

    def data_gridOnContextMenu(self, event):
        self.data_grid.PopupMenu(self.m_menu1, event.GetPosition())


###########################################################################
## Class Settings_window
###########################################################################

class Settings_window(wx.Frame):

    def __init__(self, parent):
        wx.Frame.__init__(self, parent, id=wx.ID_ANY, title=u"Settings", pos=wx.DefaultPosition, size=wx.Size(500, 300),
                          style=wx.DEFAULT_FRAME_STYLE | wx.TAB_TRAVERSAL)

        self.SetSizeHints(wx.DefaultSize, wx.DefaultSize)
        self.SetBackgroundColour(wx.Colour(255, 255, 255))

        bSizer5 = wx.BoxSizer(wx.VERTICAL)

        wSizer2 = wx.WrapSizer(wx.HORIZONTAL, wx.WRAPSIZER_DEFAULT_FLAGS)

        self.engine_threshold_text = wx.StaticText(self, wx.ID_ANY, u"Engines Threshold", wx.DefaultPosition,
                                                   wx.DefaultSize, 0)
        self.engine_threshold_text.Wrap(-1)

        wSizer2.Add(self.engine_threshold_text, 0, wx.ALL, 5)

        self.engine_threshold_slider = wx.Slider(self, wx.ID_ANY, 80, 0, 100, wx.DefaultPosition, wx.Size(500, -1),
                                                 wx.SL_HORIZONTAL)
        wSizer2.Add(self.engine_threshold_slider, 0, wx.ALL, 5)

        wSizer3 = wx.WrapSizer(wx.HORIZONTAL, wx.WRAPSIZER_DEFAULT_FLAGS)

        wSizer3.SetMinSize(wx.Size(500, -1))
        self.sens_low_text = wx.StaticText(self, wx.ID_ANY, u"   Low", wx.DefaultPosition, wx.Size(250, -1), 0)
        self.sens_low_text.Wrap(-1)

        wSizer3.Add(self.sens_low_text, 0, wx.ALL, 5)

        self.sens_high_text = wx.StaticText(self, wx.ID_ANY, u"                                          High",
                                            wx.Point(-1, -1), wx.Size(200, -1), 0)
        self.sens_high_text.Wrap(-1)

        wSizer3.Add(self.sens_high_text, 0, wx.ALL, 5)

        wSizer2.Add(wSizer3, 1, wx.EXPAND, 5)

        bSizer5.Add(wSizer2, 0, 0, 5)

        wSizer31 = wx.WrapSizer(wx.HORIZONTAL, wx.WRAPSIZER_DEFAULT_FLAGS)

        self.scan_pe_check = wx.CheckBox(self, wx.ID_ANY, u"Scan only PE files", wx.DefaultPosition, wx.Size(150, -1),
                                         0)
        self.scan_pe_check.SetValue(True)
        wSizer31.Add(self.scan_pe_check, 0, wx.ALL, 5)

        self.grayware_check = wx.CheckBox(self, wx.ID_ANY, u"Grayware Detection", wx.DefaultPosition, wx.Size(150, -1),
                                          0)
        self.grayware_check.SetValue(True)
        wSizer31.Add(self.grayware_check, 0, wx.ALL, 5)

        self.upload_check = wx.CheckBox(self, wx.ID_ANY, u"Auto Upload Files", wx.DefaultPosition, wx.Size(150, -1), 0)
        wSizer31.Add(self.upload_check, 0, wx.ALL, 5)

        self.log_check = wx.CheckBox(self, wx.ID_ANY, u"Save Log", wx.DefaultPosition, wx.Size(150, -1), 0)
        self.log_check.SetValue(True)
        wSizer31.Add(self.log_check, 0, wx.ALL, 5)

        self.crawler_check = wx.CheckBox(self, wx.ID_ANY, u"Use Crawler              ", wx.DefaultPosition,
                                         wx.DefaultSize, 0)
        wSizer31.Add(self.crawler_check, 0, wx.ALL, 5)

        self.menu_check = wx.CheckBox(self, wx.ID_ANY, u"Folder Context Menu", wx.DefaultPosition, wx.Size(150, -1), 0)
        wSizer31.Add(self.menu_check, 0, wx.ALL, 5)

        self.white_check = wx.CheckBox(self, wx.ID_ANY, u"WhiteList Cache  ", wx.DefaultPosition, wx.Size(150, -1), 0)
        self.white_check.SetValue(True)
        wSizer31.Add(self.white_check, 0, wx.ALL, 5)

        self.black_check = wx.CheckBox(self, wx.ID_ANY, u"BlackList Cache", wx.DefaultPosition, wx.Size(150, -1), 0)
        wSizer31.Add(self.black_check, 0, wx.ALL, 5)

        self.menu_file_check = wx.CheckBox(self, wx.ID_ANY, u"File Context Menu", wx.DefaultPosition, wx.Size(150, -1),
                                           0)
        wSizer31.Add(self.menu_file_check, 0, wx.ALL, 5)

        bSizer5.Add(wSizer31, 1, wx.EXPAND, 5)

        wSizer19 = wx.WrapSizer(wx.HORIZONTAL, wx.WRAPSIZER_DEFAULT_FLAGS)

        self.vtapi_text = wx.StaticText(self, wx.ID_ANY, u"VTAPI:", wx.DefaultPosition, wx.Size(150, -1), 0)
        self.vtapi_text.Wrap(-1)

        wSizer19.Add(self.vtapi_text, 0, wx.ALL, 5)

        self.vtapi_input = wx.TextCtrl(self, wx.ID_ANY, wx.EmptyString, wx.DefaultPosition, wx.Size(300, -1), 0)
        wSizer19.Add(self.vtapi_input, 0, wx.ALL, 5)

        bSizer5.Add(wSizer19, 1, wx.EXPAND, 5)

        self.ok_but = wx.Button(self, wx.ID_ANY, u"Save", wx.DefaultPosition, wx.DefaultSize, 0)
        bSizer5.Add(self.ok_but, 0, wx.ALL, 5)

        self.SetSizer(bSizer5)
        self.Layout()

        self.Centre(wx.BOTH)

        # Connect Events
        self.Bind(wx.EVT_CLOSE, self.close_set)
        self.engine_threshold_slider.Bind(wx.EVT_SCROLL, self.show_threshold_slider)
        self.engine_threshold_slider.Bind(wx.EVT_SCROLL_CHANGED, self.update_value)
        self.crawler_check.Bind(wx.EVT_CHECKBOX, self.crawler_message)
        self.menu_check.Bind(wx.EVT_CHECKBOX, self.add_menu)
        self.menu_file_check.Bind(wx.EVT_CHECKBOX, self.add_file_menu)
        self.ok_but.Bind(wx.EVT_BUTTON, self.save_settings_but_click)

    def __del__(self):
        pass

    # Virtual event handlers, overide them in your derived class
    def close_set(self, event):
        event.Skip()

    def show_threshold_slider(self, event):
        event.Skip()

    def update_value(self, event):
        event.Skip()

    def crawler_message(self, event):
        event.Skip()

    def add_menu(self, event):
        event.Skip()

    def add_file_menu(self, event):
        event.Skip()

    def save_settings_but_click(self, event):
        event.Skip()


###########################################################################
## Class about_frame
###########################################################################

class about_frame(wx.Frame):

    def __init__(self, parent):
        wx.Frame.__init__(self, parent, id=wx.ID_ANY, title=u"About", pos=wx.DefaultPosition, size=wx.Size(300, 180),
                          style=wx.DEFAULT_FRAME_STYLE | wx.TAB_TRAVERSAL)

        self.SetSizeHints(wx.DefaultSize, wx.DefaultSize)
        self.SetBackgroundColour(wx.Colour(255, 255, 255))

        bSizer4 = wx.BoxSizer(wx.VERTICAL)

        self.text_static = wx.StaticText(self, wx.ID_ANY, u"\nBy 191196846", wx.DefaultPosition, wx.DefaultSize, 0)
        self.text_static.Wrap(-1)

        bSizer4.Add(self.text_static, 0, wx.ALL | wx.EXPAND | wx.ALIGN_CENTER_HORIZONTAL, 5)

        self.link_kafan = wx.adv.HyperlinkCtrl(self, wx.ID_ANY, u"See the post on Kafan",
                                               u"https://bbs.kafan.cn/thread-2133049-1-1.html", wx.DefaultPosition,
                                               wx.DefaultSize, wx.adv.HL_DEFAULT_STYLE)
        bSizer4.Add(self.link_kafan, 0, wx.ALL, 5)

        self.text_static_2 = wx.StaticText(self, wx.ID_ANY, u"To use this tool, you must agree", wx.DefaultPosition,
                                           wx.DefaultSize, 0)
        self.text_static_2.Wrap(-1)

        bSizer4.Add(self.text_static_2, 0, wx.ALL, 5)

        self.link_vt = wx.adv.HyperlinkCtrl(self, wx.ID_ANY, u"VirusTotal Terms of Service",
                                            u"https://support.virustotal.com/hc/en-us/articles/115002145529-Terms-of-Service",
                                            wx.DefaultPosition, wx.DefaultSize, wx.adv.HL_DEFAULT_STYLE)
        bSizer4.Add(self.link_vt, 0, wx.ALL, 5)

        self.SetSizer(bSizer4)
        self.Layout()

        self.Centre(wx.BOTH)

        # Connect Events
        self.Bind(wx.EVT_CLOSE, self.close_set)

    def __del__(self):
        pass

    # Virtual event handlers, overide them in your derived class
    def close_set(self, event):
        event.Skip()
































































































