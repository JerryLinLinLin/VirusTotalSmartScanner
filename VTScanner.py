from __future__ import print_function
import winreg as reg
import wx, VTGUI, main, threading, os, datetime, sys, ctypes, time, webbrowser


class Clean(threading.Thread):

    def __init__(self):
        threading.Thread.__init__(self)
        self.start()

    def run(self):
        self.remove()

    def remove(self):
        i =0
        if len(frame.current_scan_data_infected) ==0:
            frame.remove_but.Enable()
            return
        files = frame.current_scan_data_infected
        for file in files:
            path = files[file]["path"]
            try:
                os.remove(path)
                i = i +1
            except:
                wx.MessageBox("Cannot Remove File: " + path)
        frame.data_grid.DeleteRows(0, frame.data_grid.GetNumberRows())
        frame.current_scan_data_infected.clear()
        frame.infected_files = 0
        wx.MessageBox("Remove " + str(i) + " file(s) successfully")
        frame.data_grid.Enable()
        frame.remove_but.Enable()
        return



class ScanThread(threading.Thread):
    path = None
    sensitivity = None
    upload = False
    need_check_files = set()
    bl = None
    wl = None

    def __init__(self, path, sensitivity, upload):
        threading.Thread.__init__(self)
        self.path = path
        self.sensitivity = sensitivity
        self.upload = upload
        self.start()
        frame.start_time = datetime.datetime.now()

    def run(self):
        files = main.emul(self.path, frame.settings["scan_pe_check"])
        frame.num_file = len(files)
        if files == "fail":
            return
        self.get_report(files)
        frame.scan_finished()
        return

    def get_report(self, files):
        if not os.path.exists(os.getcwd() + "\\data"):
            os.makedirs(os.getcwd() + "\\data")
        try:
            f_infected = open(os.getcwd() + "\\data\\" + "bl.dat", "r")
            f_clean = open(os.getcwd() + "\\data\\" + "wl.dat", "r")
        except:
            f_infected = open(os.getcwd() + "\\data\\" + "bl.dat", "w+")
            f_clean = open(os.getcwd() + "\\data\\" + "wl.dat", "w+")

        self.bl = f_infected.read()
        self.wl = f_clean.read()
        k = 1
        while True:
            start_time = datetime.datetime.now()
            current_files = set()
            i = 1
            for file in files:

                if frame.stop_sign:
                    return
                frame.scan_gauge.SetValue(i/len(files) * 100)

                sha256 = file.get_file_sha256()
                file_path = str(file.full_path)
                frame.SetStatusText("Loop#" + str(k) +"(" + str(i) + "/" + str(len(files)) + ") Scanning: ..." + file_path[
                                                                                               len(file_path) // 2: len(
                                                                                                   file_path)])

                if frame.settings["black_check"]:
                    bl_result = self.bl.find(sha256)
                    if bl_result != -1:
                        threatname = self.bl[bl_result + 64: bl_result + 94].rstrip()
                        print(str(threatname) + " cache")
                        data = {"threat": threatname, "filename": file.name, "path": file.full_path, "sha256": sha256,
                                "cache": True}
                        frame.add_data(data)
                        i = i + 1
                        continue

                if frame.settings["white_check"]:
                    wl_result = self.wl.find(sha256)
                    if wl_result != -1:
                        data = {"threat": "Clean", "filename": file.name, "path": file.full_path, "sha256": sha256,
                                "cache": True}
                        frame.add_data(data)
                        i = i + 1
                        continue

                api = frame.get_api()
                report = file.get_vt_report(apikey=api, use_crawler=frame.settings["crawler_check"])
                if report == "wrongkey":
                    frame.scan_finished()
                    return
                if report == "Unknown":
                    if self.upload:
                        frame.SetStatusText("Loop#" + str(k) +"(" + str(i) + "/" + str(len(files)) + ") Uploading: ..." + file_path[len(
                            file_path) // 2: len(file_path)])
                        upload_status = file.upload_vt(api)
                        if upload_status:
                            current_files.add(file)
                            print("upload successful")
                            i = i + 1
                            continue
                        else:
                            i = i + 1
                            continue
                    else:
                        i = i + 1
                        continue
                if report == "Analyzing" or report == "Fail":
                    print("Analyzing... " + str(file.full_path))
                    current_files.add(file)
                    i = i + 1
                    continue
                else:
                    threatname = file.get_threat_type(report, self.sensitivity, frame.settings["grayware_check"])
                    data = {"threat": threatname, "filename": file.name, "path": file.full_path, "sha256": sha256,
                            "cache": False}
                    frame.add_data(data)
                    i = i + 1


            if len(current_files) == 0:
                break
            else:
                files = current_files
                k = k + 1
                end_time = datetime.datetime.now()
                interval = (end_time - start_time).seconds
                print(str(interval) + "seconds")
                frame.scan_gauge.SetValue(0)
                frame.SetStatusText("Waiting for cloud to scan files...")
                if interval <=10:
                    time.sleep(10)
                else:
                    time.sleep(5)

        f_infected.close()
        f_clean.close()
        return True


class mainwindow(VTGUI.VT_AVScanner):
    num_file = 0
    settings = dict()
    start_time = None
    end_time = None
    scan_thread = None
    current_scan_data_infected = dict()
    current_scan_data_clean = dict()
    infected_files = 0
    stop_sign = False

    def __init__(self, parent):
        VTGUI.VT_AVScanner.__init__(self, parent)
        self.ini_data()
        self.Title = "VirusTotal Smart Scanner " + "1.09"


    def ini_data(self):
        try:
            f = open(os.getcwd() + "\\" + "config.ini", "r")
        except:
            return
        self.settings = eval(f.read())
        f.close()


    def scan_but_click(self, event):
        print(self.settings)
        if len(self.settings) ==0:
            self.open_set()
            return
        self.process_scan()


    def stop_but_click(self, event):
        self.stop_but.Label = 'Stopping...'
        self.SetStatusText("Stopping Scan, Please Wait...")
        self.stop_but.Disable()
        self.stop_sign = True

    def process_scan(self):
        path = self.path_dir.GetPath()
        if not (os.access(path, os.R_OK)):
            wx.MessageBox("Invalid folder path, Please check again!", "Error")
            return
        self.scan_ini()
        self.scan_thread = ScanThread(path, self.settings["engine_threshold_slider"], self.settings["upload_check"])

    def add_data(self, data=dict()):
        if data["threat"] == "NoRisk":
            return
        if data["threat"] == "Clean":
            self.current_scan_data_clean[data["path"]] = data
            return
        self.data_grid.AppendRows(1, True)
        row = self.data_grid.GetNumberRows() - 1
        self.data_grid.SetCellValue(row, 0, data["threat"])
        self.data_grid.SetCellValue(row, 1, data["filename"])
        self.data_grid.SetCellValue(row, 2, data["path"])
        self.data_grid.SetCellValue(row, 3, data["sha256"])
        self.current_scan_data_infected[data["path"]] = data
        self.infected_files = self.infected_files +1

    def scan_ini(self):
        self.scan_but.Disable()
        self.scan_but.Label = "Scanning..."
        self.path_dir.Disable()
        self.stop_but.Enable()
        self.data_grid.ClearGrid()
        self.scan_gauge.SetValue(0)
        row = self.data_grid.GetNumberRows()
        if row != 0:
            self.data_grid.DeleteRows(0, self.data_grid.GetNumberRows())
        self.current_scan_data_infected.clear()
        self.infected_files = 0
        self.stop_sign = False
        self.SetStatusText("Initialize Scan...")

    def scan_finished(self):
        self.scan_but.Enable()
        self.scan_but.Label = "Scan"
        self.path_dir.Enable()
        self.stop_but.Label = 'Stop'
        self.stop_but.Disable()
        self.scan_gauge.SetValue(100)
        self.SetStatusText("Scan Finished: " + str(len(self.current_scan_data_infected)) + " threats have been detected.")
        log_file = self.log()

        if self.settings["black_check"]:
            f = open(os.getcwd() + "\\data\\" + "bl.dat", "a")
            data = ""
            for each in self.current_scan_data_infected:
                if not self.current_scan_data_infected[each]["cache"]:
                    data = data + self.current_scan_data_infected[each]["sha256"] + str(
                        self.current_scan_data_infected[each]["threat"]).ljust(30)
            f.write(data)
            f.close()
        if self.settings["white_check"]:
            f = open(os.getcwd() + "\\data\\" + "wl.dat", "a")
            data = ""
            for each in self.current_scan_data_clean:
                if not self.current_scan_data_clean[each]["cache"]:
                    data = data + self.current_scan_data_clean[each]["sha256"] + "\n"
            f.write(data)
            f.close()

        if self.settings["log_check"]:
            if wx.MessageBox("Scan Finished. Open log file?", style=wx.YES_NO) == 2:
                os.startfile(log_file)
        else:
            wx.MessageBox("Scan Finished.")

    def log(self):
        if not (self.settings["log_check"]):
            return
        self.end_time = datetime.datetime.now()
        interval = (self.end_time - self.start_time).seconds
        time = datetime.datetime.strftime(self.end_time, '%Y-%m-%d-%H-%M-%S')
        log_folder = os.getcwd() + "\\log"
        if not os.path.exists(log_folder):
            os.makedirs(log_folder)
        log_file = os.getcwd() + "\\log\\" + "Scan" + time + ".log"
        f = open(log_file, "a")
        f.write(str(self.Title) + "\n" +
                "\n" +
                "======================================================================================" + "\n" +
                "Scan Time: ".ljust(30) + time + "\n" +
                "Scan Duration: ".ljust(30) + str(interval) + " seconds" + "\n" +
                "Scan Target: ".ljust(30) + str(self.path_dir.GetPath()) + "\n" +
                "Number of Scan Files: ".ljust(30) + str(self.num_file) + "\n" +
                "Number of Infected Files: ".ljust(30) + str(self.infected_files) + "\n" +
                "\n" )

        for setting in self.settings:
            if setting != "vtapi_input":
                sett = str(setting).ljust(30) + ": " + str(self.settings[setting]) + "\n"
                f.write(sett)


        f.write(
            "======================================================================================" + "\n" + "\n" +
            "Threat(s): " + "\n"
        )

        for threat in self.current_scan_data_infected:
            file = self.current_scan_data_infected[threat]
            data = str(file["threat"]).ljust(30) + "  sha256: " + str(file["sha256"]).ljust(50) + "    Path: " + str(file["path"]) + "\n"
            f.write(data)
        f.close()
        return log_file

    def open_log_folder_but_click(self, event):
        log_path = os.getcwd() + "\\log"
        if not os.path.exists(log_path):
            os.makedirs(log_path)
        os.startfile(os.getcwd() + "\\log")


    def get_api(self):
        apikey = self.settings["vtapi_input"]
        if apikey != "":
            api_set = dict()
            if apikey.find(";") == -1:
                api_set[1] = apikey
            i = 1
            while True:
                index = apikey.find(";")
                if index == -1:
                    api_set[i] = apikey
                    break
                api_set[i] = apikey[0: index]
                apikey = apikey[index + 1: len(apikey)]
                i = i + 1
            return api_set

    def remove_but_click(self, event):
        self.remove_but.Disable()
        self.SetStatusText("")
        Clean()

    def open_set_but_click(self, event):
        self.open_set()

    def open_set(self):
        frame_set = settings_window(None)
        frame_set.Show(True)
        frame_set.Icon = wx.Icon('Scanner.ico', wx.BITMAP_TYPE_ICO)

    def about_click(self, event):
        frame_about = about_window(None)
        frame_about.Show(True)
        frame_about.Icon = wx.Icon('Scanner.ico', wx.BITMAP_TYPE_ICO)


class about_window(VTGUI.about_frame):

    def __init__(self, parent):
        VTGUI.about_frame.__init__(self, parent)
        frame.Disable()

    def close_set(self, event):
        frame.Enable()
        self.Destroy()

class settings_window(VTGUI.Settings_window):


    def __init__(self, parent):
        VTGUI.Settings_window.__init__(self, parent)
        frame.Disable()
        if len(frame.settings) ==0:
            self.set_settings()
        else:
            self.ini_config()
        self.engine_threshold_text.Label = "Engines Threshold: " + str(self.engine_threshold_slider.GetValue()) + "%"

    def ini_config(self):
        self.engine_threshold_slider.SetValue(frame.settings["engine_threshold_slider"])
        self.upload_check.SetValue(frame.settings["upload_check"])
        self.log_check.SetValue(frame.settings["log_check"])
        self.vtapi_input.SetValue(frame.settings["vtapi_input"])
        self.menu_check.SetValue(frame.settings["menu_check"])
        self.menu_file_check.SetValue(frame.settings["menu_file_check"])
        self.scan_pe_check.SetValue(frame.settings["scan_pe_check"])
        self.grayware_check.SetValue(frame.settings["grayware_check"])
        self.black_check.SetValue(frame.settings["black_check"])
        self.white_check.SetValue(frame.settings["white_check"])
        self.crawler_check.SetValue(frame.settings["crawler_check"])

    def set_settings(self):
        frame.settings = {
            "engine_threshold_slider": self.engine_threshold_slider.GetValue(),
            "upload_check": self.upload_check.GetValue(),
            "log_check": self.log_check.GetValue(),
            "vtapi_input": self.vtapi_input.GetValue(),
            "menu_check": self.menu_check.GetValue(),
            "menu_file_check": self.menu_file_check.GetValue(),
            "scan_pe_check": self.scan_pe_check.GetValue(),
            "grayware_check": self.grayware_check.GetValue(),
            "black_check": self.black_check.GetValue(),
            "white_check": self.white_check.GetValue(),
            "crawler_check": self.crawler_check.GetValue()
        }

    def save_settings_but_click(self, event):
        f = open(os.getcwd() + "\\" + "config.ini", "w")
        self.set_settings()
        f.write(str(frame.settings))
        f.close()
        frame.Enable()
        self.Destroy()

    def close_set(self, event):
        frame.Enable()
        self.Destroy()

    def crawler_message(self, event):
        if self.crawler_check.GetValue():
            wx.MessageBox("During scanning, you may need to verify CAPTCHA.\n Please notice that DO NOT abuse this function!")

    def show_threshold_slider(self, event):
        self.engine_threshold_text.Label = "Engines Threshold: " + str(self.engine_threshold_slider.GetValue()) + "%"

    def add_menu(self, event):
        if not self.is_admin():
            if self.menu_check.GetValue():
                self.menu_check.SetValue(False)
            else:
                self.menu_check.SetValue(True)
            wx.MessageBox("You need Admin privilege. Click to restart the program")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
            self.save_settings_but_click(wx.wxEVT_CLOSE_WINDOW)
            self.Destroy()
            frame.Destroy()
            return
        if self.menu_check.GetValue():
            main.add_context_menu("Scan with VT Smart Scanner", os.getcwd() + "\\" + "VTScanner.exe",
                                  reg.HKEY_CLASSES_ROOT, r'Directory\\shell', 'S')
        else:
            main.delete_reg_key(reg.HKEY_CLASSES_ROOT, r'Directory\\shell', "Scan with VT Smart Scanner")

    def add_file_menu(self, event):
        if not self.is_admin():
            if self.menu_file_check.GetValue():
                self.menu_file_check.SetValue(False)
            else:
                self.menu_file_check.SetValue(True)
            wx.MessageBox("You need Admin privilege. Click to restart the program")
            ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
            self.save_settings_but_click(wx.wxEVT_CLOSE_WINDOW)
            self.Destroy()
            frame.Destroy()
            return
        if self.menu_file_check.GetValue():
            main.add_context_menu("Open On VirusTotal", os.getcwd() + "\\" + "VTScanner.exe",
                                  reg.HKEY_CLASSES_ROOT, r'*\\shell', 'S')
        else:
            main.delete_reg_key(reg.HKEY_CLASSES_ROOT, r'*\\shell', "Open On VirusTotal")

    def is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False

try:
    path = sys.argv[1]
except:
    path = ""

program_path = sys.path[0][0:sys.path[0].rfind("\\")]
os.chdir(program_path)

if os.path.isfile(path):
    webbrowser.open("https://www.virustotal.com/#/file/" + str(main.get_file_sha256(path)) + "/detection")
    sys.exit()

app = wx.App(False)
frame = mainwindow(None)
frame.Icon = wx.Icon('Scanner.ico', wx.BITMAP_TYPE_ICO)

if os.path.exists(path):
    frame.path_dir.Path = path
    frame.process_scan()

frame.Show(True)
# start the applications
app.MainLoop()
