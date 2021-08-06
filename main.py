import hashlib, os, requests, struct, wx, webbrowser
import winreg as reg
from bs4 import BeautifulSoup


# path = input("Enter file path")
# print("Remove same files")

class FilePro:
    path = None
    name = None
    full_path = None
    type = None

    def __init__(self, path, name):
        self.path = path
        self.name = name
        self.full_path = self.path + "\\" + self.name
        try:
            self.type = name[name.rindex("."): len(name)]
        except:
            self.type = ""
        return

    def get_file_md5(self):
        file = open(self.full_path, "rb")
        content = file.read()
        md5 = hashlib.md5()
        md5.update(content)
        file.close()
        return md5.hexdigest()

    def get_file_sha256(self):
        file = open(self.full_path, "rb")
        content = file.read()
        sha256 = hashlib.sha256()
        sha256.update(content)
        file.close()
        return sha256.hexdigest()

    def rename(self, name):
        new_full_path = self.path + "\\" + name + self.type
        if os.path.exists(new_full_path) and new_full_path != self.full_path:
            os.remove(new_full_path)
        os.rename(self.full_path, new_full_path)
        self.name = name
        self.full_path = new_full_path
        return

    def modify(self):
        file = open(self.full_path, "ab+")
        file.write(b'000000000000')
        file.close()

    def get_360(self):
        params = {"md5s": (None, self.get_file_md5()),
                  "format": (None, "XML"),
                  "product": (None, "360zip"),
                  "combo": (None, "360zip_main"),
                  "v": (None, "2"),
                  "osver": (None, "5.1"),
                  "vk": (None, "a03bc211"),
                  "mid": (None, "8a40d9eff408a78fe9ec10a0e7e60f62")}
        return requests.post("http://qup.f.360.cn/file_health_info.php", files=params)


    def upload_vt(self, apikey = dict()):

        if os.path.getsize(self.full_path) > 31457280:
            return False

        url = 'https://www.virustotal.com/vtapi/v2/file/scan'

        if apikey is None:
            apikey = {1: "8dd0c36fd4ef57dc1effd53d580a2d2c4413c65041abcc103fe60641dc001ea4",
                      2: "a2b51c4511a5da05b595cc57e57aad2428db72ed28d66d9c72ca394f6ce47963",
                      3: "e08d3ae2419f5a7f27b37db6adaf27b6d31d06d1c522b71d9b0ad8f25b542702"}

        i = 1

        params = {'apikey': apikey[i]}
        file = {'file': (open(self.full_path, 'rb'))}
        while True:
            try:
                response = requests.post(url, params=params, files=file)
                if response.status_code == 200:
                    break
                if response.status_code == 204:
                    if i >= len(apikey):
                        i = 1
                    else:
                        i = i + 1
                    params = {'apikey': apikey[i]}
                    print("Upload: 204")
                    continue
                if response.status_code == 400 or response.status_code == 403:
                    wx.MessageBox("Invalid API key, Please enter again!", "Error")
                    print(400)
                    return "wrongkey"
                if response.status_code == 403:
                    wx.MessageBox("Your IP Address is banned by VirusTotal. You may change your IP Address by using proxy." + "\n" + "Click to try again.")
                    continue
            except:
                if wx.MessageBox("Uploading files fail. Please Check your Internet Connection." + "\n" + "Do you want to try again?", caption= "Error", style=wx.YES_NO) ==2:
                    continue
                else:
                    return "Fail"

        report = response.json()
        if report['response_code'] == 1:
            return True
        else:
            return False


    def get_vt_report(self, apikey = dict(), use_crawler = True):
        url = 'https://www.virustotal.com/vtapi/v2/file/report'
        if apikey is None:
            apikey = {1: "8dd0c36fd4ef57dc1effd53d580a2d2c4413c65041abcc103fe60641dc001ea4",
                      2: "a2b51c4511a5da05b595cc57e57aad2428db72ed28d66d9c72ca394f6ce47963",
                      3: "e08d3ae2419f5a7f27b37db6adaf27b6d31d06d1c522b71d9b0ad8f25b542702"}


        i = 1

        params = {'apikey': apikey[i], 'resource': self.get_file_sha256()}
        while True:
            try:
                response = requests.get(url, params=params)
                if response.status_code == 200:
                    report = response.json()
                    if report["response_code"] == -2:
                        return "Analyzing"
                    if report["response_code"] == 0:
                        return "Unknown"
                    else:
                        break
                if response.status_code == 204:
                    if i >= len(apikey):
                        if use_crawler:
                            return self.get_vt_report_html()
                        else:
                            i = 1
                    else:
                        i = i + 1
                    params = {'apikey': apikey[i], 'resource': self.get_file_sha256()}
                    print("Get:204")
                    continue
                if response.status_code == 400:
                    wx.MessageBox("Invalid API key, Please enter again!", "Error")
                    print(400)
                    return "wrongkey"
                if response.status_code == 403:
                    wx.MessageBox("Your IP Address is banned by VirusTotal. You may change your IP Address by using proxy." + "\n" + "Click to try again.")
                    continue
            except:
                if wx.MessageBox("Getting report fails. Please Check your Internet Connection." + "\n" + "Do you want to try again?", caption= "Error", style=wx.YES_NO) ==2:
                    continue
                else:
                    return "Fail"
        result = response.json()
        if result["response_code"] ==0:
            return result

        kaspersky = ""
        eset = ""
        malwarebytes = ""
        microsoft = ""

        if "Kaspersky" in report["scans"]:
            kaspersky = str(report["scans"]["Kaspersky"]["result"])
        if "ESET-NOD32" in report["scans"]:
            eset = str(report["scans"]["ESET-NOD32"]["result"])
        if "Malwarebytes" in report["scans"]:
            malwarebytes = str(report["scans"]["Malwarebytes"]["result"])
        if "Microsoft" in report["scans"]:
            microsoft = str(report["scans"]["Microsoft"]["result"])
        threat = kaspersky + eset + malwarebytes + microsoft
        threat = threat.lower()
        result['detections'] = threat
        return result

    def get_vt_report_html(self):
        print("use crawler")
        report = {'response_code': 0, 'positives': 0, 'detections': "", 'total': 0}
        # cookies = browser_cookie3.load()
        # headers = {
        #     'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.116 Safari/537.36'
        # }
        while True:
            try:
                url = "https://www.virustotal.com/en/file/" + self.get_file_sha256() + "/analysis/"
                response = requests.get(url)
            except:
                if wx.MessageBox("Getting report fails. Please Check your Internet Connection." + "\n" + "Do you want to try again?", caption= "Error", style=wx.YES_NO) ==2:
                    continue
                else:
                    return "Fail"
            soup = BeautifulSoup(response.text, 'lxml')
            try:
                recap = soup.find(src='https://www.google.com/recaptcha/api.js')
                if recap is not None:
                    print(recap)
                    wx.MessageBox("Click to open browser to pass the CAPTCHA")
                    webbrowser.open(url)
                    wx.MessageBox('When you finished, Click OK')
                    continue
            except:
                wx.MessageBox("Your IP Address is banned by VirusTotal. You may change your IP Address by using proxy." + "\n" + "Click to try again.")
                continue

            # if str(soup.find(src= 'https://virustotalcloud.appspot.com/static/img/wait.gif').string).find('que') != -1:
            #     time.sleep(5)
            #     continue
            a = soup.find(class_='text-green')
            if a is not None:
                if str(a.string).find('0 / 0') !=-1:
                    return "Analyzing"
                else:
                    break
            else:
                break

        if soup.find(class_="alert-heading") is not None:
            print("Unknown")
            return "Unknown"

        report['response_code'] = 1

        try:
            t = str(soup.find(class_='row').div.table.find(class_='text-red').string).strip()
            report['positives'] = t[0:t.find('/')].strip()
            report['total'] = t[t.find('/') + 2: len(t)].strip()
        except:
            return report


        results = soup.find(id="active-tab").find(id="antivirus-results").find_all(class_="ltr text-red")
        for result in results:
            name = str(result.parent.td.string).rstrip().strip().strip("\n")
            if name == "Kaspersky" or name == "ESET-NOD32" or name == "Malwarebytes" or name == "Microsoft":
                report['detections'] = str(report['detections']) + str(result.string).strip().strip("\n")
        report['detections'] = report['detections'].lower()
        return report

    def get_threat_type(self, report, sensitivity, is_grayware = True):
        if report == "Fail":
            return "Fail"
        if report == "Unknown":
            return 'Unknown'
        detected_num = report["positives"]
        threat = report['detections']

        if int(detected_num) ==0:
            return "Clean"

        final_verdict = ""

        type_category = {
            "Win32.":                   ["win32"],
            "Win64.":                   ["win64"],
            "JS.":                      ["js"],
            "VBS.":                     ["vba", "vbs"],
            "Shell.":                   ["shell"],
            "Html.":                    ["html"],
            "Macro.":                   ["doc", "macro", "office"],
            "PDF.":                     ["pdf"],
            "Script.":                  ["script", "swf"],
            "Email.":                   ["email"],
            "Java.":                    ["java"],
            "Linux.":                   ["linux"],
            "Android.":                 ["android"]
        }

        for name, rules in type_category.items():
            for rule in rules:
                if threat.find(rule) != -1:
                    final_verdict = final_verdict + name
                    break
            else:
                continue
            break

        print(final_verdict)

        threat_category = {
            "Phishing.Generic":         ["phishing"],
            "Exploit.Generic":          ["exp", "cve"],
            "Worm.Generic":             ["worm"],
            "Ransom.Generic":           ["ransom", "code", "mbr"],
            "Rootkit.Generic":          ["root", "uefi", "boot"],
            "Backdoor.Bot":             ["bot", "fareit", "rat"],
            "Backdoor.Generic":         ["backdoor", "bds"],
            "Trojan.Banker":            ["banker", "emotet"],
            "Trojan.Spy":               ["spy"],
            "Trojan.Downloader":        ["downloader"],
            "Trojan.PasswordStealer":   ["pws", "psw", "passwordstealer"],
            "Trojan.Dropper":           ["drop"],
            "Trojan.Injector":          ["inject"],
            "Trojan.CoinMiner":         ["coin", "mine"],
            "Trojan.Generic":           ["trojan", "virtool", "vho", "kry", "msil", "dangerous", "generik", "adwin"]
        }
        print(int(detected_num) / int(report['total']))

        if is_grayware:
            threat_category["Grayware.Unwanted"] = ["potentially unwanted", "adware", "pua", "pup", "unwan"]
            threat_category["Grayware.RiskTool"] = ["potentially unsafe", "hacktool", "risk", "not-a-virus"]


        for name, rules in threat_category.items():
            for rule in rules:
                if threat.find(rule) != -1:
                    if final_verdict == "":
                         return "Win32." + name
                    else:
                        return final_verdict + name

        if final_verdict != "":
            return final_verdict + "Trojan.Generic"

        threshold = int(detected_num) / int(report['total'])
        if threshold > (1 - (sensitivity / 100)):
            return "Malware.Confidence:" + str(int(threshold * 100)) + "%"
        else:
            return "NoRisk"

    def classify(self, threatname):
        self.rename(str(threatname) + "_" + self.get_file_md5())


def readFileChar(path):
    try:
        fileHandle = open(path, "rb")
        data_id = struct.unpack("h", fileHandle.read(2))
        fileHandle.close()
        return data_id[0]
    except:
        return


def getShifting(path):
    try:
        # 获得0x3c地址的值，pe文件应为0x45 50
        fileHandle = open(path, "rb")
        fileHandle.seek(60, 0)
        data_id = struct.unpack("h", fileHandle.read(2))[0]
        fileHandle.close()
        # print data_id
        fileHandle = open(path, "rb")
        fileHandle.seek(data_id, 0)
        pe = struct.unpack("h", fileHandle.read(2))[0]
        fileHandle.close()
        return pe
    except:
        return


def isPE(path):
    if readFileChar(path) == 23117 and getShifting(path) == 17744:
        return True


def emul(path, PE=True):
    allfiles = set()
    files = os.walk(path)
    for interfile in files:
        file_name = interfile[2]
        for filename in file_name:
            if PE:
                if isPE(interfile[0] + "\\" + filename):
                    allfiles.add(FilePro(interfile[0], filename))
            else:
                allfiles.add(FilePro(interfile[0], filename))
    return allfiles


def print_result(allfiles=set()):
    for file in allfiles:
        print(file.full_path + "   " + file.get_file_md5())


def remove_same(path):
    i = ""
    allfiles = emul(path)
    for file in allfiles:
        if i.find(file.get_file_md5()) != -1:
            os.remove(file.full_path)
        else:
            i = i + " " + file.get_file_md5()
    return emul(path)


def add_context_menu(menu_name, command, reg_root_key_path, reg_key_path, shortcut_key):

    key = reg.OpenKey(reg_root_key_path, reg_key_path)
    reg.SetValue(key, menu_name, reg.REG_SZ, menu_name + '(&{0})'.format(shortcut_key))
    sub_key = reg.OpenKey(key, menu_name)
    reg.SetValue(sub_key, 'command', reg.REG_SZ, command + ' "%1"')
    reg.CloseKey(sub_key)
    reg.CloseKey(key)


def delete_reg_key(root_key, key, menu_name):

    try:
        parent_key = reg.OpenKey(root_key, key)
    except Exception as msg:
        print(msg)
        return
    if parent_key:
        try:
            menu_key = reg.OpenKey(parent_key, menu_name)
        except Exception as msg:
            print(msg)
            return
        if menu_key:
            try:
                reg.DeleteKey(menu_key, 'command')
            except Exception as msg:
                print(msg)
                return
            else:
                reg.DeleteKey(parent_key, menu_name)

def get_file_sha256(path):
    file = open(path, "rb")
    content = file.read()
    sha256 = hashlib.sha256()
    sha256.update(content)
    file.close()
    return sha256.hexdigest()
