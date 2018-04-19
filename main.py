from licenta.classVT import *
from licenta.mail_cetrebuie import *
from licenta.detecting import *
import sys,hashlib
from time import sleep
from selenium import webdriver
from selenium.webdriver.common.by import By

'''
sending and scanning files = 'https://www.virustotal.com/vtapi/v2/file/scan'

Rescanning already submitted files = 'https://www.virustotal.com/vtapi/v2/file/rescan'

Retrieving file scan reports = 'https://www.virustotal.com/vtapi/v2/file/report'

Sending and scanning URLs = 'https://www.virustotal.com/vtapi/v2/url/scan'

Retrieving URL scan reports = 'http://www.virustotal.com/vtapi/v2/url/report'

Retrieving IP address reports = 'http://www.virustotal.com/vtapi/v2/ip-address/report'

Retrieving domain reports = 'http://www.virustotal.com/vtapi/v2/domain/report'

'''

subprocess.run("rm -rf /home/bits/PycharmProjects/VT-scaneng/licenta/attachments/*", shell=True)
subprocess.run("rm -rf /home/bits/PycharmProjects/VT-scaneng/licenta/downloaded_malware/*", shell=True)

apikeys=[ 'apikeys']

def calculate_hash(file):
    BLOCKSIZE = 65536
    hasher = hashlib.md5()
    with open(file, 'rb') as afile:
        buf = afile.read(BLOCKSIZE)
        while len(buf) > 0:
            hasher.update(buf)
            buf = afile.read(BLOCKSIZE)
    return hasher.hexdigest()

#params = {'apikey': 'apikey', 'resource': resource } #resource will be any md5/sha256/link
headers = {
    "Accept-Encoding": "gzip, deflate",
    "User-Agent" : "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0"
}

email_sample=sys.argv[1]


if email_sample[-4:] !=  ".eml":
    conv_msg(email_sample)
    email_sample=email_sample.replace(email_sample[-4:],".eml")


email_header = decode_header(email_sample)
email_body = decode_body(email_sample)
urls_from_mail = extract_urls_from_mail(email_body)
urls_redirects = []

for url in urls_from_mail:
    temp_list = extract_redirects(url)
    for URL in temp_list:    #sometimes it does not extract all elements from whitelist.
        urls_redirects.append(URL)

suspicious_indicators=[]
for url in urls_redirects:
    if (".php" in url) or (".exe" in url) or (".jar" in url) or (".js" in url):
        suspicious_indicators.append(url)

attachments_md5={}
md5_reports={}
yara_att={}
clamav_att={}
try:
    path="/home/bits/PycharmProjects/VT-scaneng/licenta/attachments/"
    os.chdir(path)
    for file in os.listdir("."):
        attachments_md5[file] = calculate_hash(file)
        yara_att[file] = yara_match(path  + file)
        clamav_att[file] = clamav_scan(path + file)
except:
    print("an error occurred at the attchments analysis")
else:
    md5_reports = analyze_files(attachments_md5,headers,apikeys,path,nr=0)

downloadedmal_md5={}
downloadedmal_raport={}
url_raports={}

'''
def scan_url(url):
    os.environ['MOZ_HEADLESS'] = '1'
    driver = webdriver.Firefox()
    driver.get("https://www.virustotal.com/#/home/url")
    driver.find_element(By.XPATH, '//*[@id="searchInput"]').send_keys(url)    #it gives me an error when trying to sent the text: "is not reachable by keyboard
    driver.find_element(By.XPATH, '//*[@id="icon"]').click()                    # it does not resolve the capcha.
'''
clamav_dm={}
yara_dm={}
if len(urls_from_mail) > 0:
    try:
        pathm="/home/bits/PycharmProjects/VT-scaneng/licenta/downloaded_malware"
        os.chdir(pathm)
        for url in urls_from_mail:
            if requests.get(url).status_code == 200:
                subprocess.run(["wget -q "+ url],shell=True)
        for file in os.listdir("."):
            downloadedmal_md5[file] = calculate_hash(file)
            yara_dm=yara_match(pathm + "/" + file)
            clamav_dm=clamav_scan(pathm + "/" + file)
            print(yara_dm,"\n\n\n\n\n",clamav_dm)

    except:
        print("an error occured")
    else:
        downloadedmal_raport = analyze_files(downloadedmal_md5,headers,apikeys,pathm,nr=0)
    finally:
        pass




















