'''
clamd , yara , spamc , spamscope used for detecting malicious files
'''

#######yara match

import yara

rules = yara.compile(filepaths={
    "malware_set1 rules": "/home/bits/PycharmProjects/VT-scaneng/licenta/yara_rules/rules-master/index.yar",
    "malware set2 rules": "/home/bits/PycharmProjects/VT-scaneng/licenta/yara_rules/yara-rules-master/malware.yar"})


def yara_match(file_path, rules=rules):
    try:
        matches = rules.match(file_path, timeout=60)
        return matches
    #except TimeoutError:
    #    print("the time is running out")
    except:
        print("something")

######### clamd scan
import clamd

try:
    cdd = clamd.ClamdUnixSocket()
    #test if the server is reacchable
    cdd.ping()
except clamd.ConnectionError:
    cdd = clamd.ClamdNetworkSocket()
    try:
        cdd.ping()
    except clamd.ConnectionError:
        raise ("could not connect to the clamd server either by unix or network socket")

cdd.reload()

def clamav_scan(file_path, cdd=cdd):
    result=[]
    if 'OK' in cdd.scan(file_path)[file_path]:
        result.append("The file is not malicious or CLAMAV does not have signatures for this malware/file")
    else:
        result.append(cdd.scan(file_path))
    with open(file_path,"rb") as file1:
        with open(file_path,"rb") as file2:
            if 'OK' in cdd.instream(file1)['stream']:
                result.append("no malicious streams were identified using clamav stream scanning")
            else:
                result.append(cdd.instream(file2))
    return result

