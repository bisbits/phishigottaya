import requests
import urllib.request,urllib.parse
import os
from time import sleep

'''
The API response format is a JSON object containing at least the following two properties:

    response_code: if the item you searched for was not present in VirusTotal's dataset this result will be 0. If the requested item is still queued for analysis it will be -2. If the item was indeed present and it could be retrieved it will be 1. Any other case is detailed in the following sections.
    verbose_msg: provides verbose information regarding the response_code property.

Whenever you exceed the public API request rate limit a 204 HTTP status code is returned. If you try to perform calls to functions for which you do not have the required privileges an HTTP Error 403 Forbidden is raised.

'''

def scan_md5(params):
    return requests.post('https://www.virustotal.com/vtapi/v2/file/report',
params=params)

'''
            {
      'response_code': 1,
      'scan_id': '54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71-1390472785'
      'permalink': 'https://www.virustotal.com/file/__sha256hash__/analysis/1390472785/',
      'sha256': '54bc950d46a0d1aa72048a17c8275743209e6c17bdacfc4cb9601c9ce3ec9a71',
      'resource': '7657fcb7d772448a6d8504e4b20168b8',
    }
'''

def rescan_md5(params):
    return requests.post('https://www.virustotal.com/vtapi/v2/file/rescan',params=params)

def get_raport(headers, params):
    rp_raport = requests.get('https://www.virustotal.com/vtapi/v2/file/report',
      params=params, headers=headers)
    return rp_raport.json()

'''
    {
     'response_code': 1,
     'verbose_msg': 'Scan finished, scan information embedded in this object',
     'resource': '99017f6eebbac24f351415dd410d522d',
     'scan_id': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c-1273894724',
     'md5': '99017f6eebbac24f351415dd410d522d',
     'sha1': '4d1740485713a2ab3a4f5822a01f645fe8387f92',
     'sha256': '52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c',
     'scan_date': '2010-05-15 03:38:44',
     'positives': 40
     
     'total': 40,
     'scans': {
        'nProtect': {'detected': true, 'version': '2010-05-14.01', 'result': 'Trojan.Generic.3611249', 'update': '20100514'},
        'CAT-QuickHeal': {'detected': true, 'version': '10.00', 'result': 'Trojan.VB.acgy', 'update': '20100514'},
        'McAfee': {'detected': true, 'version': '5.400.0.1158', 'result': 'Generic.dx!rkx', 'update': '20100515'},
        'TheHacker': {'detected': true, 'version': '6.5.2.0.280', 'result': 'Trojan/VB.gen', 'update': '20100514'},
        .
        .
        .
        'VirusBuster': {'detected': true, 'version': '5.0.27.0', 'result': 'Trojan.VB.JFDE', 'update': '20100514'},
        'NOD32': {'detected': true, 'version': '5115', 'result': 'a variant of Win32/Qhost.NTY', 'uwpdate': '20100514'},
        'F-Prot': {'detected': false, 'version': '4.5.1.85', 'result': null, 'update': '20100514'},
        'Symantec': {'detected': true, 'version': '20101.1.0.89', 'result': 'Trojan.KillAV', 'update': '20100515'},
        'Norman': {'detected': true, 'version': '6.04.12', 'result': 'W32/Smalltroj.YFHZ', 'update': '20100514'},
        'TrendMicro-HouseCall': {'detected': true, 'version': '9.120.0.1004', 'result': 'TROJ_VB.JVJ', 'update': '20100515'},
        'Avast': {'detected': true, 'version': '4.8.1351.0', 'result': 'Win32:Malware-gen', 'update': '20100514'},
        'eSafe': {'detected': true, 'version': '7.0.17.0', 'result': 'Win32.TRVB.Acgy', 'update': '20100513'}
      },
     'permalink': 'https://www.virustotal.com/file/52d3df0ed60c46f336c131bf2ca454f73bafdc4b04dfa2aea80746f5ba9e6d1c/analysis/1273894724/'
    }
    '''
    
def post_file(files,params):
    return requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)

'''
    {
      'permalink': 'https://www.virustotal.com/file/d140c...244ef892e5/analysis/1359112395/',
      'resource': u'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556',
      'response_code': 1,
      'scan_id': 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556-1359112395',
      'verbose_msg': 'Scan request successfully queued, come back later for the report',
      'sha256': 'd140c244ef892e59c7f68bd0c6f74bb711032563e2a12fa9dda5b760daecd556'
    }
    '''
 
def scan_url(params):
    return requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params)

'''
        {
      'response_code': 1,
      'verbose_msg': 'Scan request successfully queued, come back later for the report',
      'scan_id': '1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31-1320752364',
      'scan_date': '2015-11-08 11:39:24',
      'url': 'http://www.virustotal.com/',
      'permalink': 'http://www.virustotal.com/url/1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31/analysis/1320752364/'
    }
    '''

def url_report(params,headers):
    return requests.post('https://www.virustotal.com/vtapi/v2/url/report',
                             params=params, headers=headers)

'''
response=url_report(...)
json_response=response.json()
print(json_response)
{
  'response_code': 1,
  'verbose_msg': 'Scan finished, scan information embedded in this object',
  'scan_id': '1db0ad7dbcec0676710ea0eaacd35d5e471d3e11944d53bcbd31f0cbd11bce31-1390467782',
  'permalink': 'https://www.virustotal.com/url/__urlsha256__/analysis/1390467782/',
  'url': 'http://www.virustotal.com/',
  'scan_date': '2014-01-23 09:03:02',
  'filescan_id': None,
  'positives': 0,
  'total': 51,
  'scans': {
      'CLEAN MX': {'detected': False, 'result': 'clean site'},
      'MalwarePatrol': {'detected': False, 'result': 'clean site'}
      [... continues ...]
  }
}
'''
def ipaddr_reports(parameters,url_vt):
    return (urllib.request.urlopen('%s?%s' % (url_vt, urllib.parse.urlencode(parameters))).read())
'''
response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
response_dict = json.loads(response)
print response_dict

{u'response_code': 1,
 u'verbose_msg': u'IP address found in dataset',
 u'resolutions': [
    {u'last_resolved': u'2013-04-08 00:00:00', u'hostname': u'027.ru'},
    {u'last_resolved': u'2013-04-08 00:00:00', u'hostname': u'auto.rema-tiptop.ru'},
    {u'last_resolved': u'2013-04-08 00:00:00', u'hostname': u'catalog24de.ru'},
    {u'last_resolved': u'2013-04-08 00:00:00', u'hostname': u'club.velhod.ru'},
    {u'last_resolved': u'2013-04-08 00:00:00', u'hostname': u'danilova.pro'},
    ... continues ...
  ],
 u'detected_urls': [
    {"url": "http://027.ru/", "positives": 2, "total": 37, "scan_date": "2013-04-07 07:18:09"},
    ... continues ...
 ]}
'''

def domain_report(parameters,url):
    return urllib.request.urlopen('%s?%s' % (url, urllib.parse.urlencode(parameters))).read()

'''
response = urllib.urlopen('%s?%s' % (url, urllib.urlencode(parameters))).read()
response_dict = json.loads(response)
print response_dict

{"response_code": 1,
 "verbose_msg": "Domain found in dataset",
 "resolutions": [
    {"last_resolved": "2013-04-05 00:00:00", "ip_address": "90.156.201.11"},
    {"last_resolved": "2013-04-07 00:00:00", "ip_address": "90.156.201.14"},
    {"last_resolved": "2013-04-08 00:00:00", "ip_address": "90.156.201.27"},
    {"last_resolved": "2013-04-07 00:00:00", "ip_address": "90.156.201.71"},
    ... continues ...
  ],
 "detected_urls": [
    {"url": "http://027.ru/", "positives": 2, "total": 37, "scan_date": "2013-04-07 07:18:09"},
    ... continues ...
  ]}
'''



def analyze_files(attachments_md5,headers,apikeys,directory,nr):
    os.chdir(directory)
    md5_reports={}
    def chose_apikeys(apikeys, nr):
        if nr > len(apikeys):
            nr = 0
            return apikeys[nr]
        else:
            return apikeys[nr]

    for resource in attachments_md5:
        params = {'apikey': chose_apikeys(apikeys,nr), 'resource': attachments_md5[resource]}
        result=rescan_md5(params)
        nr+=1
        if result.status_code == 200:
            if result.json()["response_code"] == 1:
                md5_reports[resource] = get_raport(headers,params)
                nr+=1
            if result.json()["response_code"] == 0:
                files={"file":("resource",open(resource,"rb"))}
                result_post=post_file(files,params)
                nr+=1
                if result_post.status_code == 200:
                    if result_post.json()["response_code"] == 1:
                        sleep(20)
                        nr+=1
                        md5_reports[resource] = get_raport(headers, params)
                    if md5_reports[resource]["response_code"] == -2:
                        sleep(25)
                        md5_reports[resource] = get_raport(headers, params)
                        nr+=1
                if result_post.status_code == 204:
                    nr+=1
                    if result_post.json()["response_code"] == 1:
                        sleep(20)
                        md5_reports[resource] = get_raport(headers, params)
                        nr+=1
                    if md5_reports[resource]["response_code"] == -2:
                        sleep(25)
                        md5_reports[resource] = get_raport(headers, params)
                        nr+=1
    return md5_reports

