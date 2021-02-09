#!/usr/bin/env python
import requests
import json
from jsonrpclib import Server
import ssl
import getpass

username = raw_input("Enter your username:\n")
password = getpass.getpass()
server_ips = ['192.168.255.50']
csvfilename = 'inventory.csv'
image = 'EOS-4.25.1F.swi'
vrf = 'MGMT'

connect_timeout = 10
headers = {"Accept": "application/json",
           "Content-Type": "application/json"}
requests.packages.urllib3.disable_warnings()
ssl._create_default_https_context = ssl._create_unverified_context
session = requests.Session()

def login(url_prefix, username, password):
    authdata = {"userId": username, "password": password}
    headers.pop('APP_SESSION_ID', None)
    response = session.post(url_prefix+'/web/login/authenticate.do', data=json.dumps(authdata),
                            headers=headers, timeout=connect_timeout,
                            verify=False)
    cookies = response.cookies
    headers['APP_SESSION_ID'] = response.json()['sessionId']
    if response.json()['sessionId']:
        return response.json()['sessionId']

def get_inventory(url_prefix):
    response = session.get('https://'+url_prefix+'/cvpservice/inventory/devices?provisioned=true')
    return response.json()

def run_upgrade(device,username,password,serverIP,image):
    url = "https://%s:%s@%s/command-api" % (username, password, device)
    ss = Server(url)
    #CONNECT TO DEVICE
    hostname = ss.runCmds( 1, ['enable','cli vrf %s' % vrf,'install source https://%s/cvpservice/image/getImagebyId/%s' % (serverIP,image)])
    output = hostname[1]
    return output

def validate_upgrade(device,username,password,serverIP,image):
    url = "https://%s:%s@%s/command-api" % (username, password, device)
    ss = Server(url)
    #CONNECT TO DEVICE
    bootVer = ss.runCmds( 1, ['enable','show boot'])[1]['softwareImage']
    return bootVer

with open(csvfilename,'w+') as f:
    f.close()

for server in server_ips:
    device_list = []
    print '###### Logging into CVP Instance '+server+'.'
    login('https://'+server, username, password)
    inventory = get_inventory(server)
    with open(csvfilename, 'a') as f:
      f.write('server_ip,hostname,modelName,systemMacAddress,version,serialNumber,ipAddress,upgraded\n')
      for switch in inventory:
          f.write(server+',')
          hostname = switch['hostname']
          print 'Found device '+hostname
          f.write(hostname+',')
          modelName = switch['modelName']
          f.write(modelName+',')
          systemMacAddress = switch['systemMacAddress']
          f.write(systemMacAddress+',')
          version = switch['version']
          f.write(version+',')
          serialNumber = switch['serialNumber']
          f.write(serialNumber+',')
          ipAddress = switch['ipAddress']
          f.write(ipAddress+',')
          streamingStatus = switch['streamingStatus']
          if streamingStatus == 'active':
              print '|____Running Upgrade on '+hostname
              try:
                  output = run_upgrade(ipAddress,username,password,server,image)
                  print '     |____Upgrade Succeeded on '+hostname+'.'
                  f.write('Upgraded\n')
              except:
                  bootfile = validate_upgrade(ipAddress,username,password,server,image)
                  if bootfile.endswith(image):
                      print '     |____Upgrade Succeeded on '+hostname+'.'
                      f.write('Upgraded\n')
                  else:
                      print '     |____Upgrade Failed on '+hostname+'. Out of disk space?'
                      f.write('Failed\n')
          else:
              if switch['ztpMode'] == 'true':
                  print '|____Device '+hostname+' is in ZTP mode. Skipping.'
                  f.write('Skipped\n')
              else:
                  print '|____Device '+hostname+' is not streaming. Skipping.'
                  f.write('Skipped\n')
    f.close()

print '##### Complete'
