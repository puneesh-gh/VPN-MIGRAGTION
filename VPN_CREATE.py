import script_test
from collections import OrderedDict
import json
from script_test import Input
from script_test import GenerateAuthToken
import sys
import requests

server = "https://10.106.46.248"

username = "puneesh"
if len(sys.argv) > 1:
    username = sys.argv[1]
password = "cisco"
if len(sys.argv) > 2:
    password = sys.argv[2]

r = None
headers = {'Content-Type': 'application/json'}
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
auth_url = server + api_auth_path
auth_token=GenerateAuthToken(auth_url,headers,username,password).generatetoken()
headers['X-auth-access-token']=auth_token
print(headers)

def make_post(url,headers,data):
    r=None
    try:
        r = requests.post(url, data=json.dumps(data), headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        print("Status code is: "+str(status_code))
        if status_code == 201 or status_code == 202:
            print ("Post was successful..")
        else:
            r.raise_for_status()
            print ("Error occurred in POST --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r: r.close()

def get_tunnel(url,headers):
    r=None
    try:
    # REST call with SSL verification turned off:
        r = requests.get(url, headers=headers, verify=False)
        status_code = r.status_code
        resp = r.text
        if (status_code == 200):
            print("GET successful. Response data --> ")
            json_resp = json.loads(resp)
            print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
        else:
            r.raise_for_status()
            print("Error occurred in GET --> "+resp)
    except requests.exceptions.HTTPError as err:
        print ("Error in connection --> "+str(err))
    finally:
        if r : r.close()


'''server="https://10.106.46.248"
username="puneesh"
password="cisco"
intial_input=Input(server,username,password)
api_auth_path = "/api/fmc_platform/v1/auth/generatetoken"
headers = {'Content-Type': 'application/json'}
auth_url = server + api_auth_path'''



ikev1_post=OrderedDict()
ikev1_post["name"]="APIVPN-IKE7"
ikev1_post["priority"]=20
ikev1_post["lifetimeInSeconds"]=86400
ikev1_post["diffieHellmanGroup"]=5
ikev1_post["authenticationMethod"]="Preshared Key"
ikev1_post["encryption"]="AES-128"
ikev1_post["hash"]="SHA"
ikev1_post["type"]="IKEv1Policy"
ikev1_post["description"]="desc"

ikev1_ipsec_post=OrderedDict()
ikev1_ipsec_post["name"]="APIVPN_IPSEC1"
ikev1_ipsec_post["id"]="ikev1ipsecproposalUUID"
ikev1_ipsec_post["espEncryption"]="3DES"
ikev1_ipsec_post["espHash"]="MD5"
ikev1_ipsec_post["description"]="desc"

tunnel_create_post=OrderedDict()
tunnel_create_post["name"]="APIS2S"
tunnel_create_post["type"]="FTDS2SVpn"
tunnel_create_post["topologyType"]="POINT_TO_POINT"
tunnel_create_post["ikeV1Enabled"]="true"
tunnel_create_post["ikeV2Enabled"]="false"

'''post_data = {
  "name": "APIVPN-IKE4",
  "priority": 20,
  "lifetimeInSeconds": 86400,
  "diffieHellmanGroup": 5,
  "authenticationMethod": "Preshared Key",
  "encryption": "AES-128",
  "hash": "SHA",
  "type": "IKEv1Policy",
  "description": "IKEv1 Policy object description"
}
'''

#list_of_policy.append(ikev1_post)

ike_policy_post_api_path="/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ikev1policies"
ike_policy_url=server+ike_policy_post_api_path

ikev1_ipsec_post_api_path="/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ikev1ipsecproposals"
ikev1_ipsec_policy_url=server+ikev1_ipsec_post_api_path

tunnel_create_api_path="/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftds2svpns"
tunnel_create_url=server+tunnel_create_api_path

tunnel_get_api_path="/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/policy/ftds2svpns"
tunnel_get_url=server+tunnel_get_api_path

#make_post(ike_policy_url,headers,ikev1_post)
#make_post(ikev1_ipsec_policy_url,headers,ikev1_ipsec_post)
#make_post(tunnel_create_url,headers,tunnel_create_post)
get_tunnel(tunnel_get_url,headers)


'''ike_policy_post_api_path='/api/fmc_config/v1/domain/e276abec-e0f2-11e3-8169-6d9ed49b625f/object/ikev1policies'
ike_policy_url=server+ike_policy_post_api_path

r = requests.post(ike_policy_url, data=json.dumps(ikev1_post1), headers=headers)
    status_code = r.status_code
    resp = r.text
    print("Status code is: "+str(status_code))
    if status_code == 201 or status_code == 202:
        print ("Post was successful...")
        json_resp = json.loads(resp)
        print(json.dumps(json_resp,sort_keys=True,indent=4, separators=(',', ': ')))
    else :
        r.raise_for_status()
        print ("Error occurred in POST --> "+resp)
except requests.exceptions.HTTPError as err:
    print ("Error in connection --> "+str(err))
finally:
    if r: r.close()
'''
