import requests
from requests.auth import HTTPBasicAuth
import os
import sys
import json

# Get the absolute path for the directory where this file is located "here"
here = os.path.abspath(os.path.dirname(__file__))

# Get the absolute path for the project / repository root
project_root = os.path.abspath(os.path.join(here, "../.."))

# Extend the system path to include the project root and import the env files
sys.path.insert(0, project_root)

import env_lab

DNAC_URL = env_lab.DNA_CENTER["host"]
DNAC_USER = env_lab.DNA_CENTER["username"]
DNAC_PASS = env_lab.DNA_CENTER["password"]

def get_auth_session(scheme:str='https://', url:str='', api_endpoint:str=''):
    """
    Building out Auth request. Using requests.post to make a call to the Auth Endpoint

    Returns:
    session.headers:requests.structures.CaseInsensitiveDict     - returning a dictionary LIKE object
    headers:dict                                                - changed the session.headers to a dictionary

    """
    if not api_endpoint:
        api_endpoint = "/dna/system/api/v1/auth/token"

    if not url:
        url = f'{scheme}{DNAC_URL}{api_endpoint}'

    hdr = {'content-type' : 'application/json'}                                                         # Define request header
    
    # Instead of using requests, we're going to use session for session management.  Create a session instance.
    session = requests.Session()
    # use the Session.post method, to make the call to get the token
    s_response = session.post(url, auth=HTTPBasicAuth(DNAC_USER, DNAC_PASS), headers=hdr, verify=False)      # Make the POST Request, do not verify certificate
    # The token is in the resonse to the session post.  Update the session headers, to change the authorization to a bearer token.
    session.headers.update({'Authorization': f"Bearer {s_response.json().get('Token')}"})
    # Session headers is a requests.structures.CaseInsensitiveDict .  Change it to a dictionary.
    headers = dict(session.headers)
    # print the dumps, nicely.
                   
    return session.headers, headers    #Return 


if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    # include the token in Authorization header for subsequent requests

    session_headers, headers = get_auth_session()
    msg = "\nGot the token, modified the session headers to:"
    print(f"{msg}\n{'-'*len(msg)}")
    print(json.dumps(headers, indent=2))

    #ima comment
    #another
    #another

    # token = resp.json().get("Token")
