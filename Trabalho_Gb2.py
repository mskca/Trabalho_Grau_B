import requests
import json 

URL_Master="http://cve.circl.lu/api/"

def BuscaCVE ():
    cve_code = input ("Digite CVE: \n") 
    requestCVE = requests.get(URL_Master + "/cve/" + cve_code)
    cve_dados = json.loads(requestCVE.content)
    print(cve_dados)

if __name__ == '__main__':
    BuscaCVE()

