import requests
import json 

URL_Master="http://cve.circl.lu/api/"

cvss_vector = ""

def BuscaCVE ():
    #cve_code = input ("Digite CVE: \n") 
    cve_code = 'CVE-2021-34527'
    requestCVE = requests.get(URL_Master + "/cve/" + cve_code)
    cve_dados = json.loads(requestCVE.content)
    #separa cvss_vector e transformar em lista
    cvss_vector = cve_dados.get('cvss-vector')
    cvss_vector = (cvss_vector.split('/'))
    #print (cvss_vector[0])
    if 'N' in cvss_vector[0]:
        print ('AV VECTOR IS NETWORK')

if __name__ == '__main__':
    BuscaCVE()
