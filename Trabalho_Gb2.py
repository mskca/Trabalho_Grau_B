from ast import While
from asyncio.windows_events import NULL
from logging import exception
from operator import ne
from pickle import TRUE
import requests
import json 
import os
import time

#REFER:https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator

#Criar Variveis Globais e zeradas
cvss_vector = NULL
cve_dados = NULL
#Criar Variaveis Temporal Score Metrics 
E = NULL
RL = NULL
RC = NULL
#Criar Variaveis Environmental Score Metrics
CDP = NULL
TD = NULL
CR = NULL
IR = NULL
AR = NULL
#Carrega variaveis para calculo: 
AccessVector = NULL
AccessComplexity = NULL
Authentication = NULL
ConfidentialityImpact = NULL
IntegrityImpact = NULL
AvailabilityImpact = NULL

#Carregar e Validar Dados Temporais de Ambiente


#Carrega Dados + Tratamento de Entrada
dd = 0
while dd == 0:
    os.system('cls') or None
    cve_code = input ("Insira Corretamente CVE, ex:CVE-2021-34527:  \n") 
    try:
        URL_Master="https://cve.circl.lu/api/cve/"
        print ('Carregando dados de', URL_Master + cve_code, '\n ------------------\n ')
        requestCVE = requests.get(URL_Master + cve_code, verify=False)
        cve_dados = json.loads(requestCVE.content)
        #Valida se dados não estão nulos
        if cve_dados.get('summary') != NULL:
            dd = 1
            print ('Dados Carregados Corretamente...')
        requestCVE.raise_for_status()
    except Exception as e:
        print ('ERRO: \n' , e)

          
def Exc_Falta_Dados(Val, fun):
    if Val != NULL:
        print ('dados nulos')
    else:
        print ('Informado Dados Errados, valor inforamdo: \n', fun, ': ' , Val )
    exit()

def Calcula_CVSS():
    #separa cvss_vector e transformar em lista
    cvss_vector = cve_dados.get('cvss-vector')
    cvss_vector = (cvss_vector.split('/'))
    cvss_calc= 0;
           
    #Calcula Access Vector 
    if cvss_vector[0] in "AV:N":
        AccessVector = 1.0
    elif  cvss_vector[0] in 'AV:A':
        AccessVector = 0.646
    elif  cvss_vector[0] in 'AV:L':
        AccessVector = 0.395
    else:
        Exc_Falta_Dados(cvss_vector[0],'AccessVector')
    
    #Calcula Access Complexity
    if cvss_vector[1] in 'AC:H':
        AccessComplexity = 0.35
    elif  cvss_vector[1] in 'AC:M':
        AccessComplexity = 0.61
    elif  cvss_vector[1] in 'AC:L':
        AccessComplexity = 0.71
    else:
        Exc_Falta_Dados(cvss_vector[0],'AccessComplexity')
    
    #Calcula Authentication  
    if cvss_vector[2] in 'Au:M':
        Authentication = 0.45
    elif cvss_vector[2] in 'Au:S':
        Authentication = 0.56
    elif  cvss_vector[2] in 'Au:N':
        Authentication = 0.704
    else:
        Exc_Falta_Dados(cvss_vector[0],'Authentication')
        
    #Calcula ConfidentialityImpact 
    if cvss_vector[3] in 'C:N':
        ConfidentialityImpact = 0
    elif  cvss_vector[3] in 'C:P':
        ConfidentialityImpact = 0.275
    elif  cvss_vector[3] in 'C:C':
        ConfidentialityImpact = 0.66
    else:
        Exc_Falta_Dados(cvss_vector[0],'ConfidentialityImpact')
        
    #Calcula ConfidentialityImpact 
    if cvss_vector[4] in 'I:N':
        IntegrityImpact = 0
    elif  cvss_vector[4] in 'I:P':
        IntegrityImpact = 0.275
    elif  cvss_vector[4] in 'I:C':
        IntegrityImpact = 0.66
    else:
        Exc_Falta_Dados(cvss_vector[0],'IntegrityImpact')
        
    #Calcula AvailabilityImpact 
    if cvss_vector[5] in 'A:N':
        AvailabilityImpact = 0
    elif  cvss_vector[5] in 'A:P':
        AvailabilityImpact = 0.275
    elif  cvss_vector[5] in 'A:C':
        AvailabilityImpact = 0.66
    else:
        Exc_Falta_Dados(cvss_vector[0],'AvailabilityImpact')

    #Calculo de CVSS2.0
    Impact = 10.41*(1-(1-ConfidentialityImpact)*(1-IntegrityImpact)*(1-AvailabilityImpact))
    Exploitability = 20*AccessVector*AccessComplexity*Authentication
    
    #Limitar Casas Decimais
    Impact = round (Impact, 1)
    Exploitability = round (Exploitability, 1)
    
    #Calculo de CVSS2.0
    if Impact != 0:
        f_impact = 1.176
    BaseScore = ((0.6*Impact)+(0.4*Exploitability)-1.5)*f_impact
    BaseScore = round (BaseScore, 1)
    
    
    
    #Imprime dados
    print ('\n -------------------------------------------- \n')
    print ('Dados', cve_code, ': \n')
    print (json.dumps(cve_dados, indent=4, sort_keys=TRUE))
    print ('\n -------------------------------------------- \n')
    print ('Base Scores: \n')
    print ('Base: ', BaseScore)
    print ('Impacto: ', Impact)
    print ('Explorabilidade: ', Exploitability)
    print ('\n -------------------------------------------- \n')
    print ('Temporal Scores: \n')
    print ('\n -------------------------------------------- \n')
    print ('Environmental: \n')
    print ('\n -------------------------------------------- \n')
    print ('Overall: \n')
    print ('\n -------------------------------------------- \n')
    
if __name__ == '__main__':
    Calcula_CVSS()
    time.sleep(120)
    
