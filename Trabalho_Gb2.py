from ast import For, While
from asyncio.windows_events import NULL
from logging import exception
from operator import ne
from pickle import FALSE, TRUE
import requests
import json 
import os
import time

#REFER:https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator

#Criar Variveis com valor nulo
cvss_vector = NULL
cve_dados = NULL
E = NULL
RL = NULL
RC = NULL
CDP = NULL
TD = NULL
CR = NULL
IR = NULL
AR = NULL
AccessVector = NULL
AccessComplexity = NULL
Authentication = NULL
ConfidentialityImpact = NULL
IntegrityImpact = NULL
AvailabilityImpact = NULL
Vect_Temp = NULL 
Vect_Amb = NULL 

#Carregar e Validar Dados Temporais de Ambiente

def InsereDadosManual ():
    #Insere Dados Temporais
    intv = 0
    while intv == 0:
        Inputvect = input ('Deseja Listar Vectores Temporais? (S)SIM / (N)NAO \n')
        if Inputvect == 'S':
            intv = 1
            Vect_Temp = TRUE
            
            E = input ('Insira Nivel de Explorabilidade: (ND) Not Defined / (U) Unproven that Expliot exists / (POC) Proof of concept code / (F) Functional exploit exists / (H) High\n' )
            while E not in  ['ND,' ,'U', 'POC', 'F', 'H']:
                E = input ('Insira Nivel de Explorabilidade: (ND) Not Defined / (U) Unproven that Expliot exists / (POC) Proof of concept code / (F) Functional exploit exists / (H) High\n' )
            
            RL = input ('Insira Nivel de Remediação: (ND) Not Defined / (OF)Official Fix / (TF) Temporarary Fix / (W) Workaround / (U) Unavailable \n')
            while RL not in ['ND,' ,'OF', 'TF', 'W', 'U']:
                RL = input ('Insira Nivel de Remediação: (ND) Not Defined / (OF)Official Fix / (TF) Temporarary Fix / (W) Workaround / (U) Unavailable \n')

            RC = input ('Insira Nivel de Report: (ND) Not Defined / (UC) Unconfirmed / (UR) Uncorroborated / (C) Confirmed \n')
            while RC not in ['ND,' ,'UC', 'C', 'UR']:   
                RC = input ('Insira Nivel de Report: (ND) Not Defined / (UC) Unconfirmed / (UR) Uncorroborated / (C) Confirmed \n')

        elif Inputvect == 'N':
            intv = 1
            Vect_Temp = FALSE
        else:
            intv = 0
    
    #Insere Dados Ambientais 
    intv = 0
    while intv == 0:
        Inputvect = input ('Deseja Listar Vectores Ambientais? (S)SIM / (N)NAO \n')
        if Inputvect == 'S':
            intv = 1
            Vect_Amb = TRUE
            print ("Insira Corremente os dados Ambientais: \n")
            CDP = input ('Insira Nivel de Collateral Damage Potential: (ND) Not Defined / (N) None / (L) Low-light loss / (LM) Low-Medium / (MH) Medium-High / (H) High-Catastraphic loss\n' )
            while CDP not in  ['ND,', 'N' ,'L', 'LM', 'MH', 'H']:
                CDP = input ('Insira Nivel de Collateral Damage Potential: (ND) Not Defined / (N) None / (L) Low-light loss / (LM) Low-Medium / (MH) Medium-High / (H) High-Catastraphic loss\n' )
            
            CR = input ('Insira Nivel de Confidentiality Requirement : (ND) Not Defined / (N)None [0%] /  (L) Low [0-25%] / (M) Medium [26-75%] / (H) Hgh [76-100%] \n')
            while CR not in   ['ND,' ,'N', 'L', 'M', 'H']:
                CR = input ('Insira Nivel de Confidentiality Requirement : (ND) Not Defined / (N)None [0%] /  (L) Low [0-25%] / (M) Medium [26-75%] / (H) Hgh [76-100%] \n')
            
            TD = input ('Insira Nivel de Remediação: (ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n')
            while TD  not in   ['ND,' ,'L', 'M', 'H']:
                TD = input ('Insira Nivel de Remediação: (ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n')
            
            IR = input ('Insira Nivel de Integrity Requirement:(ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n') 
            while IR not in   ['ND,' ,'L', 'M', 'H']:
                IR = input ('Insira Nivel de Integrity Requirement:(ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n')  
            
            AR = input ('Insira Nivel de Availability Requirement: (ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n')
            while AR not in  ['ND,' ,'L', 'M', 'H']:
                AR = input ('Insira Nivel de Availability Requirement: (ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n')       
                                      
        elif Inputvect == 'N':
            intv = 1
            Vect_Amb = FALSE
        else:
            intv = 0
          
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
    if fun == 'temp' and Vect_Temp == TRUE:
        print ("Metricas Temporais Incompletas ... ")
        InsereDadosManual ()
    elif fun == 'amb' and Vect_Amb == TRUE:
        print ('Dados Ambientais Incompletos .... ')
        InsereDadosManual ()
    elif Val != NULL:
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
    
    #Calculo de CVSS Temporal  

    #Exploitability Temporal 
    if E == 'ND':
        Exploitability_level = 1
    elif E == 'H':
        Exploitability_level = 1
    elif E == 'F':
        Exploitability_level = 0.95
    elif E == 'POC':
        Exploitability_level = 0.9
    elif E == 'U':
        Exploitability_level = 0.85
    elif Vect_Temp == False:
        print ('Exploitability Temporal: Informação Nula')
    else:
        Exc_Falta_Dados(0,'temp')
        
    #RemediationLevel Temporal 
    if RL == 'ND':
        RemediationLevel = 1
    elif RL == 'U': 
        RemediationLevel = 1
    elif RL == 'W':
        RemediationLevel = 0.95
    elif RL == 'TF':
        RemediationLevel = 0.90
    elif RL == 'OF':
        RemediationLevel = 0.87
    elif Vect_Temp == False:
        print ('RemediationLevel Temporal: Informação Nula')
    else:
        Exc_Falta_Dados(0,'temp')
    
    #ReportConfidence Temporal 
    if RC == 'ND':
        ReportConfidence = 1
    elif RC == 'C':
        ReportConfidence = 1
    elif RC == 'UR':
        ReportConfidence = 0.95
    elif RC == 'UC':
        ReportConfidence = 0.90
    elif Vect_Temp == False:
        print ('ReportConfidence Temporal: Informação Nula')
    else:
        Exc_Falta_Dados(0,'temp')
    
    #Calculo de CVSS Ambiente  

    
    #Calculo de Temporal Score
    TemporalScore = NULL
    #TemporalScore = BaseScore*Exploitability_level*RemediationLevel*ReportConfidence
    
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
    print ('Temporal Scores:' , TemporalScore ,'\n')
    print ('\n -------------------------------------------- \n')
    print ('Environmental: \n')
    print ('\n -------------------------------------------- \n')
    print ('Overall: \n')
    print ('\n -------------------------------------------- \n')
    
if __name__ == '__main__':
    InsereDadosManual ()
    Calcula_CVSS()
    time.sleep(120)
    
