from ast import For, While
from asyncio.windows_events import NULL
from logging import exception
from operator import ne
from pickle import FALSE, TRUE
from cvsslib import cvss2, calculate_vector
import requests
import json 
import os
import time
import re

#REFER:https://nvd.nist.gov/vuln-metrics/cvss/v2-calculator

#Criar Variveis com valor nulo 
cvss_vector = NULL
cve_dados = NULL
#Valores padrao para not defined
E = "H"
RL = "U"
RC = "C"
CDP = "N"
TD = "H"
CR = "M"
IR = "M"
AR = "M"
#Valores padrao para not defined - END
AccessVector = "NULL"
AccessComplexity = "NULL"
Authentication = "NULL"
ConfidentialityImpact = "NULL"
IntegrityImpact = "NULL"
AvailabilityImpact = "NULL"
Vect_Temp = NULL 
Vect_Amb = NULL 

#Carregar e Validar Dados Temporais de Ambiente

def InsereDadosManual ():
    #Insere Dados Temporais
    intv = 0
    while intv == 0:
        Inputvect = input ('Deseja Listar Vectores Temporais? (S)SIM / (N)NAO \n')
        global E, RL, RC
        if Inputvect == 'S':
            intv = 1
            Vect_Temp = TRUE
            
            E = input ('Insira Nivel de Explorabilidade: (ND) Not Defined / (U) Unproven that Expliot exists / (POC) Proof of concept code / (F) Functional exploit exists / (H) High\n' )
            while E not in  ['ND' ,'U', 'POC', 'F', 'H']:
                E = input ('Insira Nivel de Explorabilidade: (ND) Not Defined / (U) Unproven that Expliot exists / (POC) Proof of concept code / (F) Functional exploit exists / (H) High\n' )
            
            RL = input ('Insira Nivel de Remediação: (ND) Not Defined / (OF)Official Fix / (TF) Temporarary Fix / (W) Workaround / (U) Unavailable \n')
            while RL not in ['ND' ,'OF', 'TF', 'W', 'U']:
                RL = input ('Insira Nivel de Remediação: (ND) Not Defined / (OF)Official Fix / (TF) Temporarary Fix / (W) Workaround / (U) Unavailable \n')

            RC = input ('Insira Nivel de Report: (ND) Not Defined / (UC) Unconfirmed / (UR) Uncorroborated / (C) Confirmed \n')
            while RC not in ['ND' ,'UC', 'C', 'UR']:   
                RC = input ('Insira Nivel de Report: (ND) Not Defined / (UC) Unconfirmed / (UR) Uncorroborated / (C) Confirmed \n')

        elif Inputvect == 'N':
            intv = 1
            Vect_Temp = FALSE
        else:
            print("Entrada Invalida!")
            time.sleep(2)
            intv = 0
    
    #Insere Dados Ambientais 
    intv = 0
    while intv == 0:
        Inputvect = input ('Deseja Listar Vectores Ambientais? (S)SIM / (N)NAO \n')
        global CDP, CR, TD, IR, AR
        if Inputvect == 'S':
            intv = 1
            Vect_Amb = TRUE
            print ("Insira Corremente os dados Ambientais: \n")
            CDP = input ('Insira Nivel de Collateral Damage Potential: (ND) Not Defined / (N) None / (L) Low-light loss / (LM) Low-Medium / (MH) Medium-High / (H) High-Catastraphic loss\n' )
            while CDP not in  ['ND', 'N' ,'L', 'LM', 'MH', 'H']:
                CDP = input ('Insira Nivel de Collateral Damage Potential: (ND) Not Defined / (N) None / (L) Low-light loss / (LM) Low-Medium / (MH) Medium-High / (H) High-Catastraphic loss\n' )
            
            CR = input ('Insira Nivel de Confidentiality Requirement : (ND) Not Defined / (N)None [0%] /  (L) Low [0-25%] / (M) Medium [26-75%] / (H) Hgh [76-100%] \n')
            while CR not in   ['ND' ,'N', 'L', 'M', 'H']:
                CR = input ('Insira Nivel de Confidentiality Requirement : (ND) Not Defined / (N)None [0%] /  (L) Low [0-25%] / (M) Medium [26-75%] / (H) Hgh [76-100%] \n')
            
            TD = input ('Insira Nivel de Remediação: (ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n')
            while TD  not in   ['ND' ,'L', 'M', 'H']:
                TD = input ('Insira Nivel de Remediação: (ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n')
            
            IR = input ('Insira Nivel de Integrity Requirement:(ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n') 
            while IR not in   ['ND' ,'L', 'M', 'H']:
                IR = input ('Insira Nivel de Integrity Requirement:(ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n')  
            
            AR = input ('Insira Nivel de Availability Requirement: (ND) Not Defined /  (L) Low / (M) Medium  / (H) Hgh  \n')
            AirrrR = AR
            while AR not in  ['ND' ,'L', 'M', 'H']:
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
    
    # Regex para validar entrada do CVE
    if re.match("CVE-[0-9]{4}-[0-9]{4,5}", cve_code):
 
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
    else:
        print("Entrada invalida")
        time.sleep(2)
      
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
        print ('Informado Dados Errados, valor informado: \n', fun, ': ' , Val )
    exit()

def Calcula_CVSS():
    
    cvss_vector = cve_dados.get('cvss-vector')
    cvss_vector = (cvss_vector.split('/'))
    
    cve_resumo = cve_dados.get('summary')
    cve_publicadoEm = cve_dados.get('Published')
    cve_modificadoEm = cve_dados.get('Modified')
    cve_referencias = cve_dados.get('references')
    cve_produtosAfetados = cve_dados.get('vulnerable_product')
    
    #Define valores do basescore
    AccessVector = cvss_vector[0]
    AccessComplexity = cvss_vector[1]
    Authentication = cvss_vector[2]
    ConfidentialityImpact = cvss_vector[3]
    IntegrityImpact = cvss_vector[4]
    AvailabilityImpact = cvss_vector[5]
    
    #Gera vector para calculo automatico do cvss2
    vector_v2 = AccessVector+"/"+AccessComplexity+"/"+Authentication+"/"+ConfidentialityImpact+"/"+IntegrityImpact+"/"+AvailabilityImpact+"/E:"+E+"/RL:"+RL+"/RC:"+RC+"/CDP:"+CDP+"/TD:"+TD+"/CR:"+CR+"/IR:"+IR+"/AR:"+AR
    calculo_valores = calculate_vector(vector_v2, cvss2)
    
    BaseScore = calculo_valores[0]
    TemporalScore = calculo_valores[1]
    EnviromentalScore = calculo_valores[2]
    
    #Imprime dados // fazendo parse do json
    print ('\n -------------------------------------------- \n')
    print ('Dados', cve_code, ': \n')
    print ('Resumo: ', cve_resumo)
    print ('Publicado em: ', cve_publicadoEm)
    print ('Modificado em: ', cve_modificadoEm)
    print ('\n -------------------------------------------- \n')
    print ('Base Scores: \n')
    print ('Base: ', BaseScore)
    print ('\n -------------------------------------------- \n')
    print ('Temporal Scores:' , TemporalScore ,'\n')
    print ('\n -------------------------------------------- \n')
    print ('Environmental:', EnviromentalScore,'\n')
    print ('\n -------------------------------------------- \n')
    print ('Referencias: ')
    for referencia in cve_referencias: 
        print(referencia,';')
    print ('\n -------------------------------------------- \n')
    print('Produtos Afetados: \n')
    for produto in cve_produtosAfetados:
        print(produto,';')
    print ('\n -------------------------------------------- \n')

if __name__ == '__main__':
    InsereDadosManual ()
    Calcula_CVSS()
    time.sleep(120)
