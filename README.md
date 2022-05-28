# Trabalho_Grau_B

Instalação de Dependencias:
#pip install requests

Url Codigo consulta:
https://www.circl.lu/services/cve-search/

Definição do Trabalho: 
Data de entrega: 10/06/2022 - Aula 16, até as 19h30 pelo Moodle.

Data da apresentação: 10/06/2022 - Aula 16, até as 19h30.

Itens a serem entregues: código-fonte da implementação, vídeo demonstrativo e relatório.
• O código-fonte não entregue acarretará em um desconto de 50% sobre a nota do trabalho.
• O vídeo não entregue acarretará em um desconto de 25% sobre a nota do trabalho.
• O vídeo deve ter uma duração máxima de 5 minutos.
• O relatório não entegue acarretará em um desconto de 25% sobre a nota do trabalho.
• O relatório deve conter, no mínimo, 2 páginas completas.

Peso do trabalho: 3,0.

A CVE (Common Vulnerabilities and Exposures), disponível em https://cve.mitre.org/, é uma lista de entradas (cada 
uma contendo um número de identificação e uma descrição) para vulnerabilidades de segurança publicamente
conhecidas. Já a CVSS (Common Vulnerability Scoring System), cujo endereço do site é https://www.first.org/cvss/,
fornece uma maneira de capturar as principais características de uma vulnerabilidade e produzir uma pontuação 
numérica que reflete a sua gravidade. A pontuação numérica pode ser convertida em uma representação qualitativa 
(por exemplo, baixa, média, alta e crítica) para ajudar as organizações a avaliar e priorizar adequadamente os seus 
processos de gerenciamento de vulnerabilidades. O cálculo da pontuação de uma vulnerabilidade considera três 
tipos de métricas: básicas, temporais e ambientais. A maioria das ferramentas de descoberta de vulnerabilidades 
informam a pontuação CVSS para as vulnerabilidades encontradas; algumas informam a pontuação considerando 
métricas básicas e temporais, enquanto outras focam apenas em métricas básicas.
Neste contexto, a aplicação a ser desenvolvida consiste em mostrar na tela todas as informações disponíveis para 
uma CVE digitada pelo usuário. O programa deve utilizar uma API disponível para pegar as informações da 
vulnerabilidade solicitada. Neste sentido, pode-se utilizar a API circl.lu (https://www.circl.lu/services/cve-search/). 
Por exemplo, caso o usuário tenha digitado a vulnerabidade identificada pela CVE-2021-34527, o programa deve 
realizar uma consulta na API (exemplo de consulta: curl https://cve.circl.lu/api/cve/CVE-2021-
34527), parsear as informações recebidas e mostrar na tela as informações de forma estruturada.
Além disso, o programa deve permitir calcular a pontuação de uma vulnerabilidade utilizando as métricas temporais 
e ambientais. Caso a pontuação não esteja disponível, o grupo deve selecionar uma das duas opções a seguir. 
Primeiro, o programa pode permitir que o usuário especifique um arquivo (JSON, XML ou HTML) gerado por uma
ferramenta de descoberta de vulnerabilidades para o host em que a vulnerabilidade está presente. Arquivos de 
exemplo (gerados pela ferramenta Nessus) estão disponíveis na comunidade do Moodle da atividade acadêmica e 
podem ser utilizados para o desenvolvimento do trabalho. Segundo, o programa pode solicitar que o usuário 
informe os valores das métricas faltantes e calcular a pontuação. Neste caso, o grupo pode estudar a especificação 
da CVSS (disponível em https://www.first.org/cvss/v3.1/specification-document) para realizar o cálculo ou utilizar 
uma biblioteca auxiliar que realize o cálculo automaticamente.
A implementação pode ser feita na linguagem de programação de preferência do grupo e deve seguir as boas 
práticas para a geração de um código-fonte seguro. Por isso, o grupo deve (i) seguir os conceitos estudados ao longo 
do semestre na atividade acadêmica (por exemplo, validando todas as entradas do programa); e (ii) pesquisar por 
fraquezas de código-fonte (Common Weakness Enumeration – CWE), disponíveis em https://cwe.mitre.org/, estudálas e aplicar os ensinamentos no código desenvolvido.

Por fim, o grupo deve escrever um relatório explicando (i) quais CWEs foram pesquisadas e como elas ajudaram a 
aumentar a segurança do código-fonte; e (ii) como usar o software desenvolvido. O relatório deve ser escrito em 
latex e utilizar o template para artigos da SBC (disponível em https://www.sbc.org.br/documentos-dasbc/category/169-templates-para-artigos-e-capitulos-de-livros). Sugere-se o uso de uma ferramenta colaborativa de 
edição de texto em latex (tal como o Overleaf - https://www.overleaf.com/).
Observações:
• Podem ser utilizadas bibliotecas auxiliares para o cálculo da pontuação CVSS, incluindo:
o CVSSlib, disponível em https://github.com/ctxis/cvsslib;
o CVSS-NPM, disponível em https://www.npmjs.com/package/cvss.
• Também pode-se utilizar outras APIs para adquirir informações sobre CVEs, incluindo:
o NVD data feeds, disponível em https://nvd.nist.gov/vuln/data-feeds;
o pyvfeed, disponível em https://github.com/vfeedio/pyvfeed;
o cve-search, disponível em https://github.com/cve-search/cve-search e https://www.cvesearch.org/api/.

Tutotial de como instalar o git e configurar no vs 
https://www.geeksforgeeks.org/how-to-install-git-in-vs-code/#:~:text=Installing%20Git%20in%20Visual%20Studio%20Step%201%3A%20Download,git%20in%20your%20system%20using%20the%20official%20website.
