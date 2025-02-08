# OLHO-SILENT

**Olho de Silent** é uma ferramenta de análise de vulnerabilidades desenvolvida em Python, projetada para verificar sites em busca de várias falhas de segurança. Quando o usuário insere um link (seja HTTP ou HTTPS), a ferramenta realiza uma série de testes para identificar possíveis vulnerabilidades, como:

1. **SQL Injection**: Testes que tentam injetar comandos SQL maliciosos para verificar se o site é suscetível a ataques que possam comprometer o banco de dados.
2. **Cross-Site Scripting (XSS)**: Verificação de pontos em que scripts maliciosos podem ser injetados e executados no navegador do usuário, permitindo roubo de informações ou controle da conta.
3. **Remote Code Execution (RCE)**: Tentativas de execução remota de comandos para verificar se o site permite a execução de código não autorizado no servidor.

### Funcionalidades:
- **Identificação de Vulnerabilidades**: A ferramenta realiza verificações detalhadas e retorna um relatório das vulnerabilidades encontradas.
- **Estimativa de Recompensa**: Baseado nas vulnerabilidades encontradas, a ferramenta fornece uma estimativa de quanto uma empresa pode pagar pelo reporte dessas falhas de segurança.

### Requisitos:
- **Linguagem de Programação**: Python
- **Dependências**: requests, beautifulsoup4
- **Arquivo de Requisitos**: `requirements.txt` para instalação das dependências necessárias.


