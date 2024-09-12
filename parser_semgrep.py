import os
import json
import pandas as pd
import argparse
from datetime import datetime

def clean_text(value):
    # Função para remover colchetes "[" e "]"
    return str(value).replace('[', '').replace(']', '').replace('"', '').replace("'", '').replace('`','').strip()

def json_to_xlsx(input_json):
    # Obter o nome da fonte do caminho do arquivo de entrada
    source_name = os.path.splitext(os.path.basename(input_json))[0]

    # Obter a data atual
    current_date = datetime.now().strftime('%Y-%m-%d')

    # Carregar o arquivo JSON
    with open(input_json, 'r') as json_file:
        data = json.load(json_file)

    # Verificar se há resultados no campo "results"
    results = data.get('results', [])

    if not results:
        print("[INFO] O SCAN SAST NÃO DETECTOU VULNERABILIDADES.")
        return

    # Converter para DataFrame do pandas
    df = pd.json_normalize(results)

    # Sanitizar caracteres indesejados nas colunas de texto, usando a função de limpeza
    text_columns = [
        'extra.metadata.vulnerability_class',
        'extra.message',
        'extra.metadata.semgrep.dev.rule.url',
        'path'
    ]

    for col in text_columns:
        df[col] = df[col].apply(clean_text)

    # Selecionar todas as colunas desejadas
    selected_columns = [
        'extra.metadata.vulnerability_class',
        'extra.metadata.cwe',
        'extra.metadata.impact',
        'extra.message',
        'extra.metadata.semgrep.dev.rule.url',
        'path',
        'end.line',
        'extra.metadata.owasp',
        'extra.metadata.references',
        'extra.lines'
    ]

    df[selected_columns] = df[selected_columns].applymap(clean_text)

    # Renomear as colunas
    column_mapping = {
        '': 'Repository',
        'source': 'Source',
        'extra.metadata.vulnerability_class': 'Vulnerability Class',
        'date': 'Date',
        'extra.metadata.cwe': 'CWE',
        '': 'CVE',
        '': 'URL',
        'extra.metadata.impact': 'Severity',
        'extra.message': 'Description',
        '': 'Solution',
        'extra.metadata.semgrep.dev.rule.url': 'References',
        'path': 'File Path',
        'end.line': 'Lines',
        'extra.lines': 'Code',
        'extra.metadata.owasp': 'OWASP',
        'extra.metadata.references': 'OWASP References'
    }

    df = df.rename(columns=column_mapping)

    df['Repository'] = source_name
    df['Source'] = 'SAST'
    df['Date'] = current_date
    df['CVE'] = ''
    df['URL'] = ''
    df['Solution'] = ''

    # Reorganizar as colunas na ordem desejada
    ordered_columns = [
        'Repository',
        'Source',
        'Vulnerability Class',
        'Date',
        'CWE',
        'CVE',
        'URL',
        'Severity',
        'Description',
        'Solution',
        'References',
        'File Path',
        'Lines',
        'Code',
        'OWASP',
        'OWASP References'
    ]

    df = df[ordered_columns]

    # Remover quebras de linha da coluna 'Code'
    df['Code'] = df['Code'].replace('\n', ' ', regex=True)

    # Gerar automaticamente o nome do arquivo de saída com base no nome do arquivo de entrada
    output_xlsx = f"{source_name}.xlsx"

    # Salvar DataFrame como XLSX
    df.to_excel(output_xlsx, index=False)

    print("[INFO] DADOS DO SCAN SAST EXTRAIDOS COM SUCESSO!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Convert Semgrep JSON to XLSX")
    parser.add_argument("input_json", help="Path to the input Semgrep JSON file")

    args = parser.parse_args()

    json_to_xlsx(args.input_json)
