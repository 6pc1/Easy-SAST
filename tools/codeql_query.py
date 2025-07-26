import subprocess


def codeql_query(codeql_path, database_path, result_path, query_path):
    print("正在进行CodeQL扫描.....")
    subprocess.run(
        [codeql_path, 'database', 'analyze', database_path, query_path, '--format=sarif-latest', f'--output={result_path}'],
        check=True
    )




if __name__ == '__main__':
    codeql_query("./codeql/codeql.exe", "../ql-databases/micro_service_seclab", "../result/micro_service_seclab/sql.sarif", "../ql-query/sql.ql")