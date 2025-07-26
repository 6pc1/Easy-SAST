import subprocess


# 用于使用codeql去创建ql数据库
def ql_database_create(codeql_path, databas_path, java_project_path):
    print("正在创建CodeQL数据库...")
    try:

        # 打开日志文件
        with open('codeql_database_create.log', 'w') as log_file:
            result = subprocess.run(
                [codeql_path, 'database', 'create', databas_path, '--language=java',
                 '--command=mvn clean install -Dmaven.test.skip=true --file pom.xml', '--source-root',
                 java_project_path, "--overwrite"],
                check=True,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
    except subprocess.CalledProcessError as e:
        print(f"CodeQL数据库创建失败！Error：{e}")
    except Exception as e:
        print("An unknown error occurred" + str(e))
    finally:
        print("数据库创建完成！")


if __name__ == '__main__':
    ql_database_create("./codeql/codeql.exe", "../ql-databases/micro_service_seclab", "../example-project/micro_service_seclab")