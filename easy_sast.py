import argparse
import glob
import os
from ast import parse

from salt.modules.libcloud_dns import extra
from tqdm import tqdm

from tools.codeql_query import codeql_query
from tools.delombok import delombok
from tools.ql_database_create import ql_database_create
from tools.result_extracting import extract_vul

bannerText = """
███████╗ █████╗ ███████╗██╗   ██╗███████╗██████╗  █████╗ ███████╗████████╗
██╔════╝██╔══██╗██╔════╝╚██╗ ██╔╝██╔════╝██╔══██╗██╔══██╗██╔════╝╚══██╔══╝
█████╗  ███████║███████╗ ╚████╔╝ █████╗  ██████╔╝███████║███████╗   ██║   
██╔══╝  ██╔══██║╚════██║  ╚██╔╝  ██╔══╝  ██╔══██╗██╔══██║╚════██║   ██║   
███████╗██║  ██║███████║   ██║   ███████╗██║  ██║██║  ██║███████║   ██║   
╚══════╝╚═╝  ╚═╝╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝   ╚═╝   

design by 6pc1
    """


if __name__ == '__main__':
    current_path = os.getcwd()


    print(bannerText)

    paser = argparse.ArgumentParser()
    paser.add_argument("-c", "--codeql_path", help="codeql executable path", default=f"{current_path}\\tools\\codeql\\codeql.exe")
    paser.add_argument("-i", "--input_project_path", help="input project path", default=f"{current_path}\\example-project\\micro_service_seclab")
    paser.add_argument("-d", "--database_path", help="database file path", default=f"{current_path}\\ql-databases\\micro_service_seclab")
    paser.add_argument("-q", "--query_path", help="ql query. scan all .ql in path.", default=f"{current_path}\\ql-query\\")

    args = paser.parse_args()
    codeql_path = args.codeql_path
    input_project_path = args.input_project_path
    database_path = args.database_path
    query_path = args.query_path
    project_name = os.path.basename(input_project_path)

    # 进行delombok
    # delombok(input_project_path)
    # 构建codeql数据库
    ql_database_create(codeql_path, database_path, input_project_path)

    # 执行codeql扫描，使用的是整个文件夹底下的规则
    ql_files = glob.glob(os.path.join(query_path, "*.ql"))

    # 使用tqdm 包装 for 循环从而显示进度条
    for file in tqdm(ql_files, desc="Processing queries", unit="file"):

        file_name = os.path.basename(file)

        os.makedirs(f"{current_path}\\result\\{project_name}", exist_ok=True)
        result_file = f"{current_path}\\result\\{project_name}\\{file_name.split('.')[0]}.sarif"

        query_file = os.path.join(query_path, file_name)

        codeql_query(codeql_path, database_path, result_file, query_file)

        # 对结果进行保存
        extract_vul(result_file, input_project_path)
