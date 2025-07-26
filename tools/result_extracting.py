import json
import os


def extract_vul(sarif_file, src_path):
    # 读出对应数据
    with open(sarif_file, "r") as f:
        data = json.load(f)

    i = 1

    vul_contents = []
    vul_flows_all = []
    for run in data["runs"]:
        for result in run["results"]:
            vul_content = {}
            vul_content['漏洞类型'] = result['ruleId']
            vul_content['代码起点'] = {"相关文件": result['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                                       "传播参数": result['codeFlows'][0]['threadFlows'][0]['locations'][0]['location']['message']['text'],
                                       "代码行数": result['locations'][0]['physicalLocation']['region']['startLine'],
                                       "代码片段": get_code_snippet(src_path+ "\\" + result['locations'][0]['physicalLocation']['artifactLocation']['uri'],
                                                                    result['locations'][0]['physicalLocation']['region']['startLine'],
                                                                    result['locations'][0]['physicalLocation']['region']['startColumn'],
                                                                    result['locations'][0]['physicalLocation']['region']['endColumn'])
                                       }
            vul_content['代码终点'] = {"相关文件": result['codeFlows'][0]['threadFlows'][0]['locations'][-1]['location']['physicalLocation']['artifactLocation']['uri'],
                                       "传播参数": result['codeFlows'][0]['threadFlows'][0]['locations'][-1]['location']['message']['text'],
                                       "代码行": result['codeFlows'][0]['threadFlows'][0]['locations'][-1]['location']['physicalLocation']['region']['startLine'],
                                       "代码片段": get_code_snippet(src_path + "\\" + result['codeFlows'][0]['threadFlows'][0]['locations'][-1]['location']['physicalLocation']['artifactLocation']['uri'],
                                                                    result['codeFlows'][0]['threadFlows'][0]['locations'][-1]['location']['physicalLocation']['region']['startLine'],
                                                                    0,
                                                                    0)
                                       }
            # print(vul_content)
            vul_contents.append(vul_content)
            vul_flows = []
            for codeFlow in result['codeFlows']:
                for threadFlow in codeFlow['threadFlows']:
                    for location in threadFlow['locations']:
                        vul_flow = {}
                        vul_flow['相关文件'] = location['location']['physicalLocation']['artifactLocation']['uri']
                        vul_flow['传播参数'] = location['location']['message']['text']
                        vul_flow['代码行数'] = location['location']['physicalLocation']['region']['startLine']
                        vul_flow['代码片段'] = get_code_snippet(src_path + "\\" + location['location']['physicalLocation']['artifactLocation']['uri'],
                                                                location['location']['physicalLocation']['region']['startLine'],
                                                                0,
                                                                0)

                        # print(vul_flow)
                        vul_flows.append(vul_flow)
            vul_flows_all.append(vul_flows)
            write_to_file(sarif_file.split('.')[0] + str(i) + "." + sarif_file.split('.')[1], {"vul_content": vul_content, "vul_flows": vul_flows})
            i = i + 1
    # 删除对应的处理前的结果文件
    os.remove(sarif_file)
    return {"vul_contents": vul_contents, "vul_flows": vul_flows_all}



def get_code_snippet(full_file_path, start_line, start_column, end_column):


    try:
        with open(full_file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()

            # 确保行号在有效范围内
            if start_line < 1 or start_line > len(lines):
                raise ValueError(f"Invalid line number: {start_line}")

            # 获取指定行的内容
            target_line = lines[start_line - 1]

            # 如果传入的start_column和end_column都为0，则返回整行
            if start_column == 0 and end_column ==0:
                return target_line

            # 确保列号在有效范围内
            if start_column < 1 or start_column > len(target_line) or end_column < start_column or end_column > len(
                    target_line):
                raise ValueError(f"Invalid column range: {start_column}-{end_column}")

            # 获取指定列范围内的代码片段
            code_snippet = target_line[start_column - 1:end_column].strip()

            return code_snippet
    except FileNotFoundError:
        raise FileNotFoundError(f"File not found: {full_file_path}")
    except Exception as e:
        raise e

def write_to_file(sarif_file, data):
    vul_content = data['vul_content']
    vul_flows = data['vul_flows']

    file_path = sarif_file.replace("sarif", "txt")
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write("漏洞类型:" + vul_content['漏洞类型'])
        file.write("\n\n")
        file.write("代码起点:\n\n")

        lines = [f"{key}: {value}" for key, value in vul_content['代码起点'].items()]
        for line in lines:
            file.write(line)
            file.write("\n")
        file.write("\n")


        file.write("\n\n")
        file.write("代码终点:\n\n")

        lines = [f"{key}: {value}" for key, value in vul_content['代码终点'].items()]
        for line in lines:
            file.write(line)
            file.write("\n")
        file.write("\n")

        file.write("\n")
        file.write("完整链路:\n\n")
        for vul_flow in vul_flows:
            lines = [f"{key}: {value}" for key, value in vul_flow.items()]
            for line in lines:
                file.write(line)
                file.write("\n")
            file.write("\n\n")
    print("扫描完成。结果已保存至：" + file_path)