# EasySAST

​	本项目主要是想要去借助codeQL实现一个简单的白盒扫描器，能够自动化对一个项目进行白盒扫描，最后以漏洞调用链的形式详细打印出对应的污点传播路径。

# 项目介绍

项目的结构如下图所示

```

├─example-project
│  └─micro_service_seclab 一个java项目的测试用例
├─ql-databases  存放ql数据库的
│  └─micro_service_seclab 一个java项目的测试用例
├─ql-query ql查询语句存放，扫描时会调用其中所有的ql扫描规则
│  └─sql.ql  sql注入扫描规则
│  └─xxe.ql  xxe扫描规则
│  └─ssrf.ql ssrf扫描规则
│  └─exec.ql 命令执行扫描规则
│  └─fastjson fastjson扫描规则
├─result  输出结果目录
├─tools
│  └─delombok.py 解lombok
│  └─codeql_query.py 调用查询语句
│  └─ql_database_create.py codeql数据库构建
│  └─result_extracting.py 从sarif中提取有用信息并打印
│
├─easy_sast.py 项目主程序

```

如果需要查看对应的效果，直接运行easy_sast.py即可

![image-20250726155219086](C:/Users/ASUS/AppData/Roaming/Typora/typora-user-images/image-20250726155219086.png)

然后就可以看到已经在不停的扫描了，且会将结果保存，可以看看结果

```
漏洞类型:java/vul/execql

代码起点:

相关文件: src/main/java/com/l4yn3/microserviceseclab/controller/RceController.java
传播参数: command : String
代码行数: 24
代码片段: @RequestParam(value = "command") String command)



代码终点:

相关文件: src/main/java/com/l4yn3/microserviceseclab/controller/RceController.java
传播参数: commands
代码行: 29
代码片段:         ProcessBuilder processBuilder = new ProcessBuilder(commands);



完整链路:

相关文件: src/main/java/com/l4yn3/microserviceseclab/controller/RceController.java
传播参数: command : String
代码行数: 24
代码片段:     public StringBuffer One(@RequestParam(value = "command") String command) {



相关文件: src/main/java/com/l4yn3/microserviceseclab/controller/RceController.java
传播参数: command : String
代码行数: 27
代码片段:         commands.add(command);



相关文件: src/main/java/com/l4yn3/microserviceseclab/controller/RceController.java
传播参数: commands [post update] : ArrayList [<element>] : String
代码行数: 27
代码片段:         commands.add(command);



相关文件: src/main/java/com/l4yn3/microserviceseclab/controller/RceController.java
传播参数: commands
代码行数: 29
代码片段:         ProcessBuilder processBuilder = new ProcessBuilder(commands);
```

可以看到是很标准的调用链的形式， 可以很好的帮忙分析对应漏洞是否真实。

如果需要测试其他项目，则可以按照命令行的提示来指定，共有以下几个参数：

```
"-c", "--codeql_path", help="codeql executable path", 
"-i", "--input_project_path", help="input project path"
"-d", "--database_path", help="database file path"
"-q", "--query_path", help="ql query. scan all .ql in path."
```

测试的java项目来自 https://github.com/l4yn3/micro_service_seclab.git