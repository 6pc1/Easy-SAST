import subprocess


# 用于开始codeQl流程前的解lombok
def delombok(project_path):
    print("delombok ing.....")
    try:
        with open('delombok.log', 'w') as log_file:
            print(project_path)
            # linux下运行
            # result = subprocess.run(["sh", "delombok.sh", project_path], stdout=log_file, stderr=subprocess.STDOUT)
            # windows下运行
            result = subprocess.run(["delombok.bat", project_path], stdout=log_file, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(f"delombok failed: {e}")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
    finally:
        print("delombok done")


if __name__ == '__main__':
    delombok(input())