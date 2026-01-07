from os import getenv
import re
import requests
from cryptography.fernet import Fernet
import base64
import hashlib
import time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

class SeleniumAuth:
    LOGIN_URL = "https://uis.fudan.edu.cn/authserver/login?service=https://fdjwgl.fudan.edu.cn/student/home"

    def __init__(self, uid, password):
        self.uid = uid
        self.password = password
        self.session = requests.Session()
        self._login_with_edge()

    def _login_with_edge(self):
        
        options = Options()
        options.add_argument("--headless=new")
        options.add_argument("--disable-gpu")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--window-size=1920,1080")
        options.add_argument("--lang=zh-CN")

        driver = webdriver.Chrome(
            service=Service("/usr/bin/chromedriver"),
            options=options
        )

        try:
            driver.get(self.LOGIN_URL)

            wait = WebDriverWait(driver, 30)

            # 用户名
            wait.until(EC.presence_of_element_located((By.ID, "username"))).send_keys(self.uid)

            # 密码
            driver.find_element(By.ID, "password").send_keys(self.password)

            # 登录按钮
            driver.find_element(By.CLASS_NAME, "auth_login_btn").click()

            # 等 fdjwgl 首页加载完成
            wait.until(
                lambda d: d.current_url.startswith("https://fdjwgl.fudan.edu.cn/student")
            )

            # 注入 cookies → requests
            for c in driver.get_cookies():
                self.session.cookies.set(
                    c["name"],
                    c["value"],
                    domain=c.get("domain"),
                    path=c.get("path", "/")
                )

        finally:
            driver.quit()

    def close(self):
        self.session.close()


class Snapshot:
    def __init__(self, gpa=0.0, rank=0.0, credits=0.0, class_avg=0.0, class_mid=0.0):
        # 当前 GPA
        self.gpa = gpa
        # 当前排名
        self.rank = rank
        # 已修学分
        self.credits = credits
        # 班级平均 GPA
        self.class_avg = class_avg
        # 班级中位数 GPA
        self.class_mid = class_mid
    
    def compare(self, another_snapshot):
        """
        与另一份快照进行对比：
        - 若不存在历史快照，则认为发生了变化 (返回 True)
        - 否则仅比较 GPA 与学分是否发生变化
        """
        if another_snapshot is None:
            # 没有旧记录, 默认认为是新状态
            return True

        # 只要 GPA 或学分不同, 即认为快照发生变化
        return (
            self.gpa != another_snapshot.gpa or
            self.credits != another_snapshot.credits
        )


class GradeChecker(SeleniumAuth):
    def __init__(self, uid, password):
        super().__init__(uid, password)
        self.login()

    def get_stat(self):
        url = "https://fdjwgl.fudan.edu.cn/student/for-std/grade/my-gpa/search"
        params = {
            "departmentName": "大数据学院",
            "studentAssoc": "416631",
            "gradeInput": "2022",
            "grade": "2022",
            "departmentAssoc": "3381",
            "majorAssoc": "1227"
        }
        headers = {
            "Referer": "https://fdjwgl.fudan.edu.cn/student/for-std/grade/my-gpa/search-index/416631",
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        res = self.session.get(url, params=params, headers=headers)
        print("STATUS:", res.status_code)
        print("URL:", res.url)
        print("TEXT[:500]:", res.text[:500])
        
        # 登录态校验
        if "id.fudan.edu.cn" in res.url or "uis.fudan.edu.cn" in res.url:
            raise RuntimeError("Not logged in: redirected to CAS")

        if res.headers.get("Content-Type", "").startswith("text/html"):
            raise RuntimeError("Not logged in: got HTML instead of JSON")

        try:
            data = res.json()
        except Exception as e:
            print("JSON decode failed")
            print(res.text[:1000])
            raise e
        
        my_gpa = float(data['gpa'])
        my_credits = float(data['credits'])
        my_rank = float(data['rank'])
        
        gpa_list = [float(x) for x in data['classGPAList']]
        class_average = sum(gpa_list) / len(gpa_list)
        class_mid = sorted(gpa_list)[len(gpa_list)//2]
        
        return Snapshot(my_gpa, my_rank, my_credits, class_average, class_mid)


def generate_key(password: str) -> bytes:
    """
    根据用户密码生成对称加密密钥:
    1. 使用 SHA-256 对密码进行哈希
    2. 将哈希结果进行 URL-safe Base64 编码 (满足 Fernet 对密钥格式的要求)
    """
    # 对密码做 SHA-256 哈希, 得到 32 字节摘要
    hash = hashlib.sha256(password.encode()).digest()

    # 转换为 Fernet 要求的 Base64 编码格式
    return base64.urlsafe_b64encode(hash)


def encrypt(text: str, key: bytes) -> bytes:
    """
    使用 Fernet 对称加密算法加密明文字符串
    """
    # 基于密钥构造 Fernet 加密器
    fernet = Fernet(key)

    # 将字符串编码为 bytes 后进行加密
    return fernet.encrypt(text.encode())


def decrypt(encrypted_data: bytes, key: bytes) -> str:
    """
    使用 Fernet 对称加密算法解密数据
    """
    # 基于同一密钥构造 Fernet 解密器
    fernet = Fernet(key)

    # 解密并将 bytes 转回字符串
    return fernet.decrypt(encrypted_data).decode()


def save_snapshot(snapshot, password):
    """
    将成绩快照加密后写入本地文件：
    1. 将 Snapshot 序列化为字符串
    2. 使用密码派生密钥
    3. 加密并保存为二进制文件
    """
    # 将快照数据按固定顺序拼接成字符串
    # 注意: 这里隐式依赖字段顺序
    text = (
        f'{snapshot.gpa}-'
        f'{snapshot.rank}-'
        f'{snapshot.credits}-'
        f'{snapshot.class_avg}-'
        f'{snapshot.class_mid}'
    )

    # 根据密码生成加密密钥
    key = generate_key(password)

    # 加密序列化后的字符串
    encrypted = encrypt(text, key)

    # 以二进制形式写入文件 (覆盖原内容)
    with open('./record.txt', 'wb+') as f:
        f.write(encrypted)


def read_snapshot(password):
    """
    从本地文件中读取并解密成绩快照
    """
    try:
        # 以二进制方式读取加密数据
        with open('./record.txt', 'rb') as f:
            text = f.readline()

            # 文件为空的情况
            if not text:
                return None

            # 使用用户输入的密码生成解密密钥
            key = generate_key(password)

            # 解密数据
            decrypted = decrypt(text, key)

            # 反序列化：按分隔符拆分字段
            stats = decrypted.split('-')

            # 构造 Snapshot 对象并返回
            return Snapshot(
                float(stats[0]),
                float(stats[1]),
                float(stats[2]),
                float(stats[3]),
                float(stats[4])
            )

    except Exception:
        return None

        
if __name__ == '__main__':
    uid, psw, token = getenv("STD_ID"), getenv("PASSWORD"), getenv("TOKEN")
    assert (uid and psw and token)
    checker = GradeChecker(uid, psw)
    snapshot = checker.get_stat()
    checker.close()
    print(snapshot)
    
    old_snapshot = read_snapshot(token)
    if snapshot.compare(old_snapshot):
        save_snapshot(snapshot, token)
        title = f'GPA {str(old_snapshot.gpa if old_snapshot is not None else 0.0)} -> {str(snapshot.gpa)}'
        url = f'http://www.pushplus.plus/send?token={token}&title={title}&content=排名：{int(old_snapshot.rank if old_snapshot is not None else 0.0)} -> {int(snapshot.rank)}&template=html'
        requests.get(url)
        print('update')