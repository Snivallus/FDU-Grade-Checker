from os import getenv
import re
import requests
from cryptography.fernet import Fernet
import base64
import hashlib
import time


class UISAuth:
    UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:76.0) Gecko/20100101 Firefox/76.0"

    url_login = 'https://uis.fudan.edu.cn/authserver/login?service=https://fdjwgl.fudan.edu.cn/student/home'

    def __init__(self, uid, password):
        self.session = requests.session()
        self.session.keep_alive = False
        self.session.headers['User-Agent'] = self.UA
        self.uid = uid
        self.psw = password

    def _page_init(self):
        page_login = self.session.get(self.url_login)
        if page_login.status_code == 200:
            return page_login.text
        else:
            self.close()

    def login(self):
        page_login = self._page_init()
        data = {
            "username": self.uid,
            "password": self.psw,
            "service": "https://fdjwgl.fudan.edu.cn/student/home"
        }

        result = re.findall(
            r'<input type="hidden" name="([a-zA-Z0-9\-_]+)" value="([a-zA-Z0-9\-_]+)"/?>', 
            page_login
        )

        data.update(result)

        headers = {
            "Host": "uis.fudan.edu.cn",
            "Origin": "https://uis.fudan.edu.cn",
            "Referer": self.url_login,
            "User-Agent": self.UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Cache-Control": "max-age=0"
        }

        post = self.session.post(
            self.url_login,
            data=data,
            headers=headers,
            allow_redirects=False)

        if not post.status_code == 302:
            self.close()

    def logout(self):
        exit_url = 'https://uis.fudan.edu.cn/authserver/logout?service=/authserver/login'
        self.session.get(exit_url).headers.get('Set-Cookie')

    def close(self):
        self.logout()
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


class GradeChecker(UISAuth):
    def __init__(self, uid, password):
        super().__init__(uid, password)
        self.login()

    def get_stat(self):
        res = self.session.get("https://fdjwgl.fudan.edu.cn/student/for-std/grade/my-gpa")
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
    # uid, psw, token = getenv("STD_ID"), getenv("PASSWORD"), getenv("TOKEN")
    # assert (uid and psw and token)
    uid = "21307140051"
    psw = "Yongcuiyang0320"
    checker = GradeChecker(uid, psw)
    snapshot = checker.get_stat()
    checker.close()
    print(snapshot)
    
    # old_snapshot = read_snapshot(token)
    # if snapshot.compare(old_snapshot):
    #     save_snapshot(snapshot, token)
    #     title = f'GPA {str(old_snapshot.gpa if old_snapshot is not None else 0.0)} -> {str(snapshot.gpa)}'
    #     url = f'http://www.pushplus.plus/send?token={token}&title={title}&content=排名：{int(old_snapshot.rank if old_snapshot is not None else 0.0)} -> {int(snapshot.rank)}&template=html'
    #     requests.get(url)
    #     print('update')