import os
import hashlib
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
from concurrent.futures import ThreadPoolExecutor, as_completed

def derive_key_from_password(password):                     # 由原始口令派生成密钥
    hash = hashlib.sha512(password.encode("utf-8")).digest()# SHA-512得到64字节
    return hash[:32]                                        # 取前32字节作为ChaCha20-Poly1305密钥

def encrypt_file(filepath, key):                            # 单文件加密处理
    try:
        nonce = get_random_bytes(12)                        # ChaCha20-Poly1305推荐12字节nonce
        with open(filepath, "rb") as f:
            plaintext = f.read()                            # 加载明文（文件较大时可分块实现）
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)# 创建加密器实例
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        with open(filepath, "wb") as f:
            f.write(nonce)                                  # 先写nonce（12字节）
            f.write(tag)                                    # 后写tag（16字节）
            f.write(ciphertext)                             # 最后写密文 
        return (filepath, True, "")                         # 返回成功标记
    except Exception as e:
        return (filepath, False, str(e))                    # 捕获异常

def decrypt_file(filepath, key):                            # 单文件解密处理
    try:
        with open(filepath, "rb") as f:
            nonce = f.read(12)                              # 先读nonce
            tag = f.read(16)                                # 再读tag
            ciphertext = f.read()                           # 后读全部密文
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        with open(filepath, "wb") as f:
            f.write(plaintext)                              # 写回明文
        return (filepath, True, "")                         # 正常返回
    except Exception as e:
        return (filepath, False, str(e))                    # 捕获异常

def list_all_files(folder):                                 # 获取待处理全部文件绝对路径
    files = []
    for root, dirs, fs in os.walk(folder):
        for name in fs:
            files.append(os.path.join(root, name))
    return files

def batch_process_multithreaded(folder, key, encrypt=True, max_workers=None):
    files = list_all_files(folder)                          # 枚举所有目标文件
    total = len(files)
    action = "加密" if encrypt else "解密"

    worker_count = max_workers if max_workers else os.cpu_count() * 2    # 默认线程数2x核心数
    print(f"开始{action}任务，共{total}个文件，最大线程数:{worker_count}")

    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        futures = []
        for filepath in files:
            if encrypt:
                future = executor.submit(encrypt_file, filepath, key)    # 分派加密任务
            else:
                future = executor.submit(decrypt_file, filepath, key)    # 分派解密任务
            futures.append(future)
        finished = 0
        for future in as_completed(futures):                             # 逐个处理完成的任务
            filepath, ok, errmsg = future.result()
            finished += 1
            if ok:
                print(f"[OK] {action}: {filepath}")
            else:
                print(f"[FAIL] {action}: {filepath} 错误: {errmsg}")
    print(f"全部{action}任务完成。（共{total}个）")

if __name__ == "__main__":
    option = input("输入 'e' 加密，'d' 解密：").strip().lower()                  # 选择操作
    folder = input("需要处理的文件夹路径：").strip()                              # 输入待批处理文件夹
    password = input("请输入口令：").strip()                                    # 输入口令
    key = derive_key_from_password(password)                                 # 由口令得密钥

    if option == "e":
        batch_process_multithreaded(folder, key, encrypt=True)               # 多线程加密
    elif option == "d":
        batch_process_multithreaded(folder, key, encrypt=False)              # 多线程解密
    else:
        print("无效选项。")                                                  # 错误模式提示
