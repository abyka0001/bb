import asyncio
import random
import uuid
import time
import base64
import hashlib

import aiohttp
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import uvloop

DATA_CENTERS = []

async def cdn(session):
    async with session.get("https://pastebin.com/raw/JAUiZzvb") as response:
        ips_text = await response.text()

    ips = [ip.strip() for ip in ips_text.split(",") if ip.strip()]
    semaphore = asyncio.Semaphore(100)

    async def add_cdn(ip):
        async with semaphore:
            async with session.get(f"https://dns.google/resolve?name=gwbyte.sandboxol.com&type=A&edns_client_subnet={ip}") as response:
                payload = await response.json()
                return [
                    answer["data"] for answer in payload.get("Answer", [])
                    if answer.get("type") == 1 and "data" in answer
                ]

    while True:
        tasks = (add_cdn(ip) for ip in ips)
        results = await asyncio.gather(*tasks)

        unique_ips = {ip for sublist in results for ip in sublist}

        DATA_CENTERS[:] = sorted(list(unique_ips))
        print(f"DATA_CENTERS updated: {DATA_CENTERS}")

        await asyncio.sleep(600)

ACCOUNTS = []

async def fspam(session):
    while True:
        try:
            acc_id, acc_token, acc_register_ts, bmg_register_ts, bmg_id = random.choice(ACCOUNTS).split(",")

            lang = random.choice([
                "zh_CN,哥哥,姐姐,弟弟,妹妹",
                "en_US,Older Brother,Older Sister,Younger Brother,Younger Sister",
                "de_DE,Älterer Bruder,Ältere Schwester,Jüngerer Bruder,Jüngere Schwester",
                "es_ES,Hermano mayor,Hermana mayor,Hermano menor,Hermana menor",
                "fr_FR,Grand frère,Sœur aînée,Cadet,Sœur cadette",
                "hi_IN,बड़ा भाई,बड़ी बहन,छोटा भाई,छोटी बहन",
                "in_ID,Kakak,Kakak perempuan,Adik laki-laki,Adik perempuan",
                "it_IT,Fratello maggiore,Sorella maggiore,Fratello minore,Sorella minore",
                "ja_JP,兄さん,お姉さん,弟,妹",
                "ko_KR,형,언니,남동생,여동생",
                "pl_PL,Starszy brat,Starsza siostra,Młodszy brat,Młodsza siostra",
                "pt_PT,Irmão mais velho,Irmã mais velha,Irmão mais novo,Irmã mais nova",
                "ru_RU,Старший брат,Старшая сестра,Младший брат,Младшая сестра",
                "th_TH,พี่ชาย,พี่่สาว,น้องชาย,น้องสาว",
                "tr_TR,Abi,Abla,Küçük kardeş,Küçük kız kardeş",
                "uk_UA,Older Brother,Older Sister,Younger Brother,Younger Sister",
                "vi_VN,Anh trai,Chị gái,Em trai,Em gái"
            ])
            x_nonce = str(uuid.uuid4())
            x_time = str(int(time.time()))
            x_sign = hashlib.md5(f"6aDtpIdzQdgGwrpP6HzuPA/friend/api/v1/family/recruit{x_nonce}{x_time}9EuDKGtoWAOWoQH1cRng-d5ihNN60hkGLaRiaZTk-6s".encode()).hexdigest()

            async with session.delete(
                f"http://{random.choice(DATA_CENTERS)}:80/friend/api/v1/family/recruit",
                headers={
                    "userId": acc_id,
                    "packageName": "blockymods",
                    "packageNameFull": "com.sandboxol.blockymods",
                    "androidVersion": "36",
                    "OS": "android",
                    "appType": "android",
                    "appLanguage": lang[:2],
                    "appVersion": "5542",
                    "appVersionName": "3.8.2",
                    "channel": "sandbox",
                    "uid_register_ts": acc_register_ts,
                    "device_register_ts": bmg_register_ts,
                    "eventType": "app",
                    "userDeviceId": bmg_id,
                    "userLanguage": lang[:5],
                    "region": "RU",
                    "clientType": "client",
                    "env": "prd",
                    "package_name_en": "com.sandboxol.blockymods",
                    "md5": "5d0de77b0f4b93b44669f146e54b49d9",
                    "X-ApiKey": "6aDtpIdzQdgGwrpP6HzuPA",
                    "X-Nonce": x_nonce,
                    "X-Time": x_time,
                    "X-Sign": hashlib.md5((x_sign + bmg_id).encode()).hexdigest(),
                    "X-UrlPath": "/friend/api/v1/family/recruit",
                    "Access-Token": enc_token(acc_token + x_nonce),
                    "Host": "gwbyte.sandboxol.com",
                    "Connection": "Keep-Alive",
                    "Accept-Encoding": "gzip",
                    "User-Agent": "okhttp/4.12.0"
                },
                timeout=5
            ) as response:
                pass

            x_nonce = str(uuid.uuid4())
            x_time = str(int(time.time()))
            random.randint(1, 4)
            a = "{"
            b = "}"
            l_arr = lang.split(',') 

            m_type = random.randint(1, 4)
            o_type = random.randint(1, 4)

            data = f'{a}"age":0,"memberName":"{l_arr[m_type]}","memberType":{m_type},"msg":"","ownerName":"{l_arr[o_type]}","ownerType":{o_type}{b}'
            x_sign = hashlib.md5(f"6aDtpIdzQdgGwrpP6HzuPA/friend/api/v1/family/recruit{x_nonce}{x_time}{data}9EuDKGtoWAOWoQH1cRng-d5ihNN60hkGLaRiaZTk-6s".encode()).hexdigest()

            async with session.post(
                f"http://{random.choice(DATA_CENTERS)}:80/friend/api/v1/family/recruit",
                headers={
                    "language": lang[:5],
                    "userId": acc_id,
                    "packageName": "blockymods",
                    "packageNameFull": "com.sandboxol.blockymods",
                    "androidVersion": "36",
                    "OS": "android",
                    "appType": "android",
                    "appLanguage": lang[:2],
                    "appVersion": "5542",
                    "appVersionName": "3.8.2",
                    "channel": "sandbox",
                    "uid_register_ts": acc_register_ts,
                    "device_register_ts": bmg_register_ts,
                    "eventType": "app",
                    "userDeviceId": bmg_id,
                    "userLanguage": lang[:5],
                    "region": "RU",
                    "clientType": "client",
                    "env": "prd",
                    "package_name_en": "com.sandboxol.blockymods",
                    "md5": "5d0de77b0f4b93b44669f146e54b49d9",
                    "X-ApiKey": "6aDtpIdzQdgGwrpP6HzuPA",
                    "X-Nonce": x_nonce,
                    "X-Time": x_time,
                    "X-Sign": hashlib.md5((x_sign + bmg_id).encode()).hexdigest(),
                    "X-UrlPath": "/friend/api/v1/family/recruit",
                    "Access-Token": enc_token(acc_token + x_nonce),
                    "Content-Type": "application/json; charset=UTF-8",
                    "Host": "gwbyte.sandboxol.com",
                    "Connection": "Keep-Alive",
                    "Accept-Encoding": "gzip",
                    "User-Agent": "okhttp/4.12.0"
                },
                data=data,
                timeout=5
            ) as response:
                pass
            await asyncio.sleep(1)
        except Exception as e:
            print(e)

def enc_token(token):
    key = hashlib.md5(b"9EuDKGtoWAOWoQH1cRng-d5ihNN60hkGLaRiaZTk-6s").hexdigest()

    padder = padding.PKCS7(128).padder()
    encryptor = Cipher(algorithms.AES(key[:16].encode()), modes.ECB(), backend=default_backend()).encryptor()

    return base64.b64encode(encryptor.update(padder.update(bytes(b ^ 0x73 for b in token.encode())) + padder.finalize()) + encryptor.finalize()).decode()

async def main():
    async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(limit=0)) as session:
        with open("noban.txt") as f:
            ACCOUNTS.extend(f.read().splitlines())

        asyncio.create_task(cdn(session))
        while True:
            await asyncio.sleep(0)
            if not DATA_CENTERS:
                continue
            break
        tasks = [fspam(session) for _ in range(150)]
        await asyncio.gather(*tasks)

uvloop.run(main())
