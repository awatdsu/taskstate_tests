"""
Тест на уязвимость /admreg
"""
import json
import time
import sqlite3
import os

from typing import Tuple

import jwt
import requests

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_FILE = os.path.join(BASE_DIR, "data", "taskstate.db")


BASE_URL = "http://localhost:7000"
REG_ENDPOINT = "/reg"
LOGIN_ENDPOINT = "/login"

PASSWORD="password"

class Test:

    def __init__(self, vuln_endpoint: str):
        self.client = requests.Session()
        self.base_url = BASE_URL
        self.vuln_endpoint = vuln_endpoint
        self.reg_endpoint = REG_ENDPOINT
        self.login_endpoint = LOGIN_ENDPOINT

    def build_header(self) -> dict[str, str]:
        """
        Устанавливаем заголовки для запроса
        """
        return {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
        }

    def update_client_cookie(self, session: str, rid: int):
        """
        Обновляем куки клиента
        """
        cookies = {}
        if session:
            cookies["session"] = session
        if rid is not None:
            cookies["rid"] = rid
        if cookies:
            self.client.cookies.update(cookies)

    def build_reg_payload(self, login: str, password: str) -> str:
        """
        Создаем payload для регистрации
        """
        return f"login={login}&password={password}&email="

    def build_login_payload(self, login: str, password: str) -> str:
        """
        Создаем payload для авторизации
        """
        return f"login={login}&password={password}"

    def register_first_user(self, login: str, password: str) -> Tuple[str, str]:
        """
        Регистрируем первого пользователя для получения сессии и rid
        """
        self.client.post(
            url = self.base_url + self.reg_endpoint,
            headers=self.build_header(),
            data=self.build_reg_payload(login=login, password=password)
        )
        login_response = self.client.post(
            url = self.base_url + self.login_endpoint,
            headers=self.build_header(),
            data=self.build_login_payload(login=login, password=password),
            allow_redirects=False
        )
        return login_response.cookies.get("session"), login_response.cookies.get("rid")

    def reset_db(self):
        """
        Сбрасываем базу данных для теста
        """
        try:
            with sqlite3.connect(DB_FILE) as conn:
                conn.execute("DELETE FROM TS_User")
                conn.execute("DELETE FROM TS_Task")
                conn.commit()
        except Exception as e:
            conn.rollback()
            print(json.dumps({"error": f"{e}"}))

    def check_db(self):
        """
        Проверяем базу данных на наличие более одного админа, созданного в результате эксплуатации
        """
        conn = None
        try:
            with sqlite3.connect(DB_FILE, timeout=10) as conn:
                cur = conn.cursor()
                # безопасный параметризированный запрос
                cur.execute("SELECT COUNT(*) FROM TS_User WHERE rid = ?", (2,))
                row = cur.fetchone()
            admin_count = row[0] if row else 0

            if admin_count > 1:
                out = {"errcount": 1, "msgdeny": "Тест провален"}
            else:
                out = {"errcount": 0, "msgok": "Тест успешно завершен"}

            print(json.dumps(out, ensure_ascii=False))
            return out
        except Exception as e:
            out = {"errcount": 1, "msgdeny": f"{e}"}
            print(json.dumps(out))
            return out


class ADMREGVuln(Test):
    def __init__(self, vuln_endpoint: str):
        super().__init__(vuln_endpoint=vuln_endpoint)

    def exploit_admreg_vuln(self, session: str, rid: int, count: int):
        """
        Эксплуатация уязвимости - /admreg
        count - количество регистраций админов
        """
        self.update_client_cookie(session, rid)
        url = self.base_url + self.vuln_endpoint

        for i in range(count):
            payload = self.build_reg_payload(login=f"exploit_admin{i}", password=PASSWORD)
            self.client.post(
                url = url,
                headers=self.build_header(),
                data=payload,
                allow_redirects=False
            )
            time.sleep(0.2)

    def run(self):
        """
        Запускаем тест
        1. Сбрасываем базу данных
        2. Регистрируем первого пользователя для получения сессионных куки
        3. Эксплуатируем уязвимость
        4. Проверяем базу данных на наличие более одного админа
        """
        self.reset_db()
        session, rid = self.register_first_user(login="test123", password=PASSWORD)
        if not session:
            print(json.dumps({"errcount": 1, "msgdeny": "Failed to register user!"}))

        self.exploit_admreg_vuln(session=session, rid=rid, count=4)
        self.check_db()

class SSTIVuln(Test):

    def __init__(self, vuln_endpoint: str):
        super().__init__(vuln_endpoint=vuln_endpoint)

    def exploit_SSTI_vuln(self, session: str, rid: int):
        """
        Эксплуатирование SSTI уязвимости
        """
        search_query = "{{7*'7'}}"
        self.update_client_cookie(session=session, rid=rid)

        response = self.client.get(
            url=self.base_url+self.vuln_endpoint+f"?search={search_query}",
            headers=self.build_header()
        )
        exploit_res = response.text.find("7777777")

        if exploit_res < 0:
            out = {"errcount": 0, "msgok": "Тест успешно завершен"}
        else:
            out = {"errcount": 1, "msgdeny": "Тест провален"}
        print(json.dumps(out, ensure_ascii=False))


    def run(self):
        """
        Запускаем тест
        1. Сбрасываем базу данных
        2. Регистрируем первого пользователя для получения сессионных куки
        3. Эксплуатируем уязвимость
        """
        self.reset_db()
        session, rid = self.register_first_user(login="test123", password=PASSWORD)
        if not session:
            print(json.dumps({"errcount": 1, "msgdeny": "Failed to register user!"}))

        self.exploit_SSTI_vuln(session=session, rid=rid)

class RIDVuln(Test):

    def __init__(self, task_create_endpoint: str, vuln_endpoint: str = ""):
        self.task_create_endpoint = task_create_endpoint
        super().__init__(vuln_endpoint=vuln_endpoint)

    def create_task_payload(self, title: str, description: str, private: bool):
        return f"title={title}&description={description}&did=0&private={private}"

    def create_task(self, session: str, rid: int, title: str, description: str, private: bool):
        self.update_client_cookie(session=session, rid=rid)
        self.client.post(
            url=self.base_url+self.task_create_endpoint,
            headers=self.build_header(),
            data=self.create_task_payload(title, description, private)
        )

    def check_kstatus_db(self):
        """
        Проверяем kstatus в базе данных у таска, созданного первым пользователем
        """
        conn = None
        try:
            with sqlite3.connect(DB_FILE, timeout=10) as conn:
                cur = conn.cursor()
                # безопасный параметризированный запрос
                cur.execute("SELECT kstatus FROM TS_Task WHERE tid = ?", (1,))
                row = cur.fetchone()
            kstatus = row[0] if row else 0

            if str(kstatus) == "2":
                out = {"errcount": 1, "msgdeny": "Тест провален"}
            else:
                out = {"errcount": 0, "msgok": "Тест успешно завершен"}

            print(json.dumps(out, ensure_ascii=False))
            return out
        except Exception as e:
            out = {"errcount": 1, "msgdeny": f"{e}"}
            print(json.dumps(out))
            return out

    def exploit_RID_vuln(self):
        """
        Создать приватный таск под первым пользователем
        Создать второго пользователя, записать ему в куки rid=2, взять в работу таск первого пользователя
        """
        session, rid = self.register_first_user(login="test123", password=PASSWORD)
        if not session:
            print(json.dumps({"errcount": 1, "msgdeny": "Failed to register user!"}))
        
        self.create_task(session=session, rid=rid, title="First task", description="Test", private=True)

        session2, rid2 = self.register_first_user(login="new_test123", password=PASSWORD)
        self.client.cookies.clear()
        rid2 = "2"
        self.update_client_cookie(session=session2, rid=rid2)
        self.client.get(
            url=self.base_url+"/task/1/towork",
            headers=self.build_header()
        )
        self.client.get(
            url=self.base_url+"/task/1/nstatus",
            headers=self.build_header()
        )
        self.client.get(
            url=self.base_url+"/task/1/nstatus",
            headers=self.build_header()
        )


    def run(self):
        self.reset_db()
        self.exploit_RID_vuln()
        self.check_kstatus_db()
        
class JWTVuln(Test):
    
    def __init__(self):
        self.jwt_key = "CTF-2#PirateLabel"
        self.algorithm = "HS256"
        super().__init__(vuln_endpoint="")
    
    def jwt_encod(self, user_id: int, login: str):
        jwt_data = {"id": user_id,"login": login}
        token = jwt.encode(jwt_data, self.jwt_key, algorithm=self.algorithm)
        return token

    def jwt_decod(self, token):
        jwt_data = jwt.decode(token, self.jwt_key, algorithms=self.algorithm)
        return jwt_data
    
    def get_token_from_db(self):
        try:
            with sqlite3.connect(DB_FILE, timeout=10) as conn:
                cur = conn.cursor()
                cur.execute("SELECT token FROM TS_User WHERE id = ?", (1,))
                row = cur.fetchone()
            token = row[0] if row else ""
            return str(token)
        except Exception as e:
            out = {"errcount": 1, "msgdeny": f"{e}"}
            print(json.dumps(out))



    def exploit_jwt_vuln(self):

        login = "test123"
        self.register_first_user(login=login, password=PASSWORD)
        self.client.get(
            url=self.base_url+f"/passrec?login={login}",
            headers=self.build_header()
        )
        token = self.get_token_from_db()
        token_self_generated = self.jwt_encod(user_id=1, login=login)
        if token == token_self_generated:
            out = {"errcount": 1, "msgdeny": "Тест провален"}
        else:
            out = {"errcount": 0, "msgok": "Тест успешно завершен"}
        print(out)

    def run(self):
        self.reset_db()
        self.exploit_jwt_vuln()




    


def main():
    test = ADMREGVuln(vuln_endpoint="/admreg")
    test.run()

if __name__ == "__main__":
    main()
