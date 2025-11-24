import os
import requests
import json
import re
import time
import random
from urllib.parse import urlencode
from dotenv import load_dotenv
from typing import List, Dict, Any, Optional
from requests.auth import HTTPBasicAuth

# ----------------------------------------------------------------------
# RETRY SETTINGS
# ----------------------------------------------------------------------
MAX_RETRIES = 5
BASE_DELAY = 2


def make_request_with_retry(func):
    """Декоратор для устойчивых HTTP-запросов: retry на 429/5xx и сетевые ошибки."""
    def wrapper(*args, **kwargs):
        for attempt in range(MAX_RETRIES):
            try:
                response = func(*args, **kwargs)

                if response is None:
                    # func уже логировал ошибку
                    if attempt < MAX_RETRIES - 1:
                        wait_time = (BASE_DELAY ** attempt) + random.uniform(0, 1)
                        time.sleep(wait_time)
                        continue
                    return None

                if getattr(response, 'status_code', None) == 200:
                    return response

                if response.status_code in (401, 403, 404):
                    print(f"[ERROR] Критическая ошибка {response.status_code}: {getattr(response, 'url', '')}")
                    return response

                if response.status_code in (429, 500, 502, 503, 504):
                    if attempt < MAX_RETRIES - 1:
                        wait_time = (BASE_DELAY ** attempt) + random.uniform(0, 1)
                        print(f"[RETRY] Код {response.status_code}. Попытка {attempt+1}/{MAX_RETRIES}. Жду {wait_time:.2f}s")
                        time.sleep(wait_time)
                        continue
                    else:
                        print(f"[FAIL] Попытки исчерпаны. Код {response.status_code}. Тело ответа: {response.text[:400]}")
                        return response

                print(f"[WARN] Неожиданный код {response.status_code}. URL: {getattr(response, 'url', '')}. Тело: {response.text[:300]}")
                return response

            except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
                if attempt < MAX_RETRIES - 1:
                    wait_time = (BASE_DELAY ** attempt) + random.uniform(0, 1)
                    print(f"[NET ERROR] {e}. Попытка {attempt+1}/{MAX_RETRIES}. Жду {wait_time:.2f}s")
                    time.sleep(wait_time)
                    continue
                print(f"[FAIL] Ошибка сети: {e}")
                return None
            except Exception as e:
                print(f"[EXCEPTION] {e}")
                return None
        return None
    return wrapper

# ----------------------------------------------------------------------
# MAIN CLIENT
# ----------------------------------------------------------------------
load_dotenv()


class StepikClient:
    API_URL = "https://stepik.org/api"
    OAUTH_URL = "https://stepik.org/oauth2/token/"
    AUTH_URL = "https://stepik.org/oauth2/authorize/"
    # Приведите REDIRECT_URI в соответствие с зарегистрированным в приложении Stepik
    REDIRECT_URI = "http://localhost:5000/callback"

    def __init__(self):
        self.client_id = os.getenv("STEPIK_CLIENT_ID")
        self.client_secret = os.getenv("STEPIK_CLIENT_SECRET")
        if not self.client_id or not self.client_secret:
            raise ValueError("Не найдены STEPIK_CLIENT_ID или STEPIK_CLIENT_SECRET в .env")

        self.session = requests.Session()
        self.token = self._login_flow()
        # Обновляем заголовки сессии
        if self.token:
            self.session.headers.update({'Authorization': f'Bearer {self.token}'})

        # Храню последний полный raw-ответ единичного запроса (для сохранения lesson_raw)
        self._last_raw_response: Optional[Dict[str, Any]] = None

    # ---------------- AUTH FLOW ----------------
    def _login_flow(self) -> Optional[str]:
        # Пытаемся обновить токен через refresh_token
        if os.path.exists("token_storage.json"):
            try:
                with open("token_storage.json", "r", encoding='utf-8') as f:
                    data = json.load(f)
                    if data.get('refresh_token'):
                        print("[AUTH] Обнаружен refresh_token — пробуем обновить access_token...")
                        return self._refresh_access_token(data['refresh_token'])
            except Exception as e:
                print(f"[AUTH] Ошибка чтения token_storage.json: {e} — удаляю файл и буду просить вход.")
                try:
                    os.remove("token_storage.json")
                except Exception:
                    pass

        return self._authorize_user_manual()

    def _save_tokens(self, tokens: Dict[str, Any]):
        with open("token_storage.json", "w", encoding='utf-8') as f:
            json.dump(tokens, f, ensure_ascii=False, indent=2)
        print("[AUTH] Токены сохранены в token_storage.json")

    def _exchange_code_for_token(self, code: str) -> Optional[str]:
        auth = HTTPBasicAuth(self.client_id, self.client_secret)

        @make_request_with_retry
        def execute():
            return self.session.post(self.OAUTH_URL, data={
                'grant_type': 'authorization_code',
                'code': code,
                'redirect_uri': self.REDIRECT_URI
            }, auth=auth, timeout=15)

        resp = execute()
        if not resp:
            raise ConnectionError("Нет ответа при обмене кода на токен")
        if resp.status_code != 200:
            raise ConnectionError(f"Ошибка обмена кода: {resp.status_code} {resp.text}")

        tokens = resp.json()
        self._save_tokens(tokens)
        access = tokens.get('access_token')
        if access:
            self.session.headers.update({'Authorization': f'Bearer {access}'})
        return access

    def _authorize_user_manual(self) -> Optional[str]:
        params = {
            'response_type': 'code',
            'client_id': self.client_id,
            'redirect_uri': self.REDIRECT_URI,
            'scope': 'read write'
        }
        auth_link = f"{self.AUTH_URL}?{urlencode(params)}"

        print('\n' + '='*60)
        print('ОТКРОЙТЕ ССЫЛКУ В БРАУЗЕРЕ ДЛЯ АВТОРИЗАЦИИ:')
        print(auth_link)
        print('После авторизации /callback в URL будет параметр ?code=... — вставьте этот код сюда.')
        print('='*60 + '\n')

        code = input('Вставьте code из URL: ').strip()
        if not code:
            raise ConnectionError('Код авторизации не введён')
        return self._exchange_code_for_token(code)

    def _refresh_access_token(self, refresh_token: str) -> Optional[str]:
        auth = HTTPBasicAuth(self.client_id, self.client_secret)

        @make_request_with_retry
        def execute():
            return self.session.post(self.OAUTH_URL, data={
                'grant_type': 'refresh_token',
                'refresh_token': refresh_token
            }, auth=auth, timeout=15)

        resp = execute()
        if not resp:
            print('[AUTH] Не удалось получить ответ при refresh')
            return None
        if resp.status_code != 200:
            print(f"[AUTH] Refresh вернул {resp.status_code}: {resp.text[:300]}")
            try:
                os.remove("token_storage.json")
            except Exception:
                pass
            return self._authorize_user_manual()

        tokens = resp.json()
        self._save_tokens(tokens)
        access = tokens.get('access_token')
        if access:
            self.session.headers.update({'Authorization': f'Bearer {access}'})
        return access

    # ---------------- HELPERS ----------------
    def _get_headers(self) -> Dict[str, str]:
        return {'Authorization': f'Bearer {self.session.headers.get("Authorization", self.session.headers.get("authorization", "").replace("Bearer ", ""))}', 'Content-Type': 'application/json'}

    def _sanitize_filename(self, name: Any) -> str:
        name = str(name or '').strip()
        name = re.sub(r'[<>:"/\\|?*]', '', name)
        name = name.strip().rstrip('.')
        if not name:
            return 'Unnamed'
        return name

    @make_request_with_retry
    def _fetch_single_raw(self, url: str, headers: Dict[str, str], params: Any = None) -> Optional[requests.Response]:
        try:
            return self.session.get(url, headers=headers, params=params, timeout=20)
        except Exception as e:
            print(f"[HTTP GET ERROR] {e}")
            return None

    # ---------------- API FETCH ----------------
    def fetch_object_single(self, object_type: str, object_id: int) -> Dict[str, Any]:
        url = f"{self.API_URL}/{object_type}/{object_id}"
        response = self._fetch_single_raw(url=url, headers=self._get_headers())
        if not response or response.status_code != 200:
            return {}

        data = response.json()
        # Сохраняем последний raw для дальнейшего сохранения на диск
        self._last_raw_response = data

        # Возможные ключи: 'lessons', 'lesson', object_type, object_type + 's'
        items = data.get(object_type) or data.get(object_type + 's') or data.get(object_type.rstrip('s'))
        if isinstance(items, list) and items:
            return items[0]
        if isinstance(data, dict) and data.get('id'):
            return data
        return {}

    def fetch_objects(self, object_type: str, object_ids: List[int]) -> List[Dict[str, Any]]:
        if not object_ids:
            return []
        url = f"{self.API_URL}/{object_type}"
        objects: List[Dict[str, Any]] = []
        chunk_size = 20

        for i in range(0, len(object_ids), chunk_size):
            chunk = object_ids[i:i + chunk_size]
            # Формируем повторяющийся параметр ids[]
            params = [("ids[]", str(x)) for x in chunk]

            response = self._fetch_single_raw(url=url, headers=self._get_headers(), params=params)
            if not response or response.status_code != 200:
                continue

            data = response.json()
            # Определяем ключ с возвращаемыми объектами
            key = object_type if object_type in data else (list(data.keys())[0] if data else object_type)
            fetched = data.get(key) or []
            if isinstance(fetched, list):
                objects.extend(fetched)

            # Небольшая пауза между запросами
            time.sleep(0.1)

        return objects

    # ---------------- SEARCH ----------------
    def search_public_free_courses(self, query: str, limit: int = 1) -> List[Dict[str, Any]]:
        print(f"Поиск курсов по запросу: {query} ...")
        url = f"{self.API_URL}/search-results"
        found: List[Dict[str, Any]] = []
        page = 1

        while len(found) < limit:
            params = {'query': query, 'is_public': 'true', 'is_paid': 'false', 'type': 'course', 'page': page}
            response = self._fetch_single_raw(url=url, headers=self._get_headers(), params=params)
            if not response or response.status_code != 200:
                break

            results = response.json().get('search-results', [])
            if not results:
                break

            course_ids = []
            for r in results:
                # возможные поля: 'target', 'target_id', 'course'
                cid = r.get('target_id') or r.get('target') or r.get('course')
                if cid:
                    course_ids.append(cid)
                    if len(course_ids) >= (limit - len(found)):
                        break

            if not course_ids:
                break

            courses = self.fetch_objects('courses', course_ids)
            for c in courses:
                if c.get('is_public') and not c.get('is_paid'):
                    found.append(c)
                    if len(found) >= limit:
                        break

            page += 1

        return found[:limit]

    # ---------------- SAVE & PROCESS ----------------
    def save_json(self, data: Any, folder: str, filename: str):
        os.makedirs(folder, exist_ok=True)
        path = os.path.join(folder, filename)
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"Ошибка сохранения {path}: {e}")

    def process_course(self, course: Dict[str, Any]):
        cid = course.get('id')
        title = self._sanitize_filename(course.get('title', f'course_{cid}'))
        course_dir = f"Course_{cid}_{title}"
        os.makedirs(course_dir, exist_ok=True)
        print(f"\n[{cid}] Курс: {title}")
        self.save_json(course, course_dir, f"course_{cid}.json")

        section_ids = course.get('sections') or []
        if not section_ids:
            print("  Нет секций.")
            return

        sections = self.fetch_objects('sections', section_ids)
        sections.sort(key=lambda x: x.get('position', 0))
        for s in sections:
            self.process_section(s, course_dir)

    def process_section(self, section: Dict[str, Any], parent_dir: str):
        sid = section.get('id')
        pos = section.get('position', 0)
        title = self._sanitize_filename(section.get('title', f'Section_{sid}'))

        section_dir = os.path.join(parent_dir, f"Section_{pos:02d}_{title}")
        os.makedirs(section_dir, exist_ok=True)
        print(f"  -> Секция {pos}: {title}")
        self.save_json(section, section_dir, f"section_{sid}.json")

        unit_ids = section.get('units') or []
        if not unit_ids:
            return

        units = self.fetch_objects('units', unit_ids)
        units.sort(key=lambda x: x.get('position', 0))
        lesson_ids = [u.get('lesson') for u in units if u.get('lesson')]
        lessons = self.fetch_objects('lessons', lesson_ids)
        lessons_map = {l.get('id'): l for l in lessons}

        for unit in units:
            lid = unit.get('lesson')
            lesson = lessons_map.get(lid)
            if lesson:
                self.process_lesson(lesson, unit, section_dir)

    def process_lesson(self, lesson: Dict[str, Any], unit: Dict[str, Any], parent_dir: str):
        lesson_id = lesson.get('id')
        pos = unit.get('position', 0)
        title = self._sanitize_filename(lesson.get('title', f'lesson_{lesson_id}'))

        lesson_dir = os.path.join(parent_dir, f"Lesson_{pos:02d}_{title}")
        os.makedirs(lesson_dir, exist_ok=True)

        # Сохраняем unit + текущие bulk-данные урока
        self.save_json(unit, lesson_dir, f"unit_{unit.get('id')}.json")
        self.save_json(lesson, lesson_dir, f"lesson_bulk_{lesson_id}.json")

        step_ids = lesson.get('steps') or []
        if not step_ids:
            print(f"    [INFO] Урок {lesson_id} не содержит steps в bulk. Пытаюсь одиночный запрос...")
            full = self.fetch_object_single('lessons', lesson_id)
            # Сохраняем полный raw ответ, если он был
            if getattr(self, '_last_raw_response', None):
                self.save_json(self._last_raw_response, lesson_dir, f"lesson_raw_{lesson_id}.json")
                # очищаем
                self._last_raw_response = None

            if full and full.get('steps'):
                lesson = full
                step_ids = lesson.get('steps')
                print(f"    Fallback успешен: найдено {len(step_ids)} шагов.")
            else:
                print(f"    [WARN] Шаги не найдены даже после одиночного запроса.")

        print(f"    -> Урок {pos}: {title} (Шагов: {len(step_ids)})")
        if not step_ids:
            return

        steps = self.fetch_objects('steps', step_ids)
        steps.sort(key=lambda x: x.get('position', 0))
        for st in steps:
            self.save_step(st, lesson_dir)

    def save_step(self, step: Dict[str, Any], parent_dir: str):
        sid = step.get('id')
        pos = step.get('position', 0)
        block = (step.get('block') or {}).get('name', 'unknown')
        block_safe = self._sanitize_filename(block)
        fname = f"step_{pos:02d}_{sid}_{block_safe}.json"
        self.save_json(step, parent_dir, fname)

# ----------------------------------------------------------------------
# RUN
# ----------------------------------------------------------------------
if __name__ == '__main__':
    try:
        client = StepikClient()
        topic = 'Python'
        courses = client.search_public_free_courses(topic, limit=1)
        if not courses:
            print('Курсы не найдены')
        else:
            for c in courses:
                client.process_course(c)
            print('Готово')
    except Exception as e:
        print(f"Критическая ошибка: {e}")
