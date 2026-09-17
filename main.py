import os
import io
import re
import json
import base64
import asyncio
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, List
from urllib.parse import urljoin

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx
from PIL import Image, ImageDraw, ImageFont
from playwright.sync_api import sync_playwright

# --- AYARLAR VE YAPILANDIRMA ---
# Anahtari kod icine gommek yerine ortam degiskeninden okuyoruz.
DEEPL_API_KEY = os.environ.get("DEEPL_API_KEY", "0e5a2641-3117-427f-a75a-2e52fad165e1:fx")
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "app_data.db")

# "Beni hatırla" işaretliyse token uzun ömürlü (30 gün), değilse kısa ömürlü (1 gün) olur.
REMEMBER_ME_DAYS = 30
DEFAULT_SESSION_DAYS = 1

app = FastAPI(title="Manga Translator Engine (Anti-Scramble)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --- ISTEK MODELLERI ---
class MangaTranslateRequest(BaseModel):
    url: str
    title: Optional[str] = "Untitled"
    layout: Optional[str] = "webtoon"
    source_lang: Optional[str] = "en"
    target_lang: Optional[str] = "tr"


class GetChapterImagesRequest(BaseModel):
    url: str


class TranslateBatchRequest(BaseModel):
    image_urls: List[str]
    source_lang: Optional[str] = "en"
    target_lang: Optional[str] = "tr"


class RegisterRequest(BaseModel):
    username: str
    password: str
    remember_me: Optional[bool] = True


class LoginRequest(BaseModel):
    username: str
    password: str
    remember_me: Optional[bool] = True


class LibrarySaveRequest(BaseModel):
    library: List[dict]


# --- HESAP SISTEMI: VERITABANI ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            expires_at TEXT,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    # Eski veritabanlarında expires_at sütunu olmayabilir, varsa sorun cikarmadan gecer.
    try:
        conn.execute("ALTER TABLE sessions ADD COLUMN expires_at TEXT")
    except sqlite3.OperationalError:
        pass
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS libraries (
            user_id INTEGER PRIMARY KEY,
            data TEXT NOT NULL DEFAULT '[]',
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
        """
    )
    conn.commit()
    conn.close()


init_db()


def hash_password(password: str, salt: Optional[str] = None):
    if salt is None:
        salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    ).hex()
    return pwd_hash, salt


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    test_hash, _ = hash_password(password, salt)
    return secrets.compare_digest(test_hash, stored_hash)


def create_session(conn, user_id: int, remember_me: bool = True) -> str:
    """Yeni oturum tokenı üretir. remember_me=True ise 30 gün, değilse 1 gün geçerli olur."""
    token = secrets.token_hex(32)
    days = REMEMBER_ME_DAYS if remember_me else DEFAULT_SESSION_DAYS
    expires_at = (datetime.utcnow() + timedelta(days=days)).isoformat()
    conn.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
        (token, user_id, expires_at),
    )
    return token


async def get_current_user(authorization: Optional[str] = Header(None)) -> int:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Yetkilendirme başlığı eksik")
    token = authorization.split(" ", 1)[1].strip()
    conn = get_db()
    row = conn.execute(
        "SELECT user_id, expires_at FROM sessions WHERE token = ?", (token,)
    ).fetchone()

    if not row:
        conn.close()
        raise HTTPException(status_code=401, detail="Geçersiz veya süresi dolmuş oturum")

    # Süresi dolmuşsa oturumu sil ve reddet
    if row["expires_at"]:
        try:
            expires_at = datetime.fromisoformat(row["expires_at"])
        except ValueError:
            expires_at = None
        if expires_at and datetime.utcnow() > expires_at:
            conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
            conn.commit()
            conn.close()
            raise HTTPException(status_code=401, detail="Oturum süresi doldu, lütfen tekrar giriş yapın")

    conn.close()
    return row["user_id"]


# --- HESAP SISTEMI: ENDPOINT'LER ---
@app.post("/api/register")
def register(payload: RegisterRequest):
    username = payload.username.strip()
    password = payload.password

    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Kullanıcı adı en az 3 karakter olmalı")
    if len(password) < 4:
        raise HTTPException(status_code=400, detail="Şifre en az 4 karakter olmalı")

    conn = get_db()
    existing = conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(status_code=400, detail="Bu kullanıcı adı zaten alınmış")

    pwd_hash, salt = hash_password(password)
    cursor = conn.execute(
        "INSERT INTO users (username, password_hash, salt) VALUES (?, ?, ?)",
        (username, pwd_hash, salt),
    )
    user_id = cursor.lastrowid
    conn.execute("INSERT INTO libraries (user_id, data) VALUES (?, ?)", (user_id, "[]"))
    token = create_session(conn, user_id, remember_me=payload.remember_me if payload.remember_me is not None else True)
    conn.commit()
    conn.close()

    return {"status": "success", "token": token, "username": username}


@app.post("/api/login")
def login(payload: LoginRequest):
    username = payload.username.strip()

    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    if not row or not verify_password(payload.password, row["salt"], row["password_hash"]):
        conn.close()
        raise HTTPException(status_code=401, detail="Kullanıcı adı veya şifre hatalı")

    token = create_session(conn, row["id"], remember_me=payload.remember_me if payload.remember_me is not None else True)
    conn.commit()
    conn.close()

    return {"status": "success", "token": token, "username": username}


@app.post("/api/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1].strip()
        conn = get_db()
        conn.execute("DELETE FROM sessions WHERE token = ?", (token,))
        conn.commit()
        conn.close()
    return {"status": "success"}


@app.get("/api/me")
def me(user_id: int = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Kullanıcı bulunamadı")
    return {"status": "success", "username": row["username"]}


@app.get("/api/library")
def get_library(user_id: int = Depends(get_current_user)):
    conn = get_db()
    row = conn.execute("SELECT data FROM libraries WHERE user_id = ?", (user_id,)).fetchone()
    conn.close()
    library = json.loads(row["data"]) if row and row["data"] else []
    return {"status": "success", "library": library}


@app.post("/api/library")
def save_library(payload: LibrarySaveRequest, user_id: int = Depends(get_current_user)):
    conn = get_db()
    data_str = json.dumps(payload.library, ensure_ascii=False)
    conn.execute(
        """
        INSERT INTO libraries (user_id, data) VALUES (?, ?)
        ON CONFLICT(user_id) DO UPDATE SET data = excluded.data
        """,
        (user_id, data_str),
    )
    conn.commit()
    conn.close()
    return {"status": "success"}


# --- OCR LAZY LOADING ---
ocr_reader = None


def get_ocr_reader():
    global ocr_reader
    if ocr_reader is None:
        import easyocr

        ocr_reader = easyocr.Reader(["en"], gpu=False)
    return ocr_reader


# ============================================================================
# 1. SCRAPER
#    Mantik: once eski surumdeki URL toplama yontemleri (network + script JSON
#    + kaydirarak DOM tarama) calisir. Ayrica sayfanin "yapboz korumasi"
#    kullanip kullanmadigi tespit edilir; kullaniyorsa URL'ler degil, tarayicida
#    COZULMUS HALI (canvas toDataURL ya da element screenshot) alinir.
# ============================================================================

IGNORE_KEYWORDS = [
    "cover", "poster", "thumb", "avatar", "banner", "logo", "title", "icon",
    "advertisement", "favicon", "discord", "social", "button", "widgets",
    "analytics", "tracking", "loader", "spinner", "site-assets", "sprite",
]

BROWSER_ARGS = [
    "--disable-blink-features=AutomationControlled",
    "--no-sandbox",
    "--disable-setuid-sandbox",
    "--disable-infobars",
    # ---- YAPBOZ COZUMUNUN ANAHTARI ----
    # Bu bayraklar olmadan, farkli domainden gelen parcalarla cizilen canvas
    # "tainted" (kirli) sayilir ve toDataURL() SecurityError firlatir. O zaman
    # kod karisik haldeki ham URL'e geri dusuyor ve sonuc yapboz gibi geliyor.
    "--disable-web-security",
    "--allow-running-insecure-content",
    "--disable-features=IsolateOrigins,site-per-process",
    "--window-size=1600,2000",
]

# Sayfanin yapboz (scramble) korumasi kullanip kullanmadigini anlayan tespit
JS_DETECT_SCRAMBLE = """
() => {
    // 1) Buyuk canvas varsa neredeyse kesin olarak JS ile yeniden ciziliyor
    for (const c of document.querySelectorAll('canvas')) {
        if (c.width > 250 && c.height > 250) return 'canvas';
    }
    // 2) Ayni background-image'i paylasan cok sayida kucuk kutu = CSS karo yapboz
    const bgCount = {};
    for (const d of document.querySelectorAll('div, span, i')) {
        const bg = getComputedStyle(d).backgroundImage;
        if (bg && bg !== 'none' && bg.indexOf('url(') === 0) {
            bgCount[bg] = (bgCount[bg] || 0) + 1;
        }
    }
    for (const k in bgCount) { if (bgCount[k] >= 6) return 'css-tiles'; }
    // 3) img uzerinde clip-path / transform ile parcalama
    let clipped = 0;
    for (const im of document.querySelectorAll('img')) {
        const st = getComputedStyle(im);
        if (st.clipPath && st.clipPath !== 'none') clipped++;
    }
    if (clipped >= 6) return 'clip';
    return '';
}
"""

# Tum gorsellerin gercekten yuklendigini dogrula (gri placeholder cekmemek icin)
JS_IMAGES_READY = """
() => {
    const imgs = Array.from(document.querySelectorAll('img'))
        .filter(i => i.clientWidth > 250 && i.clientHeight > 200);
    if (imgs.length === 0) return true;
    return imgs.every(i => i.complete && i.naturalWidth > 0);
}
"""


def _smart_scroll_and_harvest(page, chapter_url: str) -> List[str]:
    """Sayfayi kademeli kaydirarak DOM'daki tum img kaynaklarini toplar."""
    dom_urls: List[str] = []
    dom_seen = set()

    def harvest():
        imgs = page.evaluate(
            """() => Array.from(document.querySelectorAll('img')).map(i =>
                    i.currentSrc || i.src ||
                    i.getAttribute('data-src') ||
                    i.getAttribute('data-lazy-src') ||
                    i.getAttribute('data-original') ||
                    i.getAttribute('srcset')
               ).filter(Boolean)"""
        )
        for raw in imgs:
            if not isinstance(raw, str):
                continue
            if " " in raw and raw.startswith("http"):
                raw = raw.split(" ")[0]
            full = urljoin(chapter_url, raw.strip())
            if not full.startswith("http"):
                continue
            if any(kw in full.lower() for kw in IGNORE_KEYWORDS):
                continue
            if full not in dom_seen:
                dom_seen.add(full)
                dom_urls.append(full)

    last_count, stagnant = 0, 0
    for _ in range(150):
        harvest()
        if len(dom_urls) > last_count:
            last_count = len(dom_urls)
            stagnant = 0
        else:
            stagnant += 1
            if stagnant >= 6:
                break

        page.keyboard.press("PageDown")
        page.mouse.wheel(0, 1500)
        page.evaluate(
            """() => {
                window.scrollBy(0, 1500);
                document.querySelectorAll('div, main, section, article').forEach(el => {
                    if (el.scrollHeight > el.clientHeight && el.clientHeight > 200) {
                        el.scrollTop += 1500;
                    }
                });
            }"""
        )
        page.wait_for_timeout(400)

    harvest()
    return dom_urls


def _harvest_script_json(page, chapter_url: str) -> List[str]:
    """__NEXT_DATA__ ve diger script bloklarindan gorsel URL'lerini cikarir."""
    found: List[str] = []
    seen = set()
    try:
        scripts_data = page.evaluate(
            """() => {
                const out = [];
                const nextEl = document.getElementById('__NEXT_DATA__');
                if (nextEl && nextEl.textContent) out.push(nextEl.textContent);
                document.querySelectorAll('script').forEach(s => {
                    if (s.textContent && (s.textContent.includes('image') ||
                        s.textContent.includes('chapter') || s.textContent.includes('page'))) {
                        out.push(s.textContent);
                    }
                });
                return out;
            }"""
        )
        for raw_script in scripts_data:
            matches = re.findall(
                r'"([^"]+?\.(?:jpg|jpeg|png|webp|avif)(?:\?[^"]*)?)"',
                raw_script,
                re.IGNORECASE,
            )
            for m in matches:
                full = urljoin(chapter_url, m.strip().replace("\\/", "/"))
                if not full.startswith("http"):
                    continue
                if any(kw in full.lower() for kw in IGNORE_KEYWORDS):
                    continue
                if full not in seen:
                    seen.add(full)
                    found.append(full)
    except Exception as err:
        print(f"[SCRAPER] Script/JSON çıkarma hatası: {err}")
    return found


def _capture_rendered_pages(page) -> List[str]:
    """
    Yapboz korumali sayfalarda kullanilir.
    Tarayicida COZULMUS haldeki gorseli base64 olarak alir:
      1) canvas ise toDataURL (hizli, kayipsiz, tam cozunurluk)
      2) olmazsa element screenshot (CSS karo / clip-path yapbozlari icin)
    DOM sirasina gore gezildigi icin sayfa sirasi korunur.
    """
    captured: List[str] = []

    # Tum sayfalar cizilmis mi diye bekle
    try:
        page.wait_for_function(JS_IMAGES_READY, timeout=15000)
    except Exception:
        pass
    page.wait_for_timeout(2500)  # descramble scriptinin cizimi bitirmesi icin

    elements = page.locator("canvas, img").all()
    for el in elements:
        try:
            box = el.bounding_box()
            if not box or box["width"] < 300 or box["height"] < 250:
                continue

            el.scroll_into_view_if_needed(timeout=3000)
            page.wait_for_timeout(120)

            data_url = None

            # --- 1) Canvas yolu ---
            try:
                data_url = el.evaluate(
                    """el => {
                        if (el.tagName !== 'CANVAS') return null;
                        try { return el.toDataURL('image/jpeg', 0.92); }
                        catch (e) { return null; }   // tainted canvas
                    }"""
                )
            except Exception:
                data_url = None

            # --- 2) Element screenshot yolu (canvas olmayan / tainted durumlar) ---
            if not data_url:
                # Cok uzun webtoon seritleri Chromium'un 16384px sinirini asabilir
                if box["height"] > 15000:
                    print(f" [!] Element çok uzun ({int(box['height'])}px), atlanıyor.")
                    continue
                shot = el.screenshot(type="jpeg", quality=92, timeout=20000)
                data_url = "data:image/jpeg;base64," + base64.b64encode(shot).decode("utf-8")

            if data_url and len(data_url) > 5000:  # bos/gri kareleri ele
                captured.append(data_url)
                print(f" [+] Çözülmüş sayfa {len(captured)} yakalandı.")
        except Exception:
            continue

    return captured


def scrape_manga_images(chapter_url: str) -> List[str]:
    if any(chapter_url.lower().endswith(ext) for ext in [".jpg", ".jpeg", ".png", ".webp", ".avif"]):
        return [chapter_url]

    print(f"\n[SCRAPER] Hedef URL taranıyor: {chapter_url}")

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=BROWSER_ARGS)
            context = browser.new_context(
                user_agent=(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
                ),
                viewport={"width": 1600, "height": 2000},
                bypass_csp=True,
                ignore_https_errors=True,
            )
            page = context.new_page()

            # --- Network dinleyicisi (eski koddaki yontem) ---
            network_urls: List[str] = []
            network_seen = set()

            def handle_response(response):
                try:
                    url = response.url
                    ctype = response.headers.get("content-type", "").lower()
                    is_img = "image" in ctype or any(
                        ext in url.lower() for ext in [".webp", ".jpg", ".jpeg", ".png", ".avif"]
                    )
                    if is_img and response.status in (200, 304):
                        if not any(kw in url.lower() for kw in IGNORE_KEYWORDS):
                            if url not in network_seen:
                                network_seen.add(url)
                                network_urls.append(url)
                except Exception:
                    pass

            page.on("response", handle_response)

            try:
                page.goto(chapter_url, wait_until="domcontentloaded", timeout=45000)
            except Exception as e:
                print(f"[SCRAPER UYARI] Sayfa yükleme zaman aşımı: {e}")

            page.wait_for_timeout(2500)

            json_urls = _harvest_script_json(page, chapter_url)

            print("[SCRAPER] Dinamik kaydırma başlatılıyor...")
            dom_urls = _smart_scroll_and_harvest(page, chapter_url)

            # --- YAPBOZ TESPITI ---
            scramble_mode = ""
            try:
                scramble_mode = page.evaluate(JS_DETECT_SCRAMBLE) or ""
            except Exception:
                pass

            final_list: List[str] = []

            if scramble_mode:
                print(f"[SCRAPER] Yapboz koruması tespit edildi ({scramble_mode}). "
                      f"Çözülmüş görüntüler yakalanıyor...")
                rendered = _capture_rendered_pages(page)
                # Yapboz varsa ham URL'ler karisik gelir; ONLARI KARISTIRMIYORUZ.
                if rendered:
                    final_list = rendered
                else:
                    print("[SCRAPER UYARI] Çözülmüş görüntü alınamadı, ham URL'lere dönülüyor.")

            if not final_list:
                # Yapboz yok (ya da yakalama basarisiz): eski, calisan URL yontemi
                combined = dom_urls + json_urls + network_urls
                final_list = list(dict.fromkeys(combined))

            browser.close()

            print(f"[SCRAPER SUCCESS] Toplam {len(final_list)} sayfa tespit edildi.")
            return final_list

    except Exception as e:
        print(f"[SCRAPER ERROR] Hata oluştu: {str(e)}")
        return []


# 2. SATIR BIRLESTIRICI
def merge_ocr_lines(results, y_threshold=12):
    if not results:
        return []

    sorted_results = sorted(results, key=lambda r: r[0][0][1])
    clusters = []

    for bbox, text, prob in sorted_results:
        min_y = min(p[1] for p in bbox)
        max_y = max(p[1] for p in bbox)
        min_x = min(p[0] for p in bbox)
        max_x = max(p[0] for p in bbox)

        merged = False
        for c in clusters:
            c_max_y = max(p[1] for box in c["bboxes"] for p in box)
            c_min_x = min(p[0] for box in c["bboxes"] for p in box)
            c_max_x = max(p[0] for box in c["bboxes"] for p in box)

            if abs(min_y - c_max_y) < y_threshold and not (max_x < c_min_x or min_x > c_max_x):
                c["texts"].append(text)
                c["bboxes"].append(bbox)
                c["probs"].append(prob)
                merged = True
                break

        if not merged:
            clusters.append({"texts": [text], "bboxes": [bbox], "probs": [prob]})

    merged_results = []
    for c in clusters:
        full_text = " ".join(c["texts"])
        all_x = [p[0] for box in c["bboxes"] for p in box]
        all_y = [p[1] for box in c["bboxes"] for p in box]
        merged_bbox = [
            [min(all_x), min(all_y)],
            [max(all_x), min(all_y)],
            [max(all_x), max(all_y)],
            [min(all_x), max(all_y)],
        ]
        avg_prob = sum(c["probs"]) / len(c["probs"])
        merged_results.append((merged_bbox, full_text, avg_prob))

    return merged_results


# 3. SFX VE ANLATICI FILTRESI
def filter_sfx_and_narratives(ocr_results):
    filtered = []
    sfx_words = {
        "vwoom", "wham", "boom", "bam", "thud", "whoosh", "ha", "oh", "uh",
        "aom", "kka", "wow", "gasp", "sigh", "crash", "tap",
    }

    for bbox, text, prob in ocr_results:
        clean_t = text.strip()
        text_lower = clean_t.lower()

        if len(clean_t) <= 1 or text_lower in sfx_words:
            continue

        box_w = max(p[0] for p in bbox) - min(p[0] for p in bbox)
        box_h = max(p[1] for p in bbox) - min(p[1] for p in bbox)

        if box_w < 18 or box_h < 10:
            continue

        if len(clean_t.split()) == 1 and clean_t.isupper() and len(clean_t) <= 4:
            continue

        filtered.append((bbox, clean_t, prob))
    return filtered


# 4. DEEPL XML BAGLAMSAL CEVIRI
def translate_batch_texts(texts: List[str], source_lang: str = "en", target_lang: str = "tr") -> List[str]:
    if not texts:
        return []

    cleaned_texts = [re.sub(r"\s+", " ", t).strip() for t in texts]
    if not any(cleaned_texts):
        return [""] * len(texts)

    tagged_input = ""
    for idx, txt in enumerate(cleaned_texts):
        tagged_input += f"<b{idx}>{txt}</b{idx}> "

    try:
        url = "https://api-free.deepl.com/v2/translate"
        headers = {
            "Authorization": f"DeepL-Auth-Key {DEEPL_API_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "text": [tagged_input.strip()],
            "target_lang": target_lang.upper(),
            "source_lang": source_lang.upper(),
            "tag_handling": "xml",
        }

        with httpx.Client(timeout=20.0) as client:
            response = client.post(url, json=payload, headers=headers)
            if response.status_code == 200:
                translated_xml = response.json()["translations"][0]["text"]
                translations = [""] * len(cleaned_texts)

                matches = re.findall(r"<b(\d+)>(.*?)</b\1>", translated_xml, re.DOTALL)
                for idx_str, tr_txt in matches:
                    idx = int(idx_str)
                    if idx < len(translations):
                        translations[idx] = tr_txt.strip().upper()

                for i in range(len(translations)):
                    if not translations[i]:
                        translations[i] = cleaned_texts[i].upper()

                print(f"[DEEPL ÇEVİRİ BAŞARILI] {len(translations)} baloncuk çevrildi.")
                return translations
            else:
                print(f"[DEEPL HATA KODU]: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"[DEEPL BAĞLANTI HATASI]: {e}")

    return [t.upper() for t in cleaned_texts]


# 5. FONT VE DINAMIK YAZI SIGDIRMA
def get_turkish_font(font_size: int):
    font_paths = [
        "arial.ttf",
        "DejaVuSans.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
        "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
        "C:\\Windows\\Fonts\\arial.ttf",
        "C:\\Windows\\Fonts\\calibri.ttf",
    ]
    for p in font_paths:
        try:
            return ImageFont.truetype(p, font_size)
        except Exception:
            continue
    return ImageFont.load_default()


def wrap_text_for_box(text: str, font, max_width: int, draw: ImageDraw.ImageDraw) -> List[str]:
    words = text.split()
    if not words:
        return []
    lines, current_line = [], []

    for word in words:
        test_line = " ".join(current_line + [word])
        try:
            bbox = draw.textbbox((0, 0), test_line, font=font)
            w = bbox[2] - bbox[0]
        except Exception:
            w = len(test_line) * (font.size * 0.5 if hasattr(font, "size") else 6)

        if w <= max_width or not current_line:
            current_line.append(word)
        else:
            lines.append(" ".join(current_line))
            current_line = [word]

    if current_line:
        lines.append(" ".join(current_line))
    return lines


def fit_text_in_box(text: str, max_w: int, max_h: int, draw: ImageDraw.ImageDraw):
    max_w, max_h = max(15, max_w), max(15, max_h)
    font_size = min(max_h, 28)
    min_font_size = 8

    while font_size >= min_font_size:
        font = get_turkish_font(font_size)
        lines = wrap_text_for_box(text, font, max_w, draw)
        line_height = font_size + 2
        total_h = len(lines) * line_height

        if total_h <= max_h or font_size == min_font_size:
            return font, lines, font_size, total_h
        font_size -= 1

    font = get_turkish_font(min_font_size)
    lines = wrap_text_for_box(text, font, max_w, draw)
    return font, lines, min_font_size, len(lines) * (min_font_size + 2)


# 6. ARKA PLAN VE YAZI RENGI TESPITI
def get_dominant_color(image: Image.Image, bbox):
    min_x = max(0, int(min(p[0] for p in bbox)) - 2)
    max_x = min(image.width - 1, int(max(p[0] for p in bbox)) + 2)
    min_y = max(0, int(min(p[1] for p in bbox)) - 2)
    max_y = min(image.height - 1, int(max(p[1] for p in bbox)) + 2)

    pixels = []
    for x in range(min_x, max_x + 1):
        if x < image.width:
            pixels.extend([image.getpixel((x, min_y)), image.getpixel((x, max_y))])
    for y in range(min_y, max_y + 1):
        if y < image.height:
            pixels.extend([image.getpixel((min_x, y)), image.getpixel((max_x, y))])

    if not pixels:
        return (255, 255, 255)

    r = sum(p[0] for p in pixels) // len(pixels)
    g = sum(p[1] for p in pixels) // len(pixels)
    b = sum(p[2] for p in pixels) // len(pixels)
    return (r, g, b)


def get_text_color_for_bg(bg_color):
    luminance = 0.299 * bg_color[0] + 0.587 * bg_color[1] + 0.114 * bg_color[2]
    return "white" if luminance < 128 else "black"


# 7. RESME TURKCE METIN CIZME
def process_and_draw_translation(image: Image.Image, ocr_results, translated_texts: List[str]) -> Image.Image:
    draw = ImageDraw.Draw(image)

    for (bbox, text, prob), tr_text in zip(ocr_results, translated_texts):
        tr_text = tr_text.strip()
        if not tr_text:
            continue

        x_coords = [p[0] for p in bbox]
        y_coords = [p[1] for p in bbox]
        min_x, max_x = int(min(x_coords)), int(max(x_coords))
        min_y, max_y = int(min(y_coords)), int(max(y_coords))

        box_w, box_h = max(15, max_x - min_x), max(12, max_y - min_y)

        bg_color = get_dominant_color(image, bbox)
        text_color = get_text_color_for_bg(bg_color)

        draw.rectangle([min_x - 2, min_y - 2, max_x + 2, max_y + 2], fill=bg_color)
        font, lines, font_size, total_h = fit_text_in_box(tr_text, box_w, box_h, draw)

        y_start = min_y + (box_h - total_h) / 2
        line_height = font_size + 2

        for idx, line in enumerate(lines):
            try:
                line_w = draw.textbbox((0, 0), line, font=font)[2]
            except Exception:
                line_w = len(line) * (font_size * 0.5)

            x_start = min_x + (box_w - line_w) / 2
            current_y = y_start + (idx * line_height)
            draw.text((x_start, current_y), line, fill=text_color, font=font)

    return image


# 8. TEK BIR RESMI CEVIRME (Base64 destekli)
async def process_single_image(client: httpx.AsyncClient, img_url: str, source_lang: str, target_lang: str):
    bubbles = []
    base64_image_url = ""
    try:
        if img_url.startswith("data:image"):
            header, encoded = img_url.split(",", 1)
            image_bytes = base64.b64decode(encoded)
        else:
            img_resp = await client.get(
                img_url,
                timeout=20.0,
                headers={"Referer": img_url, "User-Agent": "Mozilla/5.0"},
            )
            if img_resp.status_code == 200:
                image_bytes = img_resp.content
            else:
                return img_url, []

        image = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        img_w, img_h = image.size

        reader = get_ocr_reader()
        results = await asyncio.to_thread(reader.readtext, image_bytes)

        valid_results = [
            r for r in results if r[2] > 0.30 and len(re.sub(r"[^a-zA-Z]", "", r[1])) >= 2
        ]

        filtered_results = filter_sfx_and_narratives(valid_results)
        merged_valid_results = merge_ocr_lines(filtered_results)
        raw_texts = [r[1] for r in merged_valid_results]

        translated_texts = translate_batch_texts(raw_texts, source_lang, target_lang)

        processed_image = process_and_draw_translation(image, merged_valid_results, translated_texts)

        buffered = io.BytesIO()
        processed_image.save(buffered, format="JPEG", quality=90)
        b64_encoded = base64.b64encode(buffered.getvalue()).decode("utf-8")
        base64_image_url = f"data:image/jpeg;base64,{b64_encoded}"

        for b_id, ((bbox, orig_text, _), tr_text) in enumerate(
            zip(merged_valid_results, translated_texts), start=1
        ):
            x_coord = float(bbox[0][0]) / img_w if img_w > 0 else 0.0
            y_coord = float(bbox[0][1]) / img_h if img_h > 0 else 0.0

            bubbles.append(
                {
                    "id": b_id,
                    "original_text": orig_text,
                    "translated_text": tr_text,
                    "x": round(x_coord, 4),
                    "y": round(y_coord, 4),
                }
            )
    except Exception as ocr_error:
        print(f"Görsel İşleme Hatası: {ocr_error}")

    final_url = base64_image_url if base64_image_url else img_url
    return final_url, bubbles


# --- API ENDPOINT'LERI (CEVIRI) ---
@app.get("/")
def root():
    return {"status": "ok", "message": "Manga Translator Engine Aktif"}


@app.post("/api/get-chapter-images")
async def get_chapter_images(payload: GetChapterImagesRequest):
    if not payload.url.startswith("http"):
        raise HTTPException(status_code=400, detail="Geçersiz URL formatı")

    extracted_images = await asyncio.to_thread(scrape_manga_images, payload.url)

    if not extracted_images:
        raise HTTPException(status_code=404, detail="Bölüm içi görseller çekilemedi.")

    return {
        "status": "success",
        "total_pages": len(extracted_images),
        "images": extracted_images,
    }


MAX_CONCURRENT_OCR = 4
ocr_semaphore = asyncio.Semaphore(MAX_CONCURRENT_OCR)


async def bounded_process_single_image(client, img_url, s_lang, t_lang):
    async with ocr_semaphore:
        return await process_single_image(client, img_url, s_lang, t_lang)


@app.post("/api/translate-page-batch")
async def translate_page_batch(payload: TranslateBatchRequest):
    if not payload.image_urls:
        return {"status": "success", "pages": []}

    source_lang = payload.source_lang or "en"
    target_lang = payload.target_lang or "tr"

    async with httpx.AsyncClient(
        headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        }
    ) as client:
        tasks = [
            bounded_process_single_image(client, img_url, source_lang, target_lang)
            for img_url in payload.image_urls
        ]
        results = await asyncio.gather(*tasks)

        processed_pages = []
        for index, (img_url, (img_result_url, bubbles)) in enumerate(zip(payload.image_urls, results)):
            processed_pages.append(
                {
                    "page_number": index + 1,
                    "image_url": img_result_url,
                    "translated_image_url": img_result_url,
                    "original_url": img_url if not img_url.startswith("data:image") else "CANVAS_BASE64",
                    "bubbles": bubbles,
                }
            )

    return {"status": "success", "pages": processed_pages}


@app.post("/api/translate-chapter")
async def translate_chapter(payload: MangaTranslateRequest):
    if not payload.url.startswith("http"):
        raise HTTPException(status_code=400, detail="Geçersiz URL formatı")

    extracted_images = await asyncio.to_thread(scrape_manga_images, payload.url)

    if not extracted_images:
        raise HTTPException(status_code=404, detail="Bölüm içi görseller çekilemedi.")

    try:
        processed_pages = []

        async with httpx.AsyncClient(
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "Referer": payload.url,
            }
        ) as client:
            tasks = [
                bounded_process_single_image(client, img_url, payload.source_lang, payload.target_lang)
                for img_url in extracted_images
            ]
            results = await asyncio.gather(*tasks)

            for index, (img_url, (img_result_url, bubbles)) in enumerate(zip(extracted_images, results)):
                processed_pages.append(
                    {
                        "page_number": index + 1,
                        "image_url": img_result_url,
                        "translated_image_url": img_result_url,
                        "original_url": img_url if not img_url.startswith("data:image") else "CANVAS_BASE64",
                        "bubbles": bubbles,
                    }
                )

        return {
            "status": "success",
            "title": payload.title or "İsimsiz Manga",
            "layout": payload.layout,
            "source_lang": payload.source_lang,
            "target_lang": payload.target_lang,
            "pages": processed_pages,
        }

    except HTTPException as http_ex:
        raise http_ex
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"İşlem sırasında hata oluştu: {str(e)}")