"""Браузерная проверка панели: запускает сервер с тестовыми данными, проходит основные сценарии, делает скриншоты."""
import subprocess, time, sys, os, re
from playwright.sync_api import sync_playwright
root = os.path.dirname(os.path.abspath(__file__))
srv = subprocess.Popen(['node', os.path.join(root, 'seed_and_serve.js')], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
try:
    line = srv.stdout.readline()
    assert line.startswith('READY'), line
    out = os.environ.get('SHOTS', '/tmp')
    errs = []
    with sync_playwright() as p:
        b = p.chromium.launch(); pg = b.new_page(viewport={'width': 1280, 'height': 800})
        pg.on('console', lambda m: errs.append(m.text) if m.type == 'error' else None); pg.on('pageerror', lambda e: errs.append(str(e)))
        pg.goto('http://127.0.0.1:18099/panel/')
        pg.fill('#l-login', 'owner'); pg.fill('#l-pass', 'wrong'); pg.click('button[type=submit]'); pg.wait_for_selector('#toast.show.err')
        pg.fill('#l-pass', 'Owner-pass-12345'); pg.click('button[type=submit]'); pg.wait_for_selector('table')
        assert 'Платный HUD' in pg.inner_text('main') and 'Бесплатный HUD' in pg.inner_text('main')
        pg.screenshot(path=f'{out}/panel_list.png')
        pg.click('text=HUD-', strict=False) if False else None
        pg.locator('a.link').first.click(); pg.wait_for_selector('text=Покупатели')
        txt = pg.inner_text('main')
        assert 'попыток с других ПК: 3' in txt, txt
        assert re.search(r'PC-[0-9a-f]{12}', txt) and 'Хакер &amp; Co' in txt  # спецсимволы показаны буквально, не интерпретируются
        pg.screenshot(path=f'{out}/panel_detail.png')
        pg.once('dialog', lambda d: d.accept('слив худа')); pg.locator('button:has-text("Отключить ключ")').first.click(); pg.wait_for_selector('text=слив худа')
        pg.locator('button:has-text("Включить")').first.click(); pg.wait_for_selector('text=работает'); pg.wait_for_load_state('networkidle')
        pg.fill('#lic-label', 'Новый покупатель'); pg.click('button:has-text("Выдать")'); pg.wait_for_selector('.key')
        key = pg.inner_text('.key'); assert key.startswith('PTK-'), key
        with pg.expect_download() as dl: pg.click('text=Скачать HudLoader.build')
        assert dl.value.suggested_filename == 'HudLoader.build'
        pg.screenshot(path=f'{out}/panel_issued.png')
        pg.once('dialog', lambda d: d.accept()); pg.locator('button:has-text("Отключить HUD")').click(); pg.wait_for_selector('text=Включить HUD')
        assert 'отключён' in pg.inner_text('main')
        pg.click('text=К списку'); pg.wait_for_selector('table'); pg.screenshot(path=f'{out}/panel_list_after.png')
        pg.click('text=Журнал'); pg.wait_for_selector('text=Журнал событий'); assert 'hud_disable' in pg.inner_text('main')
        b.close()
    errs = [e for e in errs if '401' not in e]   # 401 ожидаем: тест намеренно вводит неверный пароль
    assert not errs, errs
    print('PANEL E2E OK')
finally:
    srv.terminate()
