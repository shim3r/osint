# osint-wayback-phish

Небольшой учебный OSINT-проект для скачивания архивных HTML/страниц из Wayback Machine через CDX API
и автоматического поиска признаков фишинга/мошенничества в коде.

## Возможности
- Получает список URL через CDX API (с датами, mimetype, digest, length)
- Скачивает "сырые" копии через /web/<timestamp>id_/
- Сохраняет файлы в "wayback_dump/"
- Делает отчёт "wayback_dump/findings.json":
  - email-адреса в HTML/JS
  - form action
  - внешние URL
  - признаки редиректа
  - признаки сбора credentials (password/cvv/etc)
  - sha256, размер, метаданные CDX

## Установка
Рекомендуется использовать виртуальное окружение.


python3 -m venv venv
source venv/bin/activate
python -m pip install -r requirements.txt
