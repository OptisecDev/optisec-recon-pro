# OPTISEC Recon Pro — Session Log

## المنجز (جلسة 2026-06-29)

### ✅ المهمة 1 — Dashboard احترافي
- Welcome header مع ساعة حية وتاريخ عربي
- Threat Level Gauge متحرك (SVG) يحسب مستوى التهديد تلقائياً
- 6 بطاقات إحصائية pro مع عدادات متحركة (targets/scans/findings/critical/reports/AI)
- Chart.js: Donut chart لتوزيع الثغرات + Line chart لنشاط الفحص آخر 7 أيام
- Quick Scan محسّن مع chip selectors لأنواع الفحص
- Quick Actions Grid — 16 وحدة بنقرة واحدة
- Recent Scans جدول محسّن + System Status + Live Activity Feed
- Backend: أُضيفت استعلامات critical_count، high_count، medium_count، low_count، report_count، done_scans

### ✅ المهمة 2 — توثيق API (Swagger/OpenAPI)
- `web/schemas.py` — 25+ Pydantic models (LoginRequest/Response، ScanRequest، FindingResponse، NLPRequest، إلخ)
- FastAPI metadata كاملة: وصف markdown، contact، license، 23 openapi_tags مع وصف تفصيلي
- توثيق 20+ endpoint رئيسي بـ tags + summary + description + responses
- Swagger UI بثيم OPTISEC المخصص (dark #0d1117، أخضر #00ff88) على `/docs`
- ReDoc على `/redoc` بثيم OPTISEC
- صفحة `/api-docs` في الـ Web UI مع Quick Start أكواد curl، جدول الأدوار، WebSocket guide، قائمة 149 endpoint قابلة للبحث، عرض API Key
- رابطان في السايدبار: API Docs + Swagger UI ↗

### ✅ المهمة 3 — نظام الترخيص
- `web/license.py` — محرك ترخيص كامل:
  - 3 مستويات: FREE / PRO / ENTERPRISE
  - توليد مفاتيح بصيغة `OPS4-{TIER}-{base64}.{hmac16}`
  - تحقق HMAC-SHA256 (أي تعديل يُكشف فوراً)
  - 32 ميزة مصنّفة، حدود targets/scans/users لكل مستوى
  - Persistence في `data/license.json`
  - دالة `require_feature()` للتحقق في الـ routes
- `web/templates/license.html` — صفحة إدارة: Hero بلون المستوى، نموذج تفعيل، جدول مقارنة، مولّد مفاتيح (admin فقط)
- Routes: GET/POST /license/activate، POST /license/deactivate، /api/license/activate، /api/license/generate، /api/license/status
- Sidebar: شارة ملونة للمستوى، تحذير انتهاء الصلاحية < 30 يوم، أيقونة 🔒 على الميزات المحجوبة
- Topbar: Pill يعرض المستوى + الأيام المتبقية
- `templates.env.globals["get_license"]` — متاح في كل template

**الترخيص الحالي المُفعَّل:**
- Tier: PRO
- Issued to: Ehsan Ali (ahssanali84.syber@gmail.com)
- Expires: 2027-06-29 (364 يوم)
- مفتاح التفعيل محفوظ في `data/license.json`

### ✅ المهمة 4 — Demo عام
- `web/templates/landing.html` — صفحة Landing عامة كاملة:
  - Hero مع animations وglow وgrid dots
  - Stats bar: 149 endpoints، 13 وحدة، 32 ميزة
  - Dashboard mockup مرئي (CSS فقط)
  - 12 Feature Card مع ألوان وشارات
  - 4 خطوات "كيف يعمل"
  - جدول أسعار FREE / PRO $149 / ENTERPRISE
  - CTA section
- `/` بدون auth → صفحة Landing (بدلاً من redirect للـ login)
- `/landing` — صفحة Landing مباشرة
- `/demo` — دخول فوري بنقرة واحدة (يُنشئ session للـ demo user)
- Demo Account (`demo` / `Demo@optisec1`):
  - يُنشأ تلقائياً عند startup
  - 5 أهداف: tesla/google/microsoft/apple/amazon
  - 5 فحوصات كاملة، 8 ثغرات (2 critical، 3 high، 2 medium، 1 low)
  - Role: analyst
- Demo Banner أخضر في أعلى كل صفحة لمستخدم الديمو
- Login page محسّنة: Demo Box بارز + زر "ادخل الديمو الآن"

---

## الملفات الجديدة/المعدّلة

| الملف | التغيير |
|-------|---------|
| `web/app.py` | FastAPI metadata، license routes، demo routes، /api-docs، optional_user، demo seeder |
| `web/schemas.py` | **جديد** — 25+ Pydantic models |
| `web/license.py` | **جديد** — محرك الترخيص الكامل |
| `web/templates/index.html` | إعادة كتابة كاملة — Dashboard احترافي |
| `web/templates/base.html` | license badge، demo banner، nav links |
| `web/templates/license.html` | **جديد** — صفحة إدارة الترخيص |
| `web/templates/landing.html` | **جديد** — صفحة Landing عامة |
| `web/templates/login.html` | Demo Box + Try Demo button |
| `web/templates/api_docs.html` | **جديد** — صفحة API docs في الـ web UI |
| `web/static/css/style.css` | Dashboard pro، license، demo banner، API docs CSS |
| `data/license.json` | ترخيص PRO مُفعَّل |

---

## معلومات المشروع
- Admin: admin / Optisec123!
- Demo: demo / Demo@optisec1
- Launch: `source venv/bin/activate && python -m uvicorn web.app:app --host 0.0.0.0 --port 8000`
- أو: `./start.sh web`
- Path: /home/ehsan/projects/optisec-recon-pro
- Swagger: http://localhost:8000/docs
- API Docs: http://localhost:8000/api-docs
- Landing: http://localhost:8000/landing

## المنجز (جلسة 2026-07-01)

### ✅ المهمة 5 — Dark Web Monitoring (رصد تسريبات البيانات)
- `modules/darkweb/monitor.py` — **جديد**: طبقة مراقبة مستمرة فوق `modules/osint/darkweb_intelligence.py`:
  - LeakCheck API (نفس `LEAKCHECK_API_KEY`/endpoints من مشروع Account Recovery في `unified_engine.py`) — عام بدون مفتاح، وأغنى بالتفاصيل مع مفتاح
  - `build_leak_events()` — يحوّل breaches/pastes/github_exposures/threat_actors/leakcheck إلى أحداث تسريب موحّدة ببصمة (`fingerprint`) ثابتة
  - `diff_new_events()` — يقارن الأحداث الحالية بالبصمات المخزّنة مسبقاً، فلا يتكرر التنبيه على نفس التسريب
  - `run_monitor_check()` — ينسّق darkweb_intelligence + LeakCheck بالتوازي، لا يفشل أبداً
  - دعم عربي كامل: `SOURCE_LABELS_AR` / `SEVERITY_LABELS_AR` / `EXPOSURE_LEVEL_AR` / `build_arabic_alert_message()`
- `web/models.py` — جدولان جديدان: `DarkWebMonitor` (الأهداف المراقبة) و`DarkWebAlert` (التنبيهات المخزّنة، بصمة + طابع زمني)
- `web/routers/darkweb_monitor.py` — **جديد**: `GET/POST /api/darkweb/monitor`، `DELETE /api/darkweb/monitor/{id}`، `POST /api/darkweb/monitor/{id}/check`، `GET /api/darkweb/monitor/{id}/alerts`، `GET /api/darkweb/monitor/alerts/recent`
- `web/routers/darkweb.py` — `darkweb_home()` يمرّر الآن `monitors` و`recent_alerts` للقالب
- `web/templates/darkweb.html` — تبويب سادس "Continuous Monitoring · المراقبة المستمرة": إضافة هدف، فحص فوري، حذف، وعرض التنبيهات الأخيرة بعناوين عربية
- `tests/test_darkweb_monitor.py` — **جديد**: 38 اختبار (LeakCheck، fingerprinting، build_leak_events، diff_new_events، التعريب، run_monitor_check) — نفس معيار `test_vulnerability_intelligence.py`
- **356/356 اختبار ناجح** على كامل test suite (لا regressions)

---

## المهام القادمة (جلسات مستقبلية)
- [ ] اختبار شامل وإصلاح أي bugs
- [ ] نشر على VPS / Docker
- [ ] إضافة email notifications
- [ ] تحسين أداء الفحوصات الموازية
- [ ] جدولة فحص دوري تلقائي لأهداف Dark Web Monitoring (apscheduler موجود كـ dependency لكن غير مُفعّل بعد)
