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

### ✅ المهمة 6 — جدولة الفحص الدوري التلقائي (APScheduler)
- `modules/darkweb/scheduler.py` — **جديد**: `BackgroundScheduler` (APScheduler) يفحص كل أهداف `DarkWebMonitor` النشطة دورياً:
  - `DARKWEB_SCAN_INTERVAL_HOURS` (افتراضي 24) يتحكم بفاصل الفحص، و`DARKWEB_SCAN_LOCK_STALE_HOURS` (افتراضي 2) يتحكم بمهلة القفل المُهجور
  - **قفل موزّع عبر DB** (`SchedulerLock` — تحديث شرطي ذري) يمنع تكرار الفحص عند تشغيل أكثر من worker/instance — Render يشغّل التطبيق بـ`--workers 2`، فهذا ضروري فعلياً وليس نظرياً
  - كل هدف يُفحص فقط إذا مضى عليه `last_checked_at` أكثر من الفاصل الزمني (استعلام SQL مباشر) — هذا يجعل إعادة النشر/التشغيل على Render آمنة: أول تشغيل بعد كل deploy يجد غالبية الأهداف "غير مستحقة" فلا يُعيد فحصها بلا داعٍ
  - أول تشغيل بعد 60 ثانية من إقلاع التطبيق (حتى يكتمل `init_db`)، ثم كل `DARKWEB_SCAN_INTERVAL_HOURS`
  - يعيد استخدام نفس منطق الفحص/المقارنة/الحفظ المستخدم يدوياً عبر `run_check_and_persist()` (مستخرجة من الراوتر) — تنبيهات جديدة تُضاف لنفس جدول `DarkWebAlert`
  - تسجيل تفصيلي (logging) لكل جولة: عدد المفحوص/المتخطى/الفاشل/التنبيهات الجديدة
- `web/routers/darkweb_monitor.py` — استُخرجت `run_check_and_persist()` كدالة مشتركة بين endpoint الفحص اليدوي والـscheduler؛ أُضيف `GET /api/darkweb/scheduler/status` (running/interval/last_run/next_run)؛ **إصلاح جانبي**: `last_checked_at` كان يُكتب بـ`datetime.now(timezone.utc)` (tz-aware) خلافاً لبقية الجدول (naive) — عمود `DateTime` بدون timezone على Postgres/asyncpg يرفض قيم tz-aware، فتم توحيدها إلى `datetime.utcnow()` قبل أن تُسبب crash في الإنتاج
- `web/models.py` — جدول جديد `SchedulerLock` (job_name PK, locked_at, locked_by)
- `web/app.py` — `start_scheduler()` ضمن `@app.on_event("startup")`، وأُضيف `@app.on_event("shutdown")` جديد (لم يكن موجوداً) يستدعي `stop_scheduler()`
- `tests/test_darkweb_scheduler.py` — **جديد**: 23 اختبار (فاصل الفحص من env، القفل الذري ومقاومته للتكرار وانتهاء صلاحية القفل المُهجور، تحديد الأهداف "المستحقة" فقط، استمرار الجولة رغم فشل هدف واحد، تحرير القفل حتى عند الفشل، تكامل كامل مع حفظ فعلي في DarkWebAlert، عدم تكرار التنبيه على نفس التسريب، دورة حياة start/stop/status) — DB معزولة بالكامل (SQLite in-memory عبر `monkeypatch` لـ`web.database.SessionLocal`)، لا اتصال شبكة حقيقي
- **379/379 اختبار ناجح** على كامل test suite (356 سابق + 23 جديد) — لا regressions

### ✅ المهمة 7 — Honeypot Integration (خدمات مصيدة معزولة)
- `modules/honeypot/listeners.py` — **جديد**: محاكيات خفيفة الوزن لثلاث خدمات (SSH/FTP/HTTP Admin Panel) عبر `asyncio.start_server`:
  - SSH: يرسل banner حقيقي المظهر (`SSH-2.0-OpenSSH_8.9p1...`) ويلتقط أول رسالة من العميل — بدون أي مصافحة SSH حقيقية (لا تشفير، لا مصادقة)
  - FTP: banner بأسلوب vsFTPd، يرد بأكواد استجابة معقولة (331/530/...) على أوامر USER/PASS/QUIT إلخ، ويسجّل كل الأوامر كمحاولة credential-stuffing نموذجية
  - HTTP Admin: صفحة تسجيل دخول وهمية ثابتة (مطابقة لأسلوب `modules/threat_intel/honeypot.py`)، يسجّل method/path/headers (مفلترة)/body
  - كل مقبض (handler) لا يُنفّذ أو يفسّر مدخلات المهاجم أبداً — فقط يقرأ bytes ويسجّلها؛ حدود صارمة (`MAX_PAYLOAD_BYTES`، `FTP_MAX_COMMANDS`، `READ_TIMEOUT_SECONDS`) تمنع استنزاف الذاكرة/الوقت؛ عطل في `on_event` لا يُسقط المستمع (listener) أبداً
- `modules/honeypot/enrichment.py` — **جديد**: إثراء IP المهاجم تلقائياً:
  - Geolocation عبر `modules.osint.geo_intel.geolocate_ip` الموجود أصلاً (ip-api.com + ipinfo.io)
  - AbuseIPDB عبر نفس `ABUSEIPDB_API_KEY` المستخدم في `modules/threat_intel/ioc_detector.py`
  - `risk_level` (LOW/MEDIUM/HIGH/CRITICAL) محسوب من أعلى نتيجة بين abuse score وgeo risk score، مع تعريب كامل (`RISK_LEVELS_AR`) — لا يفشل أبداً حتى لو تعطّل كل مزوّد
- `modules/honeypot/manager.py` — **جديد**: دورة حياة + تخزين:
  - **عزل صارم بالتصميم** (موثّق في docstring المديول): كل خدمة تُربط بمنفذ غير قياسي بعيد تماماً عن أي منفذ حقيقي — SSH:2222، FTP:2121، HTTP:8081 (افتراضياً بعيدة عن 22/21/80/443/8000) — قابلة للتخصيص عبر env، ومعطّلة بالكامل افتراضياً (`HONEYPOT_ENABLED=false`)، مع تفعيل/تعطيل مستقل لكل خدمة
  - `record_event()` — الـ`on_event` callback المشترك بين كل المستمعات: يُثري IP ثم يخزّن `HoneypotEvent` — لا يرمي استثناء أبداً حتى لو فشل الإثراء أو الكتابة في القاعدة
  - `start_honeypots()`/`stop_honeypots()`/`get_status()` — نفس أسلوب lifecycle الموجود في `modules/darkweb/scheduler.py`، لكن كمستمعات asyncio دائمة (لا APScheduler) داخل نفس event loop للتطبيق
- `web/models.py` — جدول جديد `HoneypotEvent` (service، source_ip، source_port، payload، session_data JSON، country/city/isp/abuse_score/risk_level المُثراة، enrichment JSON كامل) — فهرسة مركّبة على `(source_ip, created_at)` بالإضافة لفهرسة كل عمود منفرداً
- `web/routers/honeypot.py` — **جديد**: `GET /api/honeypot/events` (فلترة بـservice/source_ip/risk_level/hours + pagination)، `GET /api/honeypot/stats` (إجماليات، توزيع حسب الخدمة/مستوى الخطورة، أعلى 10 IPs/دول، heatmap 7×24 لآخر 7 أيام)، `GET /api/honeypot/status`، وصفحة `GET /honeypot`. منطق الاستعلام/التجميع (`query_events`، `compute_stats`، `build_heatmap`) دوال منفصلة قابلة للاختبار مباشرة (بنفس أسلوب `run_check_and_persist` في `darkweb_monitor.py`)
- `web/templates/honeypot.html` — **جديد**: حالة المستمعات الحية، 4 بطاقات إحصائية، Chart.js doughnut لتوزيع الخدمات، جدول أعلى IPs، خريطة حرارية CSS بسيطة (7 أيام × 24 ساعة)، جدول المحاولات الأخيرة مع فلترة حية، تحذير أمني بارز بالعربي/الإنجليزي، تعريب كامل لكل تسميات الخدمة/الخطورة
- `web/templates/base.html` — رابط سايدبار جديد تحت "Defense" 🍯
- `web/license.py` — ميزة `honeypot` جديدة (PRO + ENTERPRISE)
- `web/app.py` — تسجيل الراوترين (API + صفحة)، OpenAPI tag، `start_honeypots()`/`stop_honeypots()` في startup/shutdown
- `.env.example` — قسم `HONEYPOT_*` موثّق بالكامل مع تحذير العزل
- `tests/test_honeypot.py` — **جديد**: 74 اختبار — تحليل بروتوكولات نقي (FTP/HTTP)، اختبارات تكامل حقيقية عبر loopback sockets (منافذ OS-assigned، بدون شبكة خارجية) لكل من SSH/FTP/HTTP، إثراء AbuseIPDB/geolocation (mocked)، عتبات risk_level، دورة حياة المدير (تشغيل/إيقاف على منافذ عشوائية)، تخزين الأحداث، استعلامات/تجميع الراوتر، heatmap، تعريب
- **453/453 اختبار ناجح** على كامل test suite (379 سابق + 74 جديد) — لا regressions

---

### ✅ المهمة 8 — Real-time Threat Sharing (مشاركة التهديدات الفورية مع المجتمع)
- `modules/threat_intel/threat_sharing.py` — **جديد**: طبقة تصدير/مشاركة IOCs محلية:
  - `collect_honeypot_iocs()` — عناوين IP للمهاجمين (HIGH/CRITICAL فقط) من `HoneypotEvent` — بنية هجومية بحتة، ليست بيانات عملاء
  - `collect_darkweb_iocs()` — يستخرج فقط رابط الـpaste/GitHub العام من `DarkWebAlert.detail` (`url`/`html_url`)؛ **لا يقرأ أبداً** النطاق/البريد المراقَب (`DarkWebMonitor.target`) — هوية العميل مستبعدة هيكلياً من نتيجة الدالة، لا فلترة لاحقة
  - `collect_vulnerability_iocs()` — CVEs من قائمة CISA KEV العامة (`modules.osint.vulnerability_intelligence._query_cisa_kev`) — **ليس** من جداول Finding/Scan الخاصة بفحوصات العميل، تفادياً لأي تسريب لنتائج فحص
  - `validate_ioc()` — خط الدفاع الأخير: يرفض أي قيمة تحتوي `@` (بريد إلكتروني) بصرف النظر عن النوع المُعلن، ويتحقق من الشكل الصارم لكل نوع (IP/domain/hash MD5-40-64hex/CVE/URL)
  - `build_stix_bundle()` — حزمة STIX 2.1 مبسّطة (بدون اعتماد مكتبة `stix2` غير المثبتة أصلاً) — indicator SDOs بأنماط STIX pattern صحيحة
  - `build_csv()` — تصدير CSV بسيط
  - `share_ioc_to_otx()` / `share_ioc()` — إنشاء OTX pulse لمؤشر واحد (`POST /pulses/create`)؛ `share_ioc()` هو المدخل الوحيد المعتمد: يتحقق من `ENABLE_THREAT_SHARING` أولاً (معطّل افتراضياً)، ثم من صحة المؤشر، ثم من وجود `OTX_API_KEY` — رسائل عربية/إنجليزية في كل حالة، ولا يرمي استثناء أبداً
- `web/models.py` — جدول جديد `ThreatShare` (سجل تدقيق كامل لكل عملية مشاركة: النوع/القيمة/المصدر/الحالة/تفاصيل الاستجابة — بدون أي PII)
- `web/routers/threat_sharing.py` — **جديد**، prefix `/api/threat-feed`:
  - `GET /api/threat-feed` (الاستقبال — نفس منطق `_build_feed` من `threat_feed.py` المُعاد استخدامه، تدفق OTX pulses الحي)
  - `GET /api/threat-feed/status` (هل المشاركة مفعّلة + هل OTX مُهيّأ)
  - `GET /api/threat-feed/local-iocs` (مرشّحو المشاركة المحليون + علامة `already_shared`)
  - `GET /api/threat-feed/export?format=json|csv|stix` (تصدير للقراءة فقط)
  - `GET /api/threat-feed/history` (سجل تدقيق المشاركات)
  - `POST /api/threat-feed/share` (**الموافقة اليدوية الفعلية** — مؤشر واحد في كل طلب، مُشغّل بواسطة مستخدم مسجّل دخوله فقط، يُسجَّل في `ThreatShare` بصرف النظر عن النتيجة)
  - `record_share()`/`already_shared_values()`/`_share_to_dict()` دوال منفصلة قابلة للاختبار مباشرة (نفس أسلوب `honeypot.py`/`darkweb_monitor.py`)
- `config.py` / `.env.example` — `ENABLE_THREAT_SHARING=false` (افتراضي معطّل تماماً — لا يخرج أي IOC من هذا التنصيب بدون تفعيل صريح، وحتى مع التفعيل تبقى كل مشاركة فعلاً يدوياً بحتاً عبر `POST /share`)
- `web/license.py` — ميزة `threat_sharing` جديدة (PRO + ENTERPRISE)
- `web/templates/threat_feed.html` — تبويب سادس "Threat Sharing · مشاركة التهديدات": تحذير أمني بارز عربي/إنجليزي، حالة التفعيل، قائمة IOCs محلية مع زر مشاركة (تأكيد قبل الإرسال)، أزرار تصدير JSON/CSV/STIX، سجل المشاركات
- `web/templates/base.html` — رابط سايدبار جديد "Threat Sharing" 🤝 تحت SINGULARITY v4.0
- `web/app.py` — تسجيل الراوتر، OpenAPI tag جديد
- `tests/test_threat_sharing.py` — **جديد**: 48 اختبار (validate_ioc لكل نوع ورفض PII، جمع IOCs من الثلاثة مصادر مع التحقق الصريح من عدم تسرب هوية العميل، STIX/CSV export، مشاركة OTX مع mocking كامل لـ`requests` بدون أي اتصال شبكي حقيقي، بوابة opt-in/التحقق/فشل OTX، دوال التدقيق في الراوتر، تسجيل الميزة في الترخيص) — نفس معيار `test_honeypot.py`
- **501/501 اختبار ناجح** على كامل test suite (453 سابق + 48 جديد) — لا regressions

---

### ✅ المهمة 9 — تفعيل CVE Submission Pipeline (أداة صياغة فقط)
- الموديول كان موجوداً بشكل scaffolded (`modules/bug_bounty/cve_pipeline.py` + `web/templates/cve_pipeline.html`) لكنه **غير آمن**: كان يحتوي فعلياً على `submit_cve_to_mitre()` تُرسل `POST` حقيقي إلى `cveawg.mitre.org` إذا كانت `CVE_CNA_ORG`/`CVE_CNA_USERNAME`/`CVE_CNA_API_KEY` مضبوطة في البيئة — يخالف تماماً متطلب "لا إرسال تلقائي لأي جهة خارجية"، فتم **حذف هذه الدالة نهائياً** (لا يوجد أي استدعاء شبكي خارج `search_nvd` القراءة فقط)، ويُثبت ذلك اختبار `TestNoLiveSubmissionCapability` صراحة (لا `submit_cve_to_mitre`، لا ذكر لـ`cveawg.mitre.org`، لا route فيه "submit")
- `web/models.py` — جدول جديد `CveDraft`: `draft_ref` (CVE-DRAFT-XXXXXXXX)، ربط اختياري بـ`Finding` (المصدر: نتيجة فحص فعلية)، `status` يتحرك فقط draft → exported (لا يوجد submitted/error لأنه لا إرسال أصلاً)، حقول MITRE CNA كاملة (vendor/product/versions_affected/problem_type/CWE/CVSS/references/credits)
- `modules/bug_bounty/cve_pipeline.py` — أُعيدت كتابته بالكامل:
  - `search_nvd()` — استعلام NVD للقراءة فقط (كشف تكرار CVE قبل الصياغة)، بقي كما كان
  - `CWE_BY_VULN_TYPE` — تخطيط أنواع الثغرات الشائعة (XSS/SQLi/SSRF/LFI/Open Redirect/CSRF/RCE/IDOR/XXE...) إلى CWE مناسب
  - `SUGGESTED_CVSS_BY_SEVERITY` — نقطة بداية مقترحة (قابلة للتعديل، ليست نهائية) لمتجه CVSS 3.1 حسب severity
  - `draft_from_finding()` — يحوّل Finding من فحص فعلي (type/severity/url/parameter/evidence/payload) إلى حقول مسودة مقترحة
  - `build_cve_json_5()` — يُخرج سجل CVE JSON 5.0 كامل (`dataType`/`dataVersion`/`cveMetadata`/`containers.cna`)؛ `cveId`/`assignerOrgId` تبقى "TBD" و`state: DRAFT` لأنه لا يوجد رقم CVE حقيقي حتى تتم الموافقة والتقديم يدوياً عبر CNA معتمد
- `web/routers/cve_submission.py` — **جديد**، مسار مستقل `prefix=/api/cve` (منفصل عن `/bug-bounty` القديم):
  - `POST /api/cve/draft` — توليد مسودة من `finding_id` (مع دمج أي حقول يدوية فوقها) أو يدوياً بالكامل
  - `GET /api/cve/drafts` — قائمة مسودات المستخدم (فلترة status + pagination)
  - `GET /api/cve/drafts/{id}` — تفاصيل مسودة واحدة
  - `GET /api/cve/drafts/{id}/export` — تنزيل CVE JSON 5.0 (يُعلّم status=exported)
  - `GET /api/cve/search` — نُقل من `bug_bounty.py` (نفس NVD القراءة فقط)
  - كل استجابة مسودة تتضمن `disclaimer_en`/`disclaimer_ar` صراحة
  - أُزيلت 4 endpoints القديمة من `web/routers/bug_bounty.py` (`/api/cve/search|queue|draft|submit/{id}`) بالكامل
- `web/schemas.py` — `CveDraftRequest`/`CveDraftResponse`/`CveDraftListItem` (Swagger كامل)
- `web/templates/cve_pipeline.html` — إعادة كتابة: تحذير بارز أعلى الصفحة (نفس أسلوب `threat_feed.html`) بالنص المطلوب حرفياً "هذه أداة مساعدة لصياغة التقرير فقط — التقديم الفعلي لـMITRE يتطلب مراجعة بشرية وحساب CNA معتمد" عربي/إنجليزي، قسم جديد "توليد مسودة من نتيجة فحص" (dropdown من `/api/findings`)، إصلاح mismatch كان موجوداً أصلاً بين الـfrontend والـbackend (`d.results` بينما الـAPI يُرجع `vulnerabilities`)، زر "Submit to MITRE" استُبدل بزر تنزيل "Export CVE JSON 5.0"
- `.env.example` — أُزيلت `CVE_CNA_ORG`/`CVE_CNA_USERNAME`/`CVE_CNA_API_KEY` (لم تعد هناك حاجة لها، لا يوجد إرسال)، أُبقيت `NVD_API_KEY` فقط مع توضيح أنها اختيارية لرفع حد معدل NVD
- `tests/test_cve_pipeline.py` — **جديد**: 67 اختبار (تخطيط CWE، اقتراح CVSS، `draft_from_finding`، بنية CVE JSON 5.0 كاملة بما فيها استخراج CWE ID والمقاييس والمراجع والـcredits، `search_nvd` مع mocking كامل لـ`httpx.AsyncClient` بدون أي اتصال شبكي حقيقي، دوال المثابرة في الراوتر (`create_draft`/`list_drafts`/`get_draft`/`get_finding_for_user`) مع عزل صارم بين المستخدمين، والأهم: اختبار صريح يثبت عدم وجود أي قدرة إرسال حقيقية لـMITRE)
- **568/568 اختبار ناجح** على كامل test suite (501 سابق + 67 جديد) — لا regressions

---

## المنجز (جلسة 2026-07-02)

### ✅ المهمة 10 — تحسين دقة الكشف: تصنيف XSS الحقيقي مقابل المحجوب بـ WAF
- الماسح الفعلي هو `modules/vuln/xss.py` (وليس `modules/scanners/xss_scanner.py` كما كان مفترضاً — لا يوجد مسار `modules/scanners/` في هذا المشروع أصلاً)
- `modules/vuln/waf_aware_classifier.py` — **جديد**: يصنّف كل استجابة اختبار XSS إلى واحدة من 4 حالات بدل تسجيل أي reflection كثغرة مباشرة:
  - `CONFIRMED` — payload خام غير مرمز + HTTP 200 + لا WAF → severity=High، should_report=True
  - `WAF_BLOCKED` — HTTP 403/406/429 + توقيع WAF معروف → severity=Medium، should_report=False
  - `ENDPOINT_INVALID` — HTTP 404/400 → false positive، يُستبعد تلقائياً (ويُنهي محاولة باقي الـpayloads لنفس النقطة فوراً لتوفير الطلبات)
  - `ENCODED_SAFE` — payload موجود لكن مرمز HTML entities → لا توجد ثغرة
  - + حالة أمان احتياطية خامسة `INCONCLUSIVE` (should_report=False) لأي استجابة لا تُطابق أياً من الحالات الأربع بوضوح
  - كشف WAF عبر `detect_waf()`: headers أولاً (الأكثر موثوقية: `cf-ray`، `akamai-grn`، `x-iinfo`، `x-amzn-waf-action`، `x-sucuri-id`، `x-wa-info`)، ثم `server` header tokens، ثم نصوص صفحة الحجب (Cloudflare/Akamai/Imperva/AWS WAF/Sucuri/F5 BIG-IP ASM)
  - **إصلاح أثناء الاختبار**: كانت علامة Akamai العامة `"access denied"` تتصادم مع صفحات حجب Sucuri (نفس العبارة)، فتُنسب خطأً لـ Akamai — أُزيلت العلامات العامة، أُبقيت فقط `"akamai reference #"` المميزة
- `modules/vuln/xss.py` — عُدّل ليستدعي `classify()` بدل `_check_reflection()` القديمة في الاستعلامات الثلاثة (URL params / forms / headers)؛ فقط النتائج بـ`should_report=True` تُضاف لقائمة النتائج المُعادة
- `web/app.py` — نقطة حفظ الـ Finding الفعلية (حول السطر 1420) تمرّر الآن `waf_detected`/`verdict` من نتيجة الماسح إلى الصف المخزّن
- `web/models.py` — عمودان جديدان على `Finding`: `waf_detected` (String(50), nullable) و`verdict` (String(30), nullable)
- `web/migrate_add_finding_waf_columns.py` — **جديد**: المشروع لا يستخدم Alembic (`init_db()` يعتمد `create_all` فقط الذي لا يُعدّل جداول موجودة)، فهذا سكريبت مستقل idempotent يضيف العمودين عبر `ALTER TABLE` — يعمل على sqlite (تطوير) و Postgres (إنتاج) على حدٍ سواء. طُبّق فعلياً على `data/optisec.db` الحالي بعد موافقة صريحة (يحتوي بيانات ديمو/ترخيص حقيقية)
- `tests/test_waf_aware_classifier.py` — **جديد**: 40 اختبار (الحالات الأربع + INCONCLUSIVE، كل موردي WAF عبر header/server-token/body-marker، أولوية ENDPOINT_INVALID فوق أي إشارة WAF، عدم تصنيف CONFIRMED إذا كان WAF حاضراً حتى مع reflection خام وHTTP 200، عمل `classify_response()` مع كائنات بأسلوب `requests.Response` وليس فقط `httpx`) — عبر `httpx.MockTransport` بدون أي اتصال شبكة حقيقي
- **608/608 اختبار ناجح** على كامل test suite (568 سابق + 40 جديد) — لا regressions

### ✅ المهمة 11 — تعميم `waf_aware_classifier` على ماسح SQLi
- `modules/vuln/waf_aware_classifier.py` — أُضيفت دالتان جديدتان تُعيدان استخدام نفس نواة كشف WAF (`detect_waf`/`WAF_SIGNATURES`/`BLOCKING_STATUS_CODES`/`INVALID_STATUS_CODES`) بدل تكرارها، بلا مفهوم "ترميز HTML" (غير منطقي لـSQLi):
  - `classify_error_signature(status_code, headers, body, matched_error)` — للفحص القائم على أخطاء SQL الظاهرة في نص الاستجابة (error-based + form scan): CONFIRMED (severity=Critical) فقط عند تطابق نص خطأ SQL + HTTP 200 + لا WAF
  - `classify_blind_signal(status_a, headers_a, body_a, status_b, headers_b, body_b, signal_detected, technique)` — للفحص الأعمى (boolean-based / time-based)، يفحص **كلا** الاستجابتين بحثاً عن WAF قبل الوثوق بالفارق
  - **إصلاح أثناء الكتابة/الاختبار**: التصميم الأول جعل `ENDPOINT_INVALID` يتفعّل إذا كانت **أي واحدة** من الاستجابتين 404/400 — لكن انقسام الحالة (مثلاً true=200 / false=404) الناتج عن الشرط المحقون هو **بالضبط** إشارة الـboolean-based blind المطلوب اكتشافها، وليس دليلاً على أن نقطة النهاية معطوبة. صُحّح ليتطلب فشل **كلا** الاستجابتين بنفس الحالة قبل اعتباره ENDPOINT_INVALID
- `modules/vuln/sqli.py` — عُدّلت الدوال الثلاث (`_error_based_scan`/`_blind_scan`/`_scan_forms`) لاستدعاء الدالتين الجديدتين بدل تسجيل أي إشارة (خطأ SQL / فارق محتوى / تأخير زمني) كثغرة مباشرة؛ فقط `should_report=True` (CONFIRMED) يُضاف للنتائج؛ توقف مبكر عند ENDPOINT_INVALID لتوفير الطلبات (مطابق لسلوك `xss.py`)
- `web/app.py` لم يحتج تعديلاً — نقطة حفظ الـFinding تقرأ `waf_detected`/`verdict` من قاموس النتيجة بشكل عام لأي نوع ماسح
- `tests/test_waf_aware_classifier.py` — 16 اختبار جديد لـ`classify_error_signature`/`classify_blind_signal` (CONFIRMED/WAF_BLOCKED/ENDPOINT_INVALID(كلا الطرفين فقط)/INCONCLUSIVE، وتحديداً اختبار صريح لسيناريو "انقسام الحالة 200/404 = تأكيد وليس استبعاد")
- `tests/test_sqli.py` — **جديد**: 13 اختبار تكامل لـ`sqli.py` نفسه (error-based/boolean-blind/time-based-blind/forms/scan_sqli end-to-end) عبر `monkeypatch` على `requests.Session.get/post` (بدون شبكة حقيقية)؛ التوقيت للفحص الزمني يُحاكى عبر `monkeypatch` على `sqli.time.time` بدل انتظار فعلي
- **637/637 اختبار ناجح** على كامل test suite (608 سابق + 16 + 13 جديد) — لا regressions

### ✅ المهمة 12 — تعميم `waf_aware_classifier` على ماسحَي LFI وSSRF
- لاحظت أن `_error_based_scan` بـSQLi وماسحي LFI/SSRF لهما نفس الشكل تماماً: طلب واحد + بحث عن نص "توقيع" (signature) داخل جسم الاستجابة → فاستخرجت النواة المشتركة بدل تكرارها:
  - `classify_signature_match(status_code, headers, body, matched_signal, *, severity, signal_label)` — دالة عامة جديدة في `waf_aware_classifier.py`، تقبل `severity`/`signal_label` مخصصين لكل نوع ثغرة (لا يوجد severity واحد موحّد: LFI=High، SQLi/SSRF=Critical)
  - `classify_error_signature()` (الخاصة بـSQLi، المُستخدمة مسبقاً وبها اختبارات قائمة) أصبحت الآن مجرّد wrapper رقيق فوق `classify_signature_match()` بدل تكرار المنطق — بدون أي كسر توافقية (كل اختبارات SQLi السابقة ما زالت تعمل دون تعديل)
- `modules/vuln/lfi.py` — عُدّل ليستدعي `classify_signature_match(..., severity="High", signal_label="LFI indicator")` بدل تسجيل أي مؤشر LFI (`root:x:0:0`، `[fonts]`، إلخ) كثغرة مباشرة؛ توقف مبكر عند ENDPOINT_INVALID
- `modules/vuln/ssrf.py` — نفس الشيء مع `severity="Critical", signal_label="SSRF indicator"`؛ حافظ على المطابقة case-insensitive الأصلية (يقارن `.lower()` قبل تمرير `matched_indicator` للدالة)
- `web/app.py` لم يحتج تعديلاً (كما في SQLi) — نقطة حفظ الـFinding عامة لأي ماسح
- `tests/test_waf_aware_classifier.py` — 10 اختبار جديد لـ`classify_signature_match` (severity/label مخصصين، WAF_BLOCKED، ENDPOINT_INVALID يتغلب على تطابق الإشارة، عدم CONFIRMED مع WAF حاضر) + اختبار صريح يثبت أن `classify_error_signature` القديمة ما زالت تُفوّض بشكل صحيح بعد إعادة الهيكلة
- `tests/test_lfi.py` و`tests/test_ssrf.py` — **جديدان**: 5 + 6 اختبارات تكامل (CONFIRMED حقيقي، تجاهل WAF_BLOCKED، توقف مبكر عند 404/400، لا نتائج بدون إشارة، مطابقة case-insensitive لـSSRF) عبر `monkeypatch` على `requests.Session.get`
- **658/658 اختبار ناجح** على كامل test suite (637 سابق + 21 جديد) — لا regressions
- المتبقي من الماسحات القديمة الأسلوب: `open_redirect.py` فقط (لم يُطلب في هذه الجلسة)

### ✅ المهمة 13 — تعميم `waf_aware_classifier` على ماسح Open Redirect (آخر ماسح متبقٍ)
- شكل الكشف هنا مختلف: التأكيد يعتمد على حالة **إعادة توجيه 3xx** (301/302/303/307/308) + رأس `Location` وليس HTTP 200 + نص في الجسم — فـ`classify_signature_match()` احتاجت تعميماً إضافياً بدل دالة منفصلة كاملة:
  - أُضيف بارامتر جديد `expected_status_codes` (افتراضياً `frozenset({200})` — يحافظ على سلوك SQLi/LFI/SSRF دون أي تغيير؛ تحقّق ذلك اختبار صريح `test_signature_match_default_status_200_still_required_when_unset`) يسمح لـOpen Redirect بتمرير `{301,302,303,307,308}` بدلاً من ذلك
- `modules/vuln/open_redirect.py` — عُدّل ليستدعي `classify_signature_match(..., severity="Medium", signal_label="Open Redirect Location header", expected_status_codes=REDIRECT_STATUS_CODES)`
  - **إصلاح false-positive حقيقي كان موجوداً في الكود القديم أثناء إعادة الكتابة**: الشرط الأصلي كان `"evil.com" in loc OR (status in 3xx and loc)` — أي أن أي إعادة توجيه 3xx تحمل رأس `Location` **لأي وجهة كانت** (حتى `/login` على نفس الموقع) كانت تُسجَّل كثغرة! أصبح الشرط الآن يتطلب أن يحتوي `Location` فعلياً على العلامة الخارجية (`evil.com`) — لا إشارة = لا تأكيد
- `web/app.py` لم يحتج تعديلاً
- `tests/test_waf_aware_classifier.py` — 4 اختبار جديد لـ`expected_status_codes` (تأكيد عبر 302، عدم كسر الافتراضي 200، عدم CONFIRMED بدون تطابق Location، عدم CONFIRMED مع WAF حاضر)
- `tests/test_open_redirect.py` — **جديد**: 6 اختبار تكامل، أبرزها `test_scan_open_redirect_ignores_same_site_redirect` الذي يثبت إصلاح الـfalse-positive أعلاه
- **668/668 اختبار ناجح** على كامل test suite (658 سابق + 10 جديد) — لا regressions
- **الماسحات الخمسة (XSS/SQLi/LFI/SSRF/Open Redirect) أصبحت كلها تستخدم `waf_aware_classifier` الآن** — لا يوجد ماسح متبقٍ من الأسلوب القديم (تسجيل أي إشارة كثغرة مباشرة)

### ✅ المهمة 14 — JSON mode حقيقي + retry logic لكل استدعاءات Groq API (تحضيراً لتبديل الموديل المهجور)
- تحقّقت أولاً من توثيق Groq الحالي: `response_format={"type": "json_object"}` مدعوم من **كل** موديلات Groq (وليس فقط بعضها)، ويتطلب فقط ذكر كلمة "json" صراحة في الـsystem أو الـuser prompt — وكل الاستدعاءات الخمسة كانت تذكرها أصلاً
- `modules/ai/groq_client_utils.py` — **جديد**: دالتا retry مشتركتان `call_groq_sync_with_retry`/`call_groq_async_with_retry` (3 محاولات إجمالي افتراضياً، backoff 1s ثم 2s) تُستخدم من الملفات الخمسة بدل تكرار المنطق؛ تعيد رفع الاستثناء الأخير بعد استنفاد المحاولات فقط، فمعالجة الفشل النهائي في كل موقع استدعاء تبقى كما كانت تماماً
- استُبدل الاعتماد على regex (`re.search(r'\{.*\}', ...)`) لاستخراج JSON من الاستجابة بـ`json.loads(content)` مباشرة في كل استدعاء يتوقع JSON، بعد إضافة `response_format=json_object`:
  - `modules/ai/groq_analyzer.py::natural_language_to_command` (الوحيدة من دوال هذا الملف التي تتوقع JSON؛ `analyze_findings`/`summarize_recon` نص حر فقط أُضيف لهما retry بدون response_format)
  - `modules/osint/threat_narrative.py::generate_threat_narrative`
  - `modules/ai_advanced/autonomous_redteam.py::_ai_attack_analysis`
  - `modules/ai_advanced/red_team.py::_ai_generate_plan`
  - `modules/ai_advanced/zero_day.py::_ai_zero_day_analysis`
- لا استدعاء استُبعد من json_object mode (كلها مدعومة)
- `GROQ_MODEL` في `config.py` لم يُمس في هذه المهمة كما طُلب صراحةً

### ✅ المهمة 15 — تبديل الموديل المهجور: `llama-3.3-70b-versatile` → `openai/gpt-oss-120b`
- تحقّقت من توثيق Groq قبل التنفيذ: الموديل البديل الموصى به رسمياً من Groq بعد إهمال `llama-3.3-70b-versatile`؛ نافذة سياق 131K، يدعم `response_format=json_object` (المشاكل الموثقة في مجتمع Groq تخص تحديداً `json_schema`/structured outputs الصارم، وليس `json_object` المستخدم هنا)، وموديل reasoning لكن الـreasoning content يُرجع افتراضياً في حقل منفصل عن `message.content` لموديلات GPT-OSS — فلا حاجة لأي تعديل على كود القراءة الحالي
- `config.py` — `GROQ_MODEL = "openai/gpt-oss-120b"`
- `modules/osint/threat_narrative.py` — تحديث تعليقين توثيقيين (docstrings) كانا يذكران اسم الموديل القديم صراحةً ليشيرا إلى `config.GROQ_MODEL` بدلاً من ذلك
- تأكدت أنه لا يوجد أي مرجع آخر متبقٍ لاسم الموديل القديم في الكود

### ✅ المهمة 16 — اختبار الملفات الخمسة عبر endpoints حقيقية على السيرفر المحلي + اكتشاف وإصلاح bug حقيقي
- اختبرت 5 endpoints حقيقية (تسجيل دخول عبر `/demo`، ثم طلبات فعلية تصل Groq API الحي): `POST /ai-security/api/zero-day/predict`، `POST /ai-security/api/red-team/engagements`، `POST /api/nlp` و`POST /api/ai/analyze` (كلاهما من `groq_analyzer.py`)، `POST /api/osint/threat-analysis` (مع `include_ai:true`)، `POST /autonomous-redteam/api/start` — كلها نجحت (`source`/محتوى الاستجابة يؤكدان المرور الفعلي عبر Groq، وليس أي fallback)
- **اكتُشف bug حقيقي وقابل لإعادة الإنتاج أثناء الاختبار**: Groq يرفض مخرجات `openai/gpt-oss-120b` بخطأ HTTP 400 `json_validate_failed` بمعدل 50-100% تحديداً في `natural_language_to_command` عندما يحتاج `scan_types` لعنصرين أو أكثر (تم عزل المتغير بأكثر من 40 استدعاء API حي لتأكيد السبب والنسبة)
- **السبب الجذري**: أمثلة الـfew-shot في الـprompt كانت بصيغة نصية حرة (`"input" → action: xss, target: ...`) بدل JSON، وهذا التنسيق يبدو أنه يُشجّع الموديل على إخراج JSON غير سليم عند الحاجة لقائمة متعددة العناصر
- **الإصلاح** (بعد اختبار عدة صيغ حية لعزل الأثر): إعادة كتابة الأمثلة بصيغة JSON كاملة مع مثال ثنائي اللغة (عربي + إنجليزي) يوضح كلاهما قائمة `scan_types` بعنصرين — خفّض نسبة الفشل من 100%/50% (عربي/إنجليزي) إلى 0%/~12%؛ ولأن نسبة الفشل الإنجليزية المتبقية ليست صفراً، أُضيف بارامتر `retry_delays` اختياري لـ`call_groq_sync_with_retry`/`call_groq_async_with_retry` (الافتراضي يبقى 3 محاولات لبقية المواقع الأربعة دون أي تغيير) واستُخدم `retry_delays=(1,2,4,8)` (5 محاولات) في `natural_language_to_command` تحديداً، ليصبح احتمال الفشل المتبقي ~0.12⁴
- تم التحقق من الإصلاح مباشرة (6/6 نجاح) وعبر endpoint `/api/nlp` الفعلي (رجع الآن نتيجة الذكاء الاصطناعي `confidence: 0.97` بدل السقوط الصامت السابق لـparser محلي)
- اختبار موثوقية لبقية الاستدعاءات (`threat_narrative`/`autonomous_redteam`): 6/6 نجاح لكل منهما، بدون أي فشل — المشكلة مقتصرة على `natural_language_to_command`
- شُغّل test suite بفلترة `-k "groq or nlp or ai"` (96 اختبار ذو صلة من أصل 668) بعد كل هذه التعديلات: **96/96 ناجح** — لا regressions (لم يُشغَّل كامل الـ668 من جديد في هذه المهمة تحديداً)

---

## قرار: أعمدة WAF Classifier (waf_detected / verdict) - نهائي

- العمودان `waf_detected` (`String(50)`) و`verdict` (`String(30)`) في `web/models.py` (السطر 78-79، ضمن model الـ`Finding`) هما التصميم النهائي المعتمد — تم التحقق منهما مقابل الكود الحالي عند كتابة هذه الملاحظة (2026-07-02).
- `waf_detected` يخزن اسم الـWAF المكتشف كنص حر (مثل `"Cloudflare"` أو `"Akamai"` أو `None`) — وليس boolean.
- `verdict` يخزن نصاً حراً (`String(30)`) يستخدمه `modules/vuln/waf_aware_classifier.py`. **تصحيح مهم**: القيم الفعلية المستخدمة في الإنتاج حالياً هي **خمس قيم** وليست ثلاثاً:
  - لكشف XSS (`classify()`/`classify_response()`): `CONFIRMED`، `WAF_BLOCKED`، `ENDPOINT_INVALID`، `ENCODED_SAFE`
  - للفحوصات القائمة على التوقيع/الفحص الأعمى (SQLi/LFI/SSRF عبر `classify_signature_match()`/`classify_blind_signal()`): `CONFIRMED`، `WAF_BLOCKED`، `ENDPOINT_INVALID`، `INCONCLUSIVE` (بدل `ENCODED_SAFE` هنا)
  - فقط `CONFIRMED` يُفعّل `should_report=True` ويُحفظ كـFinding مؤكد
- تصميم بديل بـ`boolean` (بدل نص لاسم الـWAF) + enum ثابت بأربع قيم (`CONFIRMED_EXPLOITABLE`، `WAF_BLOCKED`، `ENDPOINT_INVALID`، `ENCODED_SAFE`) كان مطروحاً كبديل نظري، لكنه **غير معتمد ولم يُطبَّق أبداً** — والتصميم الحالي (نص حر لكلا العمودين) هو الوحيد الموجود في الكود والمطبَّق على البيانات الحية فعلياً، ويعطي معلومة أدق (اسم الـWAF الفعلي بدل true/false، وتمييز `ENDPOINT_INVALID`/`ENCODED_SAFE`/`INCONCLUSIVE` كحالات منفصلة بدل دمجها).
- أي عمل مستقبلي على هذا الموديول يجب أن يبني على القيم الحقيقية الموجودة في `waf_aware_classifier.py` (`CONFIRMED`/`WAF_BLOCKED`/`ENDPOINT_INVALID`/`ENCODED_SAFE`/`INCONCLUSIVE` حسب نوع الفحص) — **وليس** على القيم الثلاث أو الأربع المذكورة في أي طلب سابق يفترض عكس ذلك.
- migration script: `web/migrate_add_finding_waf_columns.py` (idempotent، يدعم SQLite وPostgres) - مطبّق مسبقاً على قاعدة البيانات الحية، لا حاجة لإعادة تشغيله.
- هذه ملاحظة توثيقية فقط — لم يُعدَّل أي كود أو schema في قاعدة البيانات ضمن هذه المهمة.

---

### ✅ المهمة 17 — إصلاح 429 في AI Analysis (`analyze_findings` / `POST /api/ai/analyze`)
- المهمة المطلوبة افترضت أن الموديل الحالي `llama-3.3-70b-versatile` (نفس Threat Narrative) — غير صحيح: المهمة 15 (2026-07-02) بدّلت `config.GROQ_MODEL` بالكامل إلى `openai/gpt-oss-120b` لأن الموديل القديم مهجور من Groq، و`threat_narrative.py` يستخدم نفس `config.GROQ_MODEL`. **لم يُغيَّر الموديل** — بقي `openai/gpt-oss-120b`
- `modules/ai/groq_analyzer.py::analyze_findings`:
  - البرومبت أصبح يرسل ملخصاً مختصراً (type/severity/parameter فقط) بحد أقصى 5 ثغرات + عدد إجمالي للباقي، بدل JSON كامل بكل evidence لكل الثغرات — هذا هو السبب الأكبر لاستهلاك التوكنز
  - `max_tokens=400` صراحة (بدل 2048)
  - `retry_delays=(1,2,4)` + `retry_on` جديد يمنع إعادة المحاولة إذا كان الخطأ 429 يومي (TPD) فعلياً — يُكتشف عبر إعادة استخدام `parse_tpd_state_from_error` الموجودة أصلاً في `rate_limiter.py` بدل تكرار منطق الكشف
  - `generate_static_summary()` — fallback بدون AI (severity counts + أكثر نوع تكراراً + توصية عامة) يُستخدم إذا فشل Groq نهائياً، بدل إرجاع نص الخطأ الخام
  - cache بسيط في الذاكرة (`OrderedDict` بحد 200 عنصر) مبني على `sha256(findings+target+lang)` يمنع استدعاء Groq مرتين لنفس نتائج الفحص
- `modules/ai/rate_limiter.py` — أُضيف `DailyTokenBudget` (تعقّب تقديري بـ`threading.Lock` بدل `asyncio.Lock`، لأن `analyze_findings` دالة sync تُستدعى عبر `asyncio.to_thread` من ثريد عامل وليس event loop — لا يمكنها مشاركة `TokenBucketLimiter` الحالي بأمان عبر الثريدز)، يرفض استباقياً عند تجاوز 90% من `GROQ_TPD_LIMIT` (180000/200000 حالياً)، ورسالة عربية/إنجليزية واضحة بدل خطأ Groq الخام؛ `get_default_daily_budget()` singleton على مستوى العملية. لم يُعدَّل `TokenBucketLimiter`/`triage_engine.py` — بقيا كما هما (تعقّب TPD منفصل لكل batch، غير موحّد مع `analyze_findings`، قرار واعٍ لتفادي تعقيد asyncio.Lock عبر ثريدز)
- `modules/ai/groq_client_utils.py::call_groq_sync_with_retry` — بارامتر اختياري جديد `retry_on` (افتراضي `None` = إعادة المحاولة على أي استثناء، نفس السلوك القديم تماماً لبقية 4 مواقع الاستدعاء)
- `tests/test_groq_client_utils.py` — **جديد**: 7 اختبارات لـ`retry_on`/توقيت الـbackoff
- `tests/test_groq_analyzer.py` — **جديد**: ~19 اختبار (ملخص الثغرات المختصر، `generate_static_summary`، الكاش، رفض ميزانية التوكن اليومية، عدم إعادة المحاولة لخطأ TPD تحديداً مقابل إعادة المحاولة لخطأ TPM عادي)
- `tests/test_rate_limiter.py` — 9 اختبارات جديدة لـ`DailyTokenBudget`/`estimate_tokens_from_text`/`get_default_daily_budget`
- **717/717 اختبار ناجح** على كامل test suite (682 سابق + 35 جديد) — لا regressions
- Commit: `83a0dac` — تم push إلى `origin/master`

## المنجز (جلسة 2026-07-03، تكملة) — الاحتفاظ بسجلات WAF_BLOCKED بقاعدة البيانات

**المشكلة:** الماسحات الخمسة (XSS/SQLi/LFI/SSRF/Open Redirect) كانت تستبعد أي
نتيجة `should_report=False` (أي verdict غير CONFIRMED: WAF_BLOCKED،
ENDPOINT_INVALID، ENCODED_SAFE، INCONCLUSIVE — انظر قسم "WAF-aware XSS
classification" أعلاه في هذا الملف) *قبل* أن تصل أصلاً لقائمة النتائج
المُعادة من الماسح، فلا تُحفظ أبداً
في جدول `findings`. **تصحيح مهم لوصف المهمة الأصلي**: الاستبعاد لم يكن في
`web/app.py` (نقطة الحفظ هناك تُنشئ Finding لكل عنصر تستلمه بدون شرط)، بل في
الماسحات نفسها (`modules/vuln/*.py`) عبر `if result.should_report:` قبل
`findings.append(...)`.

**السبب للاحتفاظ:** قيمة استخباراتية (اسم WAF المكتشف، الأدلة على أن الفحص
تم فعلاً) وتوثيق أدلة لتقارير bug bounty — مع عدم تغيير أي شيء ظاهر للعميل.

**الحل:**
1. عمود جديد `Finding.include_in_report` (Boolean, NOT NULL, DEFAULT TRUE) —
   `web/models.py`. Migration منفصل idempotent:
   `web/migrate_add_finding_include_in_report_column.py` (نفس نمط
   `migrate_add_finding_waf_columns.py`) — طُبّق فعلياً على `data/optisec.db`
   بعد موافقة صريحة، الصفوف الـ65 الموجودة مسبقاً كلها CONFIRMED فبُقّيت
   `include_in_report=True`.
2. الماسحات الخمسة عُدّلت لتُبقي *كل* نتيجة classify() بدل استبعاد
   `should_report=False`، لكن بشكل محدود الحجم: لكل باراميتر/متجه يُختبر،
   تُحفظ فقط النتيجة CONFIRMED (إن وُجدت) **أو** آخر نتيجة غير-مؤكدة جُرّبت
   (نمط `pending` — سطر واحد لكل باراميتر، وليس سطراً لكل payload) — تفادياً
   لتضخيم عدد الصفوف بلا داعٍ (10 payloads × عدة باراميترات لكل ماسح). سلوك
   الفحص نفسه (عدد الطلبات، التوقف المبكر عند ENDPOINT_INVALID) لم يتغير.
   - **Bug حقيقي اكتُشف ومُصلح أثناء الكتابة**: `scan_sqli()` كان يتخطى
     `_blind_scan()` كلياً بشرط `if not findings` — كان هذا صحيحاً فقط عندما
     `findings` تحتوي CONFIRMED حصراً؛ بعد التعديل تكاد `findings` لا تكون
     فارغة أبداً (كل باراميتر يترك سجلاً الآن)، فكان `_blind_scan` سيتوقف عن
     العمل فعلياً في الإنتاج. صُحّح ليتحقق من وجود CONFIRMED تحديداً
     (`if not any(f.get("verdict")=="CONFIRMED" for f in findings)`) — مغطّى
     باختبار تكامل جديد `test_scan_sqli_end_to_end_retains_waf_blocked_and_still_runs_blind_scan`.
3. `web/app.py`: `_finding_kwargs_from_vuln()` دالة نقية جديدة تحوّل نتيجة
   ماسح واحدة إلى `Finding(**kwargs)`، مع `include_in_report=(verdict=="CONFIRMED")`.
   نقطة حفظ الـFinding تحفظ الآن *كل* عناصر `all_vulns` (وليس فقط ما كان
   `should_report=True` قديماً). لكن `scan.results["vulnerabilities"]`
   (تستخدمها scans.html لعدّ الثغرات، وتقرير PDF عبر `modules/report/pdf_generator.py`
   الذي يقرأ `scan_data.get("vulnerabilities")` مباشرة — **لا** يستعلم جدول
   Finding إطلاقاً) بقيت مبنية من `confirmed_vulns` فقط — نفس السلوك الظاهر
   للعميل بالضبط. كذلك AI triage (`classify_findings_batch`) يعمل الآن على
   `confirmed_vulns` فقط بدل `all_vulns` — تجنّباً لاستهلاك حصة Groq اليومية
   (TPD، انظر ملاحظات الجلسات السابقة) على نتائج WAF_BLOCKED/إلخ لا تحتاج
   رأياً ثانياً من الذكاء الاصطناعي أصلاً.
   - **Bug اكتُشف بالتحقق الحي (وليس بالاختبارات) وأُصلح**: أول تنفيذ ربط
     نتائج الـtriage بالـdicts عبر `v["_triage"] = triage` (تعديل مباشر على
     نفس الكائنات المخزّنة في `results["vulnerabilities"]`) — هذا كان يُسرّب
     حقل `_triage` داخلي إلى JSON الذي يراه العميل فعلياً (تأكّد بفحص استجابة
     `GET /api/scan/{id}` الحية). صُحّح باستخدام `{id(v): t for v, t in zip(...)}`
     بدل التعديل المباشر على الـdicts.
4. `/api/findings` (`web/app.py`) ولوحة التحكم الرئيسية (`index()` —
   finding_count/critical_count/high_count/medium_count/low_count) أُضيف لها
   فلتر `Finding.include_in_report.is_(True)`. لوحة `/admin` (`total_findings`)
   تُركت **بلا فلتر عمداً** — نظرة عامة داخلية للمشغّل (admin)، وليست تقرير
   عميل. `web/routers/cve_submission.py`'s `get_finding_for_user` تُرك أيضاً
   بلا فلتر (لم يُطلب في هذه المهمة، ولا خطر أمني حقيقي — مستخدم يصوغ CVE من
   نتيجة WAF-blocked خاصة به فقط).
5. **تحقّق حي فعلي (وليس اختبارات فقط)**: شُغّل السيرفر محلياً، أُطلق فحص XSS
   حقيقي ضد target محلي (`http.server` بسيط) يحاكي WAF على باراميتر ويعكس
   XSS خام على آخر. تأكّد مباشرة من جدول `findings`: 5 صفوف محفوظة
   (CONFIRMED + WAF_BLOCKED + 3×INCONCLUSIVE)، `include_in_report` صحيح لكل
   واحد. `GET /api/findings` و`GET /` (لوحة التحكم) عرضا رقماً واحداً فقط
   (المؤكَّد) — مطابق تماماً للعدّ اليدوي المفلتَر من قاعدة البيانات.
6. **729/729 اختبار ناجح** (كان 720 قبل هذه المهمة؛ +9 صافي: ملف جديد
   بـ7 اختبارات + إضافات صافية في ملفات الماسحات المعدَّلة) —
   `tests/test_finding_include_in_report.py` **جديد** (7 اختبارات لـ
   `_finding_kwargs_from_vuln`)، `tests/test_sqli.py`/`test_lfi.py`/
   `test_ssrf.py`/`test_open_redirect.py` عُدّلت (لم تعد تفترض `findings==[]`
   عند WAF_BLOCKED/INCONCLUSIVE — بل تتحقق من الـverdict الصحيح مع عدم وجود
   CONFIRMED). لا ملف اختبار مخصص لـ`xss.py` كان موجوداً أصلاً (فجوة موجودة
   من قبل هذه الجلسة).
   - **Gotcha اختباري غير متعلق بالكود**: إضافة ملف اختبار جديد يستورد
     `web.app` (`test_finding_include_in_report.py`) قبل
     `test_migration_endpoint.py` أبجدياً كسر ذاك الأخير — `web.app` وحدة
     singleton تُسجَّل مساراتها عند الاستيراد، و`test_migration_endpoint.py`
     يعتمد على تعيين `GROQ_ENV=production` *قبل* أول استيراد لـ`web.app` في
     كامل جلسة pytest. أُصلح بتعيين نفس المتغير (`os.environ.setdefault(...)`)
     في الملف الجديد أيضاً.
- لم يُدفع (push) — بانتظار مراجعة المستخدم.

## تشخيص (جلسة 2026-07-04) — هل هناك SQLite fallback يسبب waf_detected = NULL؟

**سؤال الفحص:** 16 من أصل 64 صف في `findings` عمودها `waf_detected = NULL`. هل هذا
ناتج عن "رجوع صامت لـSQLite" في الإنتاج؟ **تحليل قراءة فقط — لم يُنفَّذ أي أمر
migration ولا تعديل على أي قاعدة بيانات.**

### 1. كيف تُقرأ DATABASE_URL — لا يوجد fallback حقيقي في زمن التشغيل

- `web/database.py:5-10`: `DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite+aiosqlite:///./data/optisec.db")` ثم `engine = create_async_engine(DATABASE_URL, ...)` مباشرة — **لا يوجد أي `try/except`** حول إنشاء الـengine أو حول أي استعلام يمسك فشل الاتصال بـPostgres ثم يُعيد التوجيه لـSQLite. الفشل لو حصل سيكون استثناء صريح (connection refused/timeout)، وليس تبديلاً صامتاً.
- `config.py:31-35` يكرر **نفس المنطق بشكل منفصل**: `DATABASE_URL = os.environ.get("DATABASE_URL", f"sqlite+aiosqlite:///{DATA_DIR}/optisec.db")`. هذا تعريف ثانٍ مستقل (مسار مطلق عبر `DATA_DIR` هنا مقابل مسار نسبي `./data/optisec.db` في `web/database.py`) — لا يبدو أن `config.DATABASE_URL` يُستخدم فعلياً لإنشاء أي engine (الـengine الوحيد يُبنى في `web/database.py`)، لكنه مصدر ازدواجية/تشتت يستحق التوحيد لاحقاً.
- **الخلاصة:** "SQLite fallback" بمعنى "الكود يحاول Postgres، يفشل، يرجع تلقائياً لـSQLite" **غير موجود في الكود إطلاقاً**. ما هو موجود فعلاً هو **قيمة افتراضية صامتة**: إذا لم يُضبط `DATABASE_URL` في البيئة (متغيّر مفقود)، يعمل التطبيق فوراً على SQLite محلي دون أي خطأ أو تحذير — وهذا خطر كامن (latent risk) وليس السبب المؤكد للـ16 صف الحاليين (انظر القسم 4).

### 2. إعداد الإنشاء (Render) — لا يوجد render.yaml في المستودع

- لا يوجد ملف `render.yaml` في المشروع؛ الإعداد يتم يدوياً عبر لوحة Render (موثّق في `README.md` قسم "Deploy to Render": `DATABASE_URL` مطلوب ✅ ويجب ضبطه يدوياً إلى Postgres URL الخاص بـRender).
- لا يوجد Persistent Disk مُعرّف في أي مكان بالمستودع (`docker-compose.yml`/`Dockerfile`/`railway.json` — لا شيء منها يُعرّف Render disk). دليل إضافي في `web/app.py:2117`: تعليق صريح "Render's free plan has no Shell access" يؤكد بيئة Render فعلية بخطة بدون قرص دائم مضمون.
- ملف SQLite المحتمل: `./data/optisec.db` (نسبي حسب `web/database.py`) أو `{DATA_DIR}/optisec.db` (مطلق حسب `config.py`، لكنه غير مُستخدم لبناء الـengine). **هذا الملف مُدرج في `.gitignore`** (`data/optisec.db`) — أي أنه لا يُشحن أبداً مع الكود المنشور على Render؛ لو استُخدم هناك (بسبب غياب `DATABASE_URL`) فسيُنشأ من الصفر على فيلسستم إنتاج Render، ويُمحى بالكامل عند أي redeploy (لا قرص دائم = لا استمرارية).

### 3. ربط بالـ16 صف NULL — الاستنتاج الأهم أولاً

**فحصت `modules/vuln/waf_aware_classifier.py` مباشرة (دالة `classify()` أسطر
172-222، و`classify_response()` بعدها مباشرة — أرقام الأسطر الدقيقة تحرّكت
بعد commit `d6712a2` التوثيقي، فالإشارة هنا لاسم الدالة لا لرقم سطر ثابت):**
`waf_detected` هو ببساطة نتيجة `detect_waf(headers, body)` — نص باسم WAF إن طابقت
استجابة HTTP توقيعاً معروفاً (Cloudflare/Akamai/Sucuri/...)، أو **`None` إن لم
يُطابق أي توقيع**. هذا يعني NULL هو **قيمة متوقعة ومصمَّمة عمداً**، وليست مؤشر
عطل:
- `verdict = CONFIRMED` → `waf_detected` يُجبر إلى `None` دائماً (داخل `classify()`) — الثغرة مؤكدة تعني بالتعريف عدم وجود WAF يحجبها.
- `verdict = WAF_BLOCKED` → **يستحيل** أن يكون `waf_detected` فارغاً (الشرط نفسه `status_code in BLOCKING_STATUS_CODES and waf_vendor` يتطلب `waf_vendor` truthy لدخول هذا الفرع أصلاً).
- `verdict ∈ {ENDPOINT_INVALID, ENCODED_SAFE, INCONCLUSIVE}` → `waf_detected = waf_vendor`، أي NULL كلما لم يُطابق `detect_waf()` أي توقيع معروف (شائع جداً لأي هدف بلا WAF مُتعرَّف عليه من القائمة).

فإذا كانت الـ16 صف NULL موزّعة على `verdict IN ('CONFIRMED', 'ENDPOINT_INVALID', 'ENCODED_SAFE', 'INCONCLUSIVE')` — وهذا شبه مؤكد رياضياً بما أن `WAF_BLOCKED` مستحيل مع NULL — فهذا **سلوك طبيعي 100%، وليس bug**.

**الاحتمال الثاني (أقل ترجيحاً لكن يستحق التحقق):** صفوف قديمة سابقة على إضافة
العمودين (مهمة #10، 2026-07-02) أو سابقة على تطبيق migration الأعمدة. علامتها
المميزة: `waf_detected IS NULL **و** verdict IS NULL معاً` (وليس NULL في عمود
واحد فقط) — لأن أي صف مرّ فعلاً عبر `waf_aware_classifier` سيُعبّئ `verdict`
دائماً حتى لو ترك `waf_detected` فارغاً. صف بـ`verdict IS NULL` يعني أنه أُنشئ
قبل دمج الـclassifier أصلاً (قديم)، وهذا غير متعلق بـSQLite fallback إطلاقاً
بل بترتيب النشر الزمني.

**نقطة تستحق تنويهاً صريحاً:** بحسب ملاحظات هذا الملف (قسم "قرار: أعمدة WAF
Classifier" وقسم مهمة 2026-07-03)، سكريبتا الـmigration
(`web/migrate_add_finding_waf_columns.py` و
`web/migrate_add_finding_include_in_report_column.py`) كلاهما "طُبّقا فعلياً
على `data/optisec.db`" — أي **قاعدة SQLite المحلية**، عبر
`web.database.engine` الذي يعتمد بدوره على `DATABASE_URL` **في بيئة التشغيل
وقت استدعاء السكريبت**. لا يوجد أي دليل في هذا الملف أو في الكود (تحقّقت من
endpoint الـmigration المؤقت في `web/app.py:2117` — يستدعي حصراً
`migrate_normalize_demo_severity.migrate()`، وليس سكريبتَي WAF/include_in_report)
على أن هاتين الـmigration طُبّقتا فعلياً على Postgres الخاص بـRender. هذا يعني
أحد احتمالين:
  1. **الأرجح**: الـ64 صف التي تُفحص الآن هي فعلياً من قاعدة SQLite المحلية
     للتطوير (`data/optisec.db`)، وليست بيانات إنتاج Render إطلاقاً — أي أن
     "مشكلة SQLite" هنا ليست fallback خفياً، بل ببساطة أن الفحص يتم على قاعدة
     SQLite المحلية المقصودة أصلاً للتطوير (وهي مُستبعدة من `.gitignore`، لا
     تُشحن للإنتاج).
  2. لو كانت هذه فعلاً بيانات Postgres على Render: فإما أن أحداً طبّق
     الـmigration يدوياً هناك بطريقة غير موثّقة في هذا الملف (عبر `psql`
     مباشرة مثلاً)، أو أن جدول `findings` على Render لا يملك هذين العمودين
     أصلاً بعد — وفي هذه الحالة **كل** عملية حفظ Finding بعد نشر الكود الحالي
     (commit `a11cb90`، موجود فعلاً على `origin/master` والفرع الحالي متزامن
     معه تماماً) كانت ستفشل بخطأ Postgres صريح (`column "waf_detected" of
     relation "findings" does not exist`) وليس NULL صامت — وهذا سيناريو أخطر
     بكثير (توقف كامل لحفظ النتائج) كان سيظهر كخطأ 500 فوري في السجلات، وليس
     كصف NULL هادئ.

### استعلام SQL مقترح لحسم الأمر (لم يُنفَّذ — للتوثيق فقط)

```sql
-- توزيع NULL/غير-NULL حسب verdict — يحسم فوراً هل NULL متوقع تصميمياً
SELECT
    verdict,
    COUNT(*) AS total,
    COUNT(waf_detected) AS non_null_waf,
    COUNT(*) - COUNT(waf_detected) AS null_waf
FROM findings
GROUP BY verdict
ORDER BY verdict;

-- توزيع NULL حسب فترة زمنية (قبل/بعد نشر مهمة #10 بتاريخ 2026-07-02)
SELECT
    CASE WHEN created_at < '2026-07-02' THEN 'قبل الكلاسيفاير' ELSE 'بعد الكلاسيفاير' END AS period,
    COUNT(*) AS total,
    SUM(CASE WHEN waf_detected IS NULL THEN 1 ELSE 0 END) AS waf_null,
    SUM(CASE WHEN verdict IS NULL THEN 1 ELSE 0 END) AS verdict_null  -- verdict_null > 0 هنا = دليل على صفوف قديمة قبل الـmigration/الكلاسيفاير
FROM findings
GROUP BY period;
```

### الخلاصة والسبب الجذري الأرجح

1. **لا يوجد SQLite fallback في زمن التشغيل** (لا try/except، لا منطق يعيد
   التوجيه بعد فشل Postgres) — هذا مؤكد من قراءة الكود مباشرة.
2. **الأرجح بفارق كبير**: الـNULL في `waf_detected` سلوك مصمَّم عمداً — يعني
   ببساطة "لم يُكتشف WAF معروف في هذه الاستجابة تحديداً"، وهذا متوقع لغالبية
   النتائج `CONFIRMED` (يستحيل تصميمياً أن يكون لها WAF) وجزء كبير من باقي
   الحالات. **شغّل استعلام GROUP BY verdict أعلاه أولاً** — إن كانت كل صفوف
   NULL بها `verdict` غير فارغ (CONFIRMED أو غيره)، فلا يوجد bug هنا إطلاقاً.
3. **احتمال ثانوي يستحق التحقق**: إن وُجدت صفوف بـ`verdict IS NULL` أيضاً، فتلك
   صفوف قديمة سابقة على دمج الـclassifier (مهمة #10) أو سابقة على تطبيق
   الـmigration محلياً — مسألة **ترتيب زمني للنشر**، وليست SQLite fallback.
4. **الخطر الحقيقي الوحيد المكتشف** (كامن، غير مؤكد أنه السبب الحالي): إن لم
   يُضبط `DATABASE_URL` في بيئة Render فعلياً، سيعمل التطبيق صامتاً على SQLite
   محلي على فيلسستم مؤقت (لا قرص دائم مُعرَّف) — فقدان بيانات كامل عند أي
   redeploy، بدون أي خطأ ظاهر. يُنصح بالتحقق من قيمة `DATABASE_URL` الفعلية في
   لوحة Render مباشرة كخطوة أولى قبل أي استنتاج آخر.
5. لم يُوثَّق في أي مكان أن `migrate_add_finding_waf_columns.py`/
   `migrate_add_finding_include_in_report_column.py` طُبّقا فعلياً ضد Postgres
   الخاص بـRender — فقط ضد `data/optisec.db` المحلي. يجب التحقق من هذا قبل أي
   شيء آخر لأنه يحدد ما إذا كانت الـ64 صف قيد الفحص هي بيانات Render فعلاً أم
   بيانات التطوير المحلي.

### خطوات الإصلاح المقترحة (لم تُنفَّذ — تحتاج موافقة صريحة)

1. **أولاً وقبل أي شيء**: تأكيد من أين أتت الـ64 صف — استعلام مباشر عبر لوحة
   Render (أو `psql` بمفتاح اتصال Render الفعلي) للتحقق: هل `findings` على
   Postgres الإنتاج أصلاً تحتوي عمودي `waf_detected`/`verdict`؟ (`\d findings`
   في `psql`). إن كانت غائبة تماماً، فالـ64 صف قيد الفحص هي حتماً من SQLite
   المحلي وليست إنتاجاً.
2. تشغيل استعلامي الـSQL أعلاه (GROUP BY verdict، وحسب الفترة الزمنية) على أياً
   كانت القاعدة الفعلية قيد الفحص، لتأكيد أن NULL متوقع تصميمياً.
3. لو تبيّن أن Postgres الإنتاج فعلاً ناقص العمودين: تشغيل
   `python -m web.migrate_add_finding_waf_columns` و
   `python -m web.migrate_add_finding_include_in_report_column` **مع تصدير
   `DATABASE_URL` الصريح لقاعدة Render Postgres يدوياً في نفس الجلسة** (وليس
   الاعتماد على أي ملف `.env` محلي) — عبر الطريقة المتاحة فعلياً (endpoint مؤقت
   شبيه بـ`/internal/run-migration` الموجود لِـ`migrate_normalize_demo_severity`،
   أو أي وصول مباشر آخر لقاعدة Render).
4. تقوية الكود لمنع تكرار هذا اللبس مستقبلاً: عند `GROQ_ENV=production` أو
   `RENDER` مضبوطين، رفض الإقلاع صراحة (`raise RuntimeError`) إن كان
   `DATABASE_URL` غير مضبوط أو يبدأ بـ`sqlite`، بدل الرجوع الصامت الحالي —
   يحوّل أي خطأ ضبط مستقبلي من "صمت + احتمال فقدان بيانات" إلى فشل فوري وواضح
   في السجلات.
5. توحيد تعريف `DATABASE_URL` المكرر بين `config.py` و`web/database.py` في
   مكان واحد لتفادي أي تشتت مستقبلي.

---

## ملاحظة تصميمية (Design Note) — waf_detected/verdict، 2026-07-04

**لتفادي إعادة نفس التشخيص في جلسات قادمة** (فُحص هذا الموضوع بالتفصيل مرتين:
قسم "قرار: أعمدة WAF Classifier" في 2026-07-02، وقسم "تشخيص... waf_detected =
NULL؟" في 2026-07-04 أعلاه) — الخلاصة النهائية الثابتة:

- `Finding.waf_detected` كونه **NULL سلوك تصميمي متعمّد، وليس bug ولا مؤشر
  فقدان بيانات**.
- `verdict = CONFIRMED` → `waf_detected` **يُجبر دائماً إلى None** (الثغرة
  مؤكدة بالتعريف يعني عدم وجود WAF حجبها — لا علاقة للفحص التقني بـWAF هنا).
- `verdict = WAF_BLOCKED` → `waf_detected` **يستحيل أن يكون None** (الشرط
  الذي يدخل هذا الفرع يتطلب اسم WAF مكتشف أصلاً).
- `verdict ∈ {ENDPOINT_INVALID, ENCODED_SAFE, INCONCLUSIVE}` → `waf_detected`
  هو ببساطة نتيجة `detect_waf()` لتلك الاستجابة: اسم WAF إن طابقت توقيعاً
  معروفاً، أو None إن لم تطابق (شائع لأي هدف بلا WAF معروف من `WAF_SIGNATURES`).
- تم توثيق هذا الآن مباشرة في الكود (تعليقات فقط، لا تغيير منطقي):
  - `modules/vuln/waf_aware_classifier.py` — docstring كامل على
    `ClassificationResult` يشرح الحالات الخمس لـ`verdict` وقيمة `waf_detected`
    المتوقعة لكل واحدة، + تعليق مختصر عند كل نقطة تُجبر `waf_detected=None`.
  - `web/models.py` — تعليق مباشر فوق تعريف عمود `waf_detected`.
- **لا داعٍ لإعادة فتح هذا التحقيق مستقبلاً** إلا إذا ظهر دليل فعلي على صف
  بـ`verdict IS NULL` (يعني صفاً قديماً سابقاً على دمج الـclassifier — مسألة
  ترتيب نشر زمني، وليست هذا السلوك التصميمي).
- **729/729 اختبار ناجح** بعد هذه التعديلات (تعليقات/توثيق فقط، بدون تغيير
  منطقي) — نفس عدد الاختبارات السابق تماماً (لا اختبارات جديدة، ولا regressions).
  Commit: `d6712a2` — تم push إلى `origin/master`.

---

## المنجز (جلسة 2026-07-04، تكملة) — إكمال المرحلة 1 من IOC Detection

**المشكلة:** commit سابق (`c8036a0`، "feat: add idempotent migration script
for iocs table") دفع فقط ثلاثة ملفات (`web/migrate_add_ioc_table.py`،
`migrations/README_ioc_migration.md`، `tests/test_migrate_add_ioc_table.py`)
بينما بقيت `web/models.py` (تحتوي `class Ioc` نفسه)، `modules/ioc/`
(`IOCEngine`)، و`tests/test_ioc_engine.py` غير ملتزمة محلياً — أي أن السكربت
المدفوع على `master` كان يستورد `from web.models import Ioc` وهي غير موجودة
أصلاً على ذلك الفرع.

**التحقق قبل الـcommit:**
- تأكدت أن `web/models.py` يحتوي `class Ioc` (جدول `iocs`) مطابقاً لِما يتوقعه
  `migrate_add_ioc_table.py` — السكربت يبني `CREATE TABLE` مباشرة من
  `Ioc.__table__` (لا أسماء أعمدة مكتوبة يدوياً في السكربت)، فالتطابق مضمون
  هيكلياً بمجرد وجود الكلاس، وكذلك اختبارات `test_migrate_add_ioc_table.py`
  تشتق توقعاتها ديناميكياً من نفس `Ioc.__table__`.
- شُغّل test suite الكامل: **763/763 اختبار ناجح** (بينها 73 اختبار متعلق
  بـIOC تحديداً: `test_ioc_engine.py` + `test_migrate_add_ioc_table.py`) — لا
  فشل، لا regressions.
- لم يُشغَّل `migrate_add_ioc_table.py` ولم يُتصل بأي `DATABASE_URL` إنتاجي —
  هذه المهمة كانت فقط استكمال الكود المفقود محلياً.

**الملفات المُلتزَمة (commit `f621167`، بعده push إلى `origin/master`):**
- `web/models.py` — إضافة `class Ioc` (جدول `iocs`: `ioc_type`/`ioc_value`
  بقيد `UniqueConstraint`، `source`، `confidence_score`، `first_seen`/
  `last_seen`، `related_finding_id` (FK اختياري لـ`Finding`)، `tags` JSON،
  `is_active`) — تصميم *مخزن IOC محلي* منفصل تماماً عن
  `modules/ioc_correlation.py` الموجود أصلاً خلف صفحة `/correlations`
  (ذاك يُرابط IOCs من feeds عامة (OTX + عيّنة ثابتة) مع بعضها، ولا يلمس هذا
  الجدول أو بيانات فحوصات هذا المشروع إطلاقاً؛ التوثيق كامل في docstring
  الكلاس).
- `modules/ioc/ioc_engine.py` (+`modules/ioc/__init__.py`) — **جديد**:
  `IOCEngine` بواجهة `check_ioc()`/`enrich_ioc()`/`extract_iocs_from_finding()`
  تُغلّف عملاء threat-intel الموجودين أصلاً (`modules.threat_intel.ioc_detector`
  لـVirusTotal/AbuseIPDB) خلف مستودع injectable (`IOCRepository` — قاموس في
  الذاكرة حالياً، بنفس أشكال methods التي سيحتاجها مستودع مبني على جدول
  `Ioc` لاحقاً بدون إعادة كتابة منطق المحرك). `extract_iocs_from_finding()`
  يستخرج IOCs مرشّحة (روابط/IPs خارجية) من حقل `evidence` فقط في finding
  dict — يتجنّب عمداً `url`/`payload` لأنهما دوماً نطاق الهدف المفحوص أو
  payload الفحص المُحقَن، وليسا بنية هجومية مُلاحَظة فعلاً.
- `tests/test_ioc_engine.py` — **جديد**: اختبارات `IOCRepository`/`check_ioc`/
  `enrich_ioc`/`extract_iocs_from_finding`.

---

## تشخيص فشل endpoint IOC migration (جلسة 2026-07-04) — قراءة فقط، لم يُعدَّل أي كود

**العرض:** طلب `POST /internal/run-ioc-migration` على Render يرجع **404** رغم
أن الـtoken المُرسَل "صحيح" من وجهة نظر المستخدم، ورغم أن آخر deploy نجح
(commit `1f76cf1` — "feat: add temporary token-gated endpoint to run IOC table
migration on production" — مدفوع فعلاً ومتطابق تماماً مع `origin/master`،
تحقّقت بـ`git log origin/master..HEAD` = فارغ).

### 1. شرط تسجيل الـ route — `web/app.py:2122`

```python
if os.environ.get("GROQ_ENV") == "production" or os.environ.get("RENDER"):
    ...
    @app.post("/internal/run-migration", ...)      # سطر 2125
    ...
    @app.post("/internal/run-ioc-migration", ...)  # سطر 2147
```

كلا الـendpoint (القديم `/internal/run-migration` والجديد `/internal/run-ioc-migration`)
مُسجَّلان **معاً** تحت نفس الشرط الواحد. اسم المتغيّر بالضبط: `RENDER` (بدون أي
لاحقة)، أو بديلاً `GROQ_ENV == "production"` (مطابقة نصية حصراً، حساسة لحالة
الأحرف والقيمة الدقيقة). لا يوجد أي منطق آخر يتحكم بتسجيل هذا الـroute.

`grep` عبر المشروع (`web/app.py`، `config.py`، `.env.example`، `README.md`) لا
يُظهر أي استخدام آخر لاسم `RENDER` أو `GROQ_ENV` خارج هذا الشرط والاختبارات —
الاسم دقيق ولا يوجد تشتت/typo بين الملفات.

### 2. ما الذي يضبطه Render فعلياً — تحقّقت من توثيق Render الرسمي

بحثت في `render.com/docs/environment-variables` (Default Environment
Variables): Render يضبط تلقائياً متغيّر `RENDER=true` على **كل** خدمة، في وقت
البناء والتشغيل معاً، بدون أي إعداد يدوي من المستخدم. أي أن شرط
`os.environ.get("RENDER")` في `web/app.py:2122` **يجب أن يتحقق تلقائياً بمجرد
التشغيل على Render** — هذا الجزء من الشرط ليس مصدر المشكلة على الأرجح، لأنه لا
يحتاج أي إعداد يدوي أصلاً (بخلاف `GROQ_ENV` الذي هو فعلاً بديل يدوي احتياطي).

**الخلاصة الجزئية:** لو لم يكن الـroute مُسجَّلاً إطلاقاً، لكان
`/internal/run-migration` (الـendpoint الأقدم، المُستخدم فعلاً وناجح سابقاً حسب
السجل) يفشل أيضاً بنفس الطريقة — لا يوجد ما يشير إلى أن هذا الشرط تحديداً هو
السبب.

### 3. السبب الجذري الأرجح — تصميم الـ404 المتعمّد يُخفي فشل مصادقة عن غياب الإعداد

من `web/app.py:2147-2155`:

```python
@app.post("/internal/run-ioc-migration", include_in_schema=False)
async def run_ioc_table_migration(request: Request):
    expected_token = os.environ.get("IOC_MIGRATION_TOKEN")
    provided_token = request.headers.get("X-Migration-Token")
    if not expected_token or not provided_token or not _secrets_compare.compare_digest(
        provided_token, expected_token
    ):
        raise HTTPException(404, "Not Found")
```

هذا التصميم **مقصود وموثّق صراحة في التعليق أعلى الكود** (سطر 2143-2144: "يرجع
404 وليس 401/403 حتى لا يُكشَف عن وجود الـendpoint لأي فحص غير مصرَّح") — ومؤكَّد
باختبار صريح `tests/test_ioc_migration_endpoint.py::test_no_secret_configured_returns_404`
الذي يثبت أن **غياب `IOC_MIGRATION_TOKEN` من البيئة يُنتج 404 مطابقاً تماماً**
لحالتي "token خاطئ" و"الـroute غير مسجَّل أصلاً" — الحالات الثلاث لا يمكن
تمييزها من طرف العميل إطلاقاً.

**النقطة الحاسمة:** `IOC_MIGRATION_TOKEN` هو متغيّر بيئة **جديد تماماً**، أُضيف
في نفس commit الذي أضاف الـendpoint نفسه (`1f76cf1`)، ومنفصل كلياً عن
`MIGRATION_SECRET_TOKEN` (المستخدم في `/internal/run-migration` الأقدم والذي
يبدو أنه أُعِدّ ونجح سابقاً). بحثت في `README.md` و`.env.example` و
`migrations/README_ioc_migration.md` عن أي ذكر لـ`IOC_MIGRATION_TOKEN` — **لا
يوجد أي ذكر إطلاقاً** في أي ملف توثيقي؛ الاسم موجود فقط داخل `web/app.py`
والاختبارات. كما أن `migrations/README_ioc_migration.md` نفسه (المكتوب *قبل*
إضافة هذا الـendpoint في commit سابق) يصف فقط تشغيل السكربت يدوياً عبر Render
Shell أو `DATABASE_URL` مباشرة — **لا يذكر الـendpoint أو الـtoken إطلاقاً**،
أي أنه لا يوجد أي مصدر توثيقي كان يُذكِّر بضبط `IOC_MIGRATION_TOKEN` يدوياً في
لوحة Render (وهي خطوة يدوية منفصلة عن `git push`/deploy — ضبط متغيّر بيئة على
Render لا يحدث تلقائياً بمجرد نجاح الـdeploy).

**السيناريو الأرجح:** الـdeploy نجح (الكود موجود، الـroute مُسجَّل لأن `RENDER`
مضبوط تلقائياً)، لكن **لم يُضبط `IOC_MIGRATION_TOKEN` كمتغيّر بيئة فعلي في لوحة
Render** لأنه لا يوجد أي تذكير/خطوة موثّقة تطلب ذلك (بخلاف `RENDER` الذي Render
يضبطه بنفسه). المستخدم "توكن صحيح" من منظوره (يرسل قيمة يعتقد أنها الصحيحة في
Header)، لكن السيرفر ليس لديه أي `expected_token` ليقارنها به (`None` → falsy)،
فيدخل الشرط `if not expected_token or ...` ويُرجع 404 — **بصرف النظر تماماً عن
قيمة الـtoken المُرسَل**. وبما أن هذا الـ404 مطابق حرفياً لحالة "route غير
موجود"، فمن الخارج يبدو الأمر وكأن الـendpoint "غير موجود" فعلاً، رغم أنه
مسجَّل ويعمل تماماً — فقط ينقصه الإعداد.

### 4. Trailing slash / 307 redirect — تحقّقت، مُستبعد

`grep` لم يُظهر أي route آخر مسجَّل بنفس المسار مع أو بدون trailing slash (لا
تعارض). المسار `/internal/run-ioc-migration` وحيد وواضح، ولا يوجد أي router
بـ`prefix="/internal"` قد يُسبّب ازدواجية تسجيل. هذا الاحتمال غير مرجّح إطلاقاً
كسبب — يستحق التحقق فقط إذا كان طلب المستخدم الفعلي (عبر curl/أداة أخرى) يضيف
`/` زائدة في نهاية المسار خطأً، وهو أمر لا يمكن تأكيده من الكود، بل من الطلب
الفعلي نفسه فقط.

### الخلاصة والإصلاح المقترح (لم يُنفَّذ — يحتاج تأكيداً ثم تنفيذاً صريحاً)

**السبب الجذري الأرجح بفارق كبير:** `IOC_MIGRATION_TOKEN` غير مضبوط كمتغيّر
بيئة في لوحة Render الفعلية (خطوة يدوية منسية، غير موثّقة في أي مكان)، وتصميم
الـ404 المتعمّد (لإخفاء وجود الـendpoint عن أي فحص) يجعل هذا الغياب **يبدو
تماماً** وكأن الـroute غير موجود من منظور طلب HTTP خارجي، رغم أن الـdeploy نجح
والـcode موجود ويعمل.

**خطوات الإصلاح المقترحة:**
1. تأكيد أولاً (بدون تخمين): الدخول إلى لوحة Render → Environment، والتحقق
   مباشرة هل `IOC_MIGRATION_TOKEN` موجود ضمن قائمة متغيّرات البيئة للخدمة أم لا.
   هذا يحسم الأمر فوراً بشكل قاطع دون الحاجة لأي تخمين إضافي.
2. لو كان غائباً: إضافته من لوحة Render بقيمة سرّية قوية (نفس القيمة التي
   سيرسلها المستخدم لاحقاً في Header الـ`X-Migration-Token`)، ثم الانتظار
   حتى يُعيد Render تشغيل الخدمة تلقائياً بعد حفظ متغيّر البيئة (Render يعيد
   deploy/restart تلقائياً عند تغيير env vars — ليس مجرد حفظ صامت).
3. بعد ذلك فقط: إعادة إرسال نفس طلب `POST /internal/run-ioc-migration` بنفس
   الـtoken — يُفترض أن يرجع 200 مع تفاصيل الجدول المُنشأ.
4. **ملاحظة تصميمية للمستقبل (اختيارية، ليست جزءاً من هذا الإصلاح الفوري):**
   بما أن الـ404 الموحَّد يُصعِّب فعلياً تشخيص "الإعداد ناقص" مقابل "لا صلاحية"،
   قد يكون من المفيد لاحقاً إضافة تسجيل (logging) من جانب السيرفر فقط (لا يظهر
   للعميل) يُميّز صراحة بين حالة `expected_token` غائب تماماً وحالة token خاطئ
   فعلاً — لتسريع أي تشخيص مشابه مستقبلاً دون كشف أي شيء للعميل الخارجي. هذا
   اقتراح توثيقي فقط، لم يُنفَّذ ولا يُنصح بتنفيذه دون موافقة صريحة لأنه تعديل
   على endpoint إنتاجي حسّاس.

---

## إصلاح: سطور [DIAG] لا تظهر في سجلات Render (جلسة 2026-07-04، تكملة)

**المشكلة:** سطرا `[DIAG startup]` و`[DIAG request]` (أُضيفا بـcommit `a84da30`
عبر `logging.info(...)`) لم يظهرا إطلاقاً في سجلات Render، حتى سطر الـstartup.

**السبب الجذري:** لا يوجد `logging.basicConfig()` في أي مكان بالمشروع (تحقّقت
بـ`grep -rn "logging.basicConfig"` — لا نتيجة). الموضع الوحيد الذي يضبط
`setLevel` هو `web/auth.py::_auth_logger`، وهو logger معزول تماماً بـ
`FileHandler` خاص به على `optisec.auth`، لا علاقة له بالـroot logger. الأمر
الفعلي على Render (موثّق في `README.md`): `uvicorn web.app:app --workers 2`
بدون أي `--log-level`. uvicorn يضبط فقط loggers الخاصة به
(`uvicorn`/`uvicorn.error`/`uvicorn.access`) — **لا يلمس الـroot logger
إطلاقاً**. فيبقى الـroot logger عند مستواه الافتراضي `WARNING`، وأي
`logging.info(...)` يُستدعى عبره (بما فيها سطرا [DIAG]) يُستبعد صامتاً قبل أي
handler.

**الإصلاح في `web/app.py`:**
1. سطر `[DIAG startup]` (داخل `startup()`) — `logging.info` → `print(...,
   flush=True)`.
2. سطر `[DIAG request]` (داخل `run_ioc_table_migration`) — نفس التحويل.
3. سطر جديد `[DIAG module-load]` على مستوى الموديول، قبل شرط
   `if os.environ.get("GROQ_ENV")...` مباشرة (يُنفَّذ فوراً عند استيراد
   `app.py`، خارج أي دالة) — يطبع قيمتَي `GROQ_ENV`/`RENDER` الفعليتين وهل تم
   تسجيل راوترَي `/internal/run-migration` و`/internal/run-ioc-migration`
   (`REGISTERED`) أو تخطيهما (`SKIPPED`).
4. تحقّقت يدوياً (`python -c "import web.app"` مع/بدون `RENDER=true`) أن
   السطر الجديد يطبع القيمة الصحيحة في كلا الفرعين.
- **769/769 اختبار ناجح** — لا regressions.
- Commit + push إلى `origin/master` بموافقة صريحة.

---

## خلاصة حل مشكلة IOC migration endpoint (جلسة 2026-07-04، تنظيف نهائي)

**السبب الجذري المؤكَّد:** لم يكن السبب غياب `IOC_MIGRATION_TOKEN` نفسه، بل
تأخر تفعيل Auto-Deploy على Render بعد تحديث Environment Variables — عدة
طلبات `curl` متتالية كانت فعلياً تصل نسخة **قديمة** من الكود (قبل تسجيل
الـroute أو قبل ضبط التوكن)، رغم أن واجهة Render كانت تُظهر القيمة الجديدة
للمتغيّر بالفعل. القيمة "الجديدة" في الواجهة لا تعني أن الـdeploy الذي
يخدمها فعلياً قد اكتمل بعد.

**الدرس المستفاد:** بعد أي "Environment updated" في Render، يجب التحقق من
ظهور حدث "Deploy live" **بتوقيت لاحق فعلي** لذلك التحديث في تبويب Events —
قبل افتراض أن التغيير نافذ فعلاً على النسخة التي تخدم الطلبات. الاعتماد على
ظهور القيمة الجديدة في شاشة Environment وحده غير كافٍ لتأكيد النفاذ.

**النتيجة النهائية:** بعد التحقق من نفاذ الـdeploy، نجح
`POST /internal/run-ioc-migration` فعلياً على الإنتاج
(`{"success": true, "table": "iocs", ...}`, `created: false` لأن الجدول كان
موجوداً مسبقاً من محاولة ناجحة سابقة). جدول `iocs` **مؤكَّد وموجود على قاعدة
بيانات الإنتاج**.

**تنظيف ما بعد النجاح (هذه المهمة):**
- حُذف بالكامل من `web/app.py`: endpoint `POST /internal/run-ioc-migration`
  (المنطق كاملاً)، سطر `[DIAG module-load]`، سطر `[DIAG startup]`، وسطر
  `[DIAG request]` (حُذف تلقائياً مع حذف الـendpoint). الـendpoint القديم
  المنفصل `/internal/run-migration` (لـ`migrate_normalize_demo_severity`)
  وما يشترك معه من `import secrets as _secrets_compare` **بقيا بلا تغيير**
  — غير مرتبطين بمشكلة IOC.
- `web/migrate_add_ioc_table.py` (السكربت المستقل نفسه) **لم يُمس** — يبقى
  في الكودبيس قابلاً لإعادة الاستخدام على أي بيئة أخرى مستقبلاً.
- `tests/test_ioc_migration_endpoint.py` **حُذف بالكامل** (6 اختبارات) — كانت
  مخصصة حصراً للـendpoint المحذوف ولم تعد قابلة للتطبيق.
- `migrations/README_ioc_migration.md` — حُدِّث سطر الحالة من "not applied"
  إلى "applied to production" مع توثيق تاريخ التنفيذ والـendpoint المؤقت
  (المحذوف الآن) الذي نُفِّذ عبره.
- **763/763 اختبار ناجح** (769 السابقة − 6 اختبارات الـendpoint المحذوف) —
  لا فشل، لا regressions.
- لم يُنفَّذ أي commit/push بعد — بانتظار مراجعة المستخدم وتأكيده الصريح.

---

## تشخيص RuntimeError - Dark Web Scheduler (جلسة 2026-07-04) — قراءة/تحليل فقط، لم يُعدَّل أي كود

الخطأ في سجلات الإنتاج:
```
RuntimeError: Task <Task pending name='Task-X' coro=<run_scheduled_scan() running at
/app/modules/darkweb/scheduler.py:140> cb=[_run_until_complete_cb() at
.../asyncio/base_events.py:181]> got Future <Future pending cb=[BaseProtocol._on_waiter_completed()]>
attached to a different loop
```

### 1. كيف يُجدوَل `run_scheduled_scan()`
- `modules/darkweb/scheduler.py` يستخدم **APScheduler `BackgroundScheduler`** (سطر 210) — هذا Scheduler يعمل في **ثريد منفصل خاص به**، وليس على event loop التطبيق (uvicorn/FastAPI).
- كل جولة، APScheduler ينادي `_run_scan_job()` (سطر 192) على ذلك الثريد، وهي دالة **sync** تستدعي:
  ```python
  asyncio.run(run_scheduled_scan())
  ```
  `asyncio.run()` تُنشئ **event loop جديد تماماً** في كل استدعاء، وتُغلقه عند الانتهاء. أي أن كل جولة فحص (كل `DARKWEB_SCAN_INTERVAL_HOURS`، وأول مرة بعد 60 ثانية من الإقلاع) تُشغَّل على loop مختلف عن سابقتها، وكلها مختلفة عن loop التطبيق الرئيسي.
- القفل المُشار إليه سابقاً (`SchedulerLock`، تحديث شرطي ذري عبر DB) موجود ويعمل كما هو مطلوب لمنع تشغيل مزدوج بين الـ2 workers على Render — لكنه **غير متعلق** بهذا الخطأ؛ الخطأ سببه event loops متعددة ضمن نفس الـprocess، وليس تعدد الـworkers.
- أول استدعاء async يعتمد على DB داخل `run_scheduled_scan()` هو بالضبط سطر 140:
  ```python
  async with _db.SessionLocal() as db:      # سطر 139
      acquired = await _acquire_lock(db, ...)  # سطر 140 — هنا بالضبط يظهر في الـtraceback
  ```

### 2. تهيئة event loop على مستوى التطبيق
- `web/database.py` (سطر 10-11): `engine`/`SessionLocal` **singletons على مستوى الموديول** — يُنشآن مرة واحدة عند استيراد الموديول، ويُستخدَمان من كل مكان في التطبيق (كل الـrouters + `web/app.py` + الـscheduler) دون أي تمييز لأي loop.
- `web/app.py` (`@app.on_event("startup")`, سطر 496-503): `await init_db()` يُنفَّذ على **loop التطبيق الرئيسي** (uvicorn)، وهذا أول استخدام فعلي لـ`engine` — أي أول اتصال asyncpg حقيقي يُفتح وُيوضع في الـconnection pool يكون **مربوطاً بـloop التطبيق الرئيسي**.
- مباشرة بعد ذلك، ضمن نفس دالة `startup()`، يُستدعى `start_scheduler()` — الذي يُشغّل `BackgroundScheduler` على ثريد منفصل كما ذُكر أعلاه.
- **لا يوجد أكثر من event loop نشط في نفس اللحظة** بالمعنى التقليدي (uvicorn's loop نشط طوال الوقت، وكل استدعاء `asyncio.run()` من ثريد الـscheduler ينشئ loop مؤقت يُغلق بعد كل جولة) — لكن المشكلة ليست "أكثر من loop نشط بالتزامن"، بل **إعادة استخدام نفس الـconnection pool عبر loops متعاقبة/مختلفة**.

### 3. السبب الجذري الدقيق
`engine = create_async_engine(DATABASE_URL)` في `web/database.py` ينشئ **connection pool واحد على مستوى العملية (process)** (افتراضياً `AsyncAdaptedQueuePool`). اتصالات asyncpg الفعلية داخل هذا الـpool تبقى مرتبطة داخلياً (عبر Future/waiter objects) بـevent loop الذي كان نشطاً وقت إنشاء كل اتصال:

1. عند startup، `init_db()` يفتح أول اتصال على **loop التطبيق الرئيسي (uvicorn)** ويُعاد للـpool (idle) بعد الانتهاء من `engine.begin()`.
2. بعد 60 ثانية، أول جولة scheduler تستدعي `asyncio.run(run_scheduled_scan())` فتُنشئ **loop جديد (Loop B)**. عندما تطلب `_db.SessionLocal()` اتصالاً من الـpool المشترك، الـpool (الذي لا يعرف شيئاً عن event loops) قد يُعيد **نفس الاتصال الذي فُتح على loop التطبيق الرئيسي**.
3. أول `await` فعلي على ذلك الاتصال تحت Loop B (هنا بالضبط `await _acquire_lock(...)` في سطر 140) يحاول انتظار Future/waiter داخلي تابع لـasyncpg كان قد أُنشئ أصلاً مرتبطاً بـloop التطبيق الرئيسي → أسينكيو يرفض فوراً بـ`RuntimeError: ... attached to a different loop`.
4. نفس المشكلة تتكرر بين جولات الـscheduler نفسها: كل جولة تخلق loop جديد بواسطة `asyncio.run()`، فأي اتصال بقي idle في الـpool من جولة سابقة (Loop سابق أُغلق) سيُعاد استخدامه تحت loop الجولة الحالية → نفس الخطأ.

**خلاصة السبب**: نعم، هذا بالضبط النمط الشائع لهذا الخطأ — لكن ليس "الـscheduler ينشئ اتصال على loop مختلف عن اللي ينفذ فيه الاستعلام" بالمعنى الحرفي لعملية واحدة، بل **مشاركة نفس connection pool (نفس `engine`/`SessionLocal` على مستوى الموديول) بين loop التطبيق الرئيسي وbين loops مؤقتة متعددة يخلقها `asyncio.run()` في كل جولة scheduler** — وهذا استخدام غير مدعوم أصلاً من asyncpg/SQLAlchemy async (اتصال واحد لا يجوز استخدامه إلا على نفس الـloop الذي أُنشئ عليه).

### 4. هل هذا يعطّل الوظيفة فعلياً أم مجرد تحذير غير مؤثر؟
**يعطّل الوظيفة فعلياً — ليس تحذيراً بلا أثر.** بالتفصيل:

- لا يوجد أي `try/except` حول السطرين 139-140 داخل `run_scheduled_scan()` نفسها. الـ`try/finally` الوحيد يبدأ في السطر 147 — أي **بعد** نقطة فشل `_acquire_lock`. فإذا رمى asyncpg الخطأ عند السطر 140، الاستثناء يتصاعد ليخرج من `run_scheduled_scan()` بالكامل **قبل** الوصول لأي منطق فحص المراقبات (`due_ids`, حلقة `run_check_and_persist`, إلخ).
- الاستثناء يُمسَك فقط في `_run_scan_job()` (سطر 192-197) عبر `except Exception: logger.exception(...)` — هذا يمنع تحطم ثريد الـscheduler/العملية، لكنه يعني أن **الجولة كاملة تُلغى صامتاً (بعد تسجيلها كـexception في اللوج) بدون فحص أي هدف واحد من `DarkWebMonitor`**. لا يُحدَّث `_last_run_summary`، ولا تُحفَظ أي تنبيهات جديدة، ولا يتقدّم `last_checked_at` لأي هدف.
- نظراً لأن الفشل يحدث عند أول `await` فعلي على الاتصال (على الأرجح أثناء تنفيذ/checkout الاتصال نفسه، قبل أن يُنفَّذ أي SQL فعلياً) — فمن المرجّح أن تحديث `SchedulerLock` (الـUPDATE الذري) **لم يُنفَّذ ولم يُلتزَم (commit)** بعد، أي أن القفل على الأرجح **لا يبقى عالقاً (stuck)** بسبب هذا العطل تحديداً. لكن هذا استنتاج مبني على فهم سلوك asyncpg/SQLAlchemy المعتاد، وليس تتبعاً حياً لمكان الفشل بالضبط داخل `_acquire_lock` — يحتاج تأكيداً بإعادة إنتاج محلية لو أردنا يقيناً كاملاً.
- الأثر العملي: **فحص Dark Web الدوري لا يكتمل أبداً تلقائياً** (أو يكتمل بشكل متقطّع فقط حين يحصل أن الـpool يُعطي اتصالاً جديداً تماماً بدل واحد قديم من loop آخر) — وهذا يفسّر تكرار نفس الخطأ في السجلات: **كل جولة تقريباً تفشل بنفس الطريقة**، لأن الـpool يستمر بإعادة تدوير اتصالات "ملوّثة" بـloops سابقة طالما لم يُعَد تشغيل العملية بالكامل.

### الإصلاح المقترح (لم يُنفَّذ — اقتراح فقط)
الخيار الموصى به: **إبقاء `BackgroundScheduler` على ثريده الخاص (كما هو مصمَّم فعلاً، لأسباب موثّقة في docstring الموديول — فصل توقيت الجدولة عن انشغال loop التطبيق)، لكن تنفيذ الكوروتين فعلياً على نفس event loop الذي يملك `engine`/`SessionLocal` المشترك، بدل `asyncio.run()` الذي يخلق loop جديد كل مرة**:

1. عند `start_scheduler()` (يُستدعى من داخل `async def startup()` في `web/app.py` — أي أثناء تنفيذه، loop التطبيق الرئيسي هو الـrunning loop) التقط مرجع الـloop عبر `asyncio.get_running_loop()` واحتفظ به في متغيّر معياري (module-level) في `scheduler.py`.
2. استبدل `asyncio.run(run_scheduled_scan())` في `_run_scan_job()` بـ:
   ```python
   future = asyncio.run_coroutine_threadsafe(run_scheduled_scan(), app_loop)
   future.result()  # حظر ثريد الـscheduler الخاص فقط، لا يؤثر على loop التطبيق
   ```
   بهذا الشكل: APScheduler ما زال يطلق الجولة من ثريده الخاص بنفس التوقيت المُجدوَل، لكن كل عمليات الـDB الفعلية للـcoroutine تُنفَّذ **على نفس loop التطبيق** الذي يملك الـconnection pool أصلاً — فلا يحدث تصادم loops مطلقاً، وكل اتصال يُستخدم دائماً على نفس الـloop الذي فُتح عليه.
3. بديل معماري أوسع (أكثر تغييراً): استبدال `BackgroundScheduler` بـ`AsyncIOScheduler` (من نفس مكتبة APScheduler)، الذي يُجدوِل الكوروتينات مباشرة على event loop التطبيق دون ثريد منفصل أو `asyncio.run()` إطلاقاً — يُلغي المشكلة جذرياً، لكنه يغيّر طريقة `start_scheduler()`/`stop_scheduler()` (يجب استدعاؤه من داخل loop التطبيق فقط، وهو الحال فعلاً في `startup()`/`shutdown()` الحاليين، فالتغيير سطحي نسبياً).
4. **غير مستحسن**: إنشاء `engine` منفصل بالكامل داخل كل استدعاء `asyncio.run()` (محلي لكل جولة، يُتخلَّص منه في نهايتها) — يحل المشكلة تقنياً لكنه يُفقِد فائدة الـpooling تماماً ويُضيف overhead إنشاء/إغلاق اتصالات جديدة في كل جولة scheduler دون داعٍ حقيقي.

لم يُطبَّق أي من هذه الخيارات — بانتظار موافقة صريحة قبل التنفيذ.

### ✅ تم التنفيذ (جلسة 2026-07-04، تكملة) — الخيار الموصى به: `run_coroutine_threadsafe`
- `modules/darkweb/scheduler.py`:
  - `start_scheduler(loop=None)` — بارامتر جديد اختياري؛ يلتقط event loop التطبيق (`asyncio.get_running_loop()` افتراضياً إن لم يُمرَّر) ويخزّنه في `_app_loop` (متغيّر معياري جديد على مستوى الموديول).
  - `_run_scan_job()` — استُبدل `asyncio.run(run_scheduled_scan())` بـ:
    ```python
    future = asyncio.run_coroutine_threadsafe(run_scheduled_scan(), _app_loop)
    future.result()
    ```
    الآن كل جولة (رغم إطلاقها من ثريد `BackgroundScheduler` الخاص) تُنفَّذ فعلياً على نفس loop التطبيق الذي يملك الـconnection pool المشترك — لا يوجد أي loop جديد يُنشأ بعد الآن، فلا تصادم بين loops إطلاقاً.
  - `stop_scheduler()` — يُصفّر `_app_loop = None` أيضاً عند الإيقاف (تنظيف كامل للحالة).
  - تحديث docstring الموديول ليشرح التصميم الجديد بدل الإشارة لـ`asyncio.run()`.
- `web/app.py` (`startup()`, سطر ~502): `start_scheduler(asyncio.get_running_loop())` — تمرير صريح للـloop بدل الاعتماد الضمني على auto-detect.
- `tests/test_darkweb_scheduler.py` — 4 اختبارات كانت تستدعي `start_scheduler()`/`_run_scan_job()` بشكل متزامن خارج أي loop نشط، فكسرها التغيير (كانت تعتمد على `asyncio.run()` القديم ضمنياً):
  - 3 اختبارات ضمن `TestLifecycle` (`test_start_scheduler_runs_and_configures_interval`, `test_start_is_idempotent`, `test_get_status_reflects_running_state`) — عُدِّلت لتمرير `asyncio.new_event_loop()` صراحة لـ`start_scheduler()` (لا حاجة لتشغيله فعلياً — الجولة الأولى مجدولة بعد 60 ثانية، خارج نطاق هذه الاختبارات).
  - `TestRunScanJob.test_never_raises_even_if_the_sweep_crashes` — أُعيدت كتابته ليُحاكي طوبولوجيا الإنتاج الحقيقية: event loop يعمل على ثريد خاص به (يمثّل loop التطبيق)، بينما ثريد الاختبار الرئيسي (يمثّل ثريد APScheduler) يستدعي `_run_scan_job()` مباشرة — يتحقق أن `run_coroutine_threadsafe(...).result()` يلتقط الاستثناء عبر حدود الثريدز بشكل صحيح ولا يُسقط شيئاً.
- **763/763 اختبار ناجح** على كامل test suite (لا regressions) — تشغيل `tests/test_darkweb_scheduler.py` وحده أيضاً: **23/23 ناجح**.
- تحقّق حي: تشغيل `uvicorn web.app:app` فعلياً (بدء وإيقاف كاملين) لتأكيد أن `start_scheduler(asyncio.get_running_loop())` لا يرمي أي استثناء ضمن `async def startup()` الحقيقي، وأن `stop_scheduler()` يُنظّف الحالة دون أخطاء عند الإغلاق.

---

## المنجز (جلسة 2026-07-04، تكملة) — المرحلة 2 من IOC Detection: ربط IOCEngine بقاعدة بيانات حقيقية ومسارات الفحص الحية

**الهدف:** استبدال `IOCRepository` الوهمي (in-memory dict، المرحلة 1) بتطبيق حقيقي فوق جدول `iocs`
(`web.models.Ioc`)، وربط الاستخراج التلقائي بمسار حفظ الـFindings، وإضافة endpoint قراءة. لم يُتصل
بأي قاعدة بيانات إنتاجية ولا Render في هذه المهمة — SQLite في الذاكرة فقط للاختبارات.

**قرار معماري جوهري:** طبقة الـDB في المشروع بالكامل async-only (`web/database.py`'s
`SessionLocal` هو `async_sessionmaker`، لا يوجد أي مسار sync للوصول لقاعدة البيانات في أي مكان آخر
بالكودبيس). لذا `IOCRepository` الجديد يأخذ `AsyncSession` مُمرَّرة من المتصل (نفس اتفاقية كل
راوتر آخر: `web/routers/honeypot.py`، `darkweb_monitor.py` — المستودع فقط يعمل `add()`/`flush()`،
والمتصل يملك الـcommit). هذا يعني `IOCEngine.enrich_ioc()` (الدالة الوحيدة التي تكتب للمستودع)
أصبحت `async def` بعد أن كانت `def` — التغيير الوحيد في التوقيعات، وضروري وليس اختيارياً. أما
`check_ioc()` و`extract_iocs_from_finding()` فبقيتا sync تماماً كما كانتا (لا تلمسان الـDB إطلاقاً).

**1. `modules/ioc/ioc_engine.py`:**
- `IOCRepository` أُعيدت كتابته بالكامل: `get_by_value`/`create`/`update_last_seen`/`list_active`
  (CRUD المطلوب حرفياً) + `upsert()` (تُبقيها كما هي — get_by_value ثم create أو update_last_seen —
  حتى لا يتغيّر استدعاء `enrich_ioc()` الوحيد لها). كلها `async` وتستعلم/تكتب فعلياً على
  `web.models.Ioc` عبر `sqlalchemy.select`.
- `IOCEngine.__init__`: `repository` افتراضيًا `None` الآن (لم يعد هناك مستودع افتراضي في الذاكرة) —
  `check_ioc`/`extract_iocs_from_finding` لا يحتاجان مستودعاً أصلاً، و`enrich_ioc` يتجاوز الحفظ
  بأمان إن كان `repository=None`.
- استيراد `web.models.Ioc` يتم داخل كل دالة (lazy import)، بنفس اتفاقية
  `modules/honeypot/manager.py`/`modules/darkweb/scheduler.py` — وليس على مستوى الموديول.

**2. الدمج التلقائي مع مسار الفحص (`web/app.py`):**
- نقطة حفظ الـFinding الوحيدة في المشروع (`_run_scan_task`, حوالي السطر 1522 — تُغذّى من
  الماسحات الخمسة XSS/SQLi/SSRF/LFI/Open Redirect معاً، لا يوجد أكثر من موضع واحد لحفظ Finding)
  عُدّلت: تحتفظ الآن بمرجع كل `Finding` بعد `db.add()`، ثم `await db.flush()` (لتعبئة `row.id` قبل
  أي استخدام)، ثم تستدعي دالة جديدة `_extract_and_store_iocs(db, finding_rows)`.
- `_extract_and_store_iocs()` (دالة جديدة top-level): لكل Finding محفوظ، تبني `IOCEngine()` بدون
  مستودع (فقط لاستدعاء `extract_iocs_from_finding()` — لا شبكة، لا VirusTotal/AbuseIPDB)، ثم تحفظ
  كل مرشّح عبر `IOCRepository(db).upsert(...)` مباشرة — **بدون** المرور عبر `enrich_ioc()`/
  `check_ioc()`، تفادياً لاستدعاء threat-intel APIs حقيقية تلقائياً على كل finding (قرار متعمّد: لم
  يُطلب إثراء تلقائي، فقط استخراج وتخزين محلي).
- **غير معطِّل تماماً**: `try/except Exception` حول معالجة كل finding على حدة (وليس حول الحلقة
  كاملة) — فشل استخراج/حفظ IOC واحد لا يمنع بقية الـFindings من أن تُعالَج، ولا يمنع `db.commit()`
  النهائي لكل Findings الفحص من النجاح. نفس اتفاقية `modules/honeypot/manager.py::record_event`
  (`except Exception: logger.exception(...)`).

**3. Endpoint جديد — `web/routers/ioc.py` (`GET /api/iocs`):**
- `prefix="/api/iocs"`, tag جديد `"ioc"` (أُضيف لقائمة `openapi_tags` في `web/app.py`)، مسجَّل عبر
  `app.include_router(ioc_router.router)`.
- فلترة اختيارية `ioc_type` (يرفض بـ400 أي قيمة خارج `IOC_TYPES` الست) و`is_active`
  (`None` افتراضياً = لا فلترة، يعرض النشط وغير النشط معاً)، pagination عبر `limit`/`offset`
  (نفس حدود `web/routers/honeypot.py`: `max(1, min(limit, 200))`).
- يتطلب مستخدماً مسجَّل دخوله (`get_current_user`)، بنفس نمط `_user()` المُستخدَم في كل راوتر آخر.

**4. الاختبارات:**
- `tests/test_ioc_engine.py` أُعيدت كتابته بالكامل: `TestIOCRepository` تستخدم الآن SQLite حقيقية
  في الذاكرة (fixture `db_factory`، نفس نمط `tests/test_honeypot.py`) بدل قاموس وهمي؛
  `TestEnrichIoc` أصبحت async (`_run(engine.enrich_ioc(...))`)، تختبر كلا الحالتين
  (`repository=None` بدون حفظ، ومستودع حقيقي بحفظ فعلي). `TestCheckIoc`/`TestExtractIocsFromFinding`
  بقيتا بلا تغيير (sync، لا DB). أُضيف `TestExtractThenPersistIntegration` (استخراج من finding حقيقي
  ثم حفظ عبر `IOCRepository` فعلياً، مع التحقق من `related_finding_id`).
- `tests/test_ioc_router.py` **جديد**: يستدعي `list_iocs()` مباشرة (نفس اتفاقية استدعاء دوال
  الراوتر مباشرة بدل TestClient المستخدمة في بقية ملفات اختبار الراوترات) — فلترة
  ioc_type/is_active، pagination، رفض ioc_type غير مدعوم (400)، و`_ioc_to_dict()`.
- `tests/test_ioc_scan_integration.py` **جديد**: يختبر `web.app._extract_and_store_iocs()` مباشرة
  ضد SQLite حقيقية — استخراج وحفظ IOC مرتبط بـ`related_finding_id`، عدم إنشاء صفوف عند عدم وجود
  مرشّحين، وأهم شيء: أن فشل الاستخراج (عبر `monkeypatch` على
  `IOCEngine.extract_iocs_from_finding` ليرمي استثناءً) **لا يمنع** حفظ الـFinding ولا يوقف معالجة
  بقية الـFindings في نفس الدفعة.
- **779/779 اختبار ناجح** على كامل test suite (763 سابقاً + 16 صافي) — لا فشل، لا regressions.

**تحقّق حي (محلي فقط، ليس إنتاجاً):** شُغّل `uvicorn web.app:app` محلياً، تسجيل دخول عبر `/demo`،
`GET /api/iocs` أرجع `{"iocs": [], "count": 0, "limit": 50, "offset": 0}` (200)، و
`GET /api/iocs?ioc_type=bogus` أرجع 400 مع رسالة الخطأ الصحيحة. تأكدت أيضاً (عبر `app.openapi()`،
وليس `app.routes` مباشرة — هذا الإصدار من FastAPI (0.138.1) يستخدم `_IncludedRouter` كغلاف كسول لا
يظهر كـ`Route` عادي في `app.routes`، وهذا موجود مسبقاً على `master` أيضاً وليس ناتجاً عن هذه
المهمة) أن `/api/iocs` مسجَّل بشكل صحيح في مخطط OpenAPI.

**لم يُنفَّذ:** لا اتصال بـRender/قاعدة بيانات إنتاجية، لا commit/push — بانتظار مراجعة المستخدم.

---

## تنظيف: حذف endpoint هجرة api_key_hash بعد نجاحه على الإنتاج (جلسة 2026-07-05)

**الخلفية:** endpoint المؤقّت `POST /internal/run-api-key-migration` (أُضيف في commit
`edf7719`) كان الطريقة الوحيدة لتشغيل `web/migrate_add_api_key_hash.py` على إنتاج Render
(لا يوجد Shell access في الخطة المجانية). الهجرة نجحت فعلياً على قاعدة بيانات الإنتاج —
عمود `users.api_key_hash` موجود الآن، لذا لم تعد الحاجة للـendpoint قائمة.

**تنظيف ما بعد النجاح:**
- حُذف بالكامل من `web/app.py`: الـendpoint `POST /internal/run-api-key-migration` (المنطق
  كاملاً، بما فيه الفحص عبر `API_KEY_MIGRATION_TOKEN`). الـendpoint المنفصل
  `/internal/run-migration` (لـ`migrate_normalize_demo_severity`) **بقي بلا تغيير** — غير
  مرتبط بهذه المهمة.
- `tests/test_api_key_migration_endpoint.py` **حُذف بالكامل** (3 اختبارات) — كانت مخصصة
  حصراً للـendpoint المحذوف.
- تعليق/تحذير الـstartup guard في `web/app.py` (حول `_users_table_has_api_key_hash()`)
  أُعيد صياغته: لم يعد يشير إلى endpoint محذوف، بل يوضّح أن الهجرة اكتملت على الإنتاج وأن
  الـguard باقٍ فقط كإجراء احترازي لأي بيئة أخرى ما زال العمود ناقصاً فيها (مع توجيه لتشغيل
  `web/migrate_add_api_key_hash.py` مباشرة في تلك الحالة).
- Commit `68fcfe2` (`chore: remove one-off api_key_hash migration trigger after production
  success`) — تم push إلى `origin/master`.

**تحقّق حي على الإنتاج بعد الـpush:** `curl` مباشر على `https://optisec-recon-pro.onrender.com/`
(200، صفحة Landing كاملة)، `/docs` (200، Swagger UI)، `/demo` (302 كما متوقَّع) — تأخر أول طلب
~30 ثانية بسبب cold start على الخطة المجانية، وبعدها استجابة أقل من ثانية على كل الطلبات. لا
crash-loop، لا regression. لم تُفحص سجلات Render مباشرة (لا يوجد Render CLI/API key مُعدّ في
هذه البيئة، وتقرّر عدم إعداد واحد) — الاعتماد كان على فحوصات curl فقط لتأكيد سلامة الإنتاج.

---

## تنظيف: حذف endpoint هجرة demo-severity المتبقّي (جلسة 2026-07-05، تكملة)

**الخلفية:** بعد حذف endpoint هجرة `api_key_hash`، تحقّقتُ من وجود أي endpoints هجرة مؤقّتة
أخرى متبقّية في `web/app.py`. وُجد `POST /internal/run-migration` (لـ
`web.migrate_normalize_demo_severity.migrate()`، محمي بـ`MIGRATION_SECRET_TOKEN`، مسجَّل فقط
عند `GROQ_ENV=production` أو `RENDER`) — وحسب `SESSION.md` (سطر ~648) كان قد نُفِّذ بنجاح على
الإنتاج مسبقاً، فلم تعد الحاجة له قائمة.

**تنظيف ما بعد النجاح:**
- حُذف بالكامل من `web/app.py`: كتلة `if os.environ.get("GROQ_ENV") == "production" or
  os.environ.get("RENDER"):` كاملة — كانت مخصصة حصراً لهذا الـendpoint (`import secrets as
  _secrets_compare` + الـroute نفسه)، فلا شيء آخر يعتمد عليها.
- `tests/test_migration_endpoint.py` **حُذف بالكامل** (3 اختبارات) — كانت مخصصة حصراً
  للـendpoint المحذوف.
- `config.py` (سطر ~39-41): تعليق كان يشير إلى `/internal/run-migration` كمثال على استخدام
  `GROQ_ENV` — أُزيلت الإشارة إلى الـroute المحذوف، مع إبقاء بقية التعليق (متغيّر `GROQ_ENV`
  نفسه ما زال مُستخدَماً في مكان آخر، بواسطة `_resolve_jwt_secret()`).
- **873/873 اختبار ناجح** — لا فشل، لا regressions.
- Commit `b3a1ebc` (`chore: remove one-off demo-severity migration trigger after production
  success`) — تم push إلى `origin/master`.

**تحقّق حي على الإنتاج بعد الـpush:** نفس الفحوصات عبر `curl` — `/` (200)، `/docs` (200)،
`/demo` (302) — هذه المرة بدون تأخر cold start (النسخة كانت لا تزال دافئة من الفحص السابق).

**النتيجة:** لا توجد أي endpoints هجرة مؤقّتة متبقّية في `web/app.py` (تم التأكد بالبحث عن
`TEMPORARY`/`/internal/run-`/`DELETE AFTER USE` عبر الملف بالكامل).

---

## المهام القادمة (جلسات مستقبلية)
- [ ] اختبار شامل وإصلاح أي bugs
- [ ] نشر على VPS / Docker
- [ ] إضافة email notifications
- [ ] تحسين أداء الفحوصات الموازية
- [ ] تفعيل Honeypot فعلياً على بيئة إنتاج معزولة (VPS/حاوية منفصلة) واختبار الالتقاط الحي
