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

## المهام القادمة (جلسات مستقبلية)
- [ ] اختبار شامل وإصلاح أي bugs
- [ ] نشر على VPS / Docker
- [ ] إضافة email notifications
- [ ] تحسين أداء الفحوصات الموازية
- [ ] تفعيل Honeypot فعلياً على بيئة إنتاج معزولة (VPS/حاوية منفصلة) واختبار الالتقاط الحي
