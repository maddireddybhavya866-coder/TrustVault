# API / Route authorization reference

| Method | Route | Who may call | Server-side rule |
|---|---|---|---|
| GET, POST | `/register` | Public | New accounts always become viewer |
| GET, POST | `/login` | Public | Password hash verification |
| GET | `/logout` | Authenticated | Current session |
| GET | `/dashboard` | Authenticated | Admin sees all; others see owned/shared docs |
| GET, POST | `/upload` | Owner, Admin | Role check |
| GET | `/document/<id>` | Authenticated | Admin, owner or read/edit grant |
| GET | `/document/<id>/download` | Authenticated | Admin, owner or current read/edit grant |
| POST | `/document/<id>/edit` | Authenticated | Admin, owner or edit grant |
| POST | `/document/<id>/delete` | Authenticated | Admin or owner |
| POST | `/document/<id>/permissions` | Owner, Admin | Admin or document owner |
| GET | `/admin` | Admin | Role check |
| POST | `/admin/users/<id>/role` | Admin | Role check |

The route table is a concise summary. `app.py` is authoritative. Add CSRF protection before production deployment.
