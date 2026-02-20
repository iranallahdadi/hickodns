# Hickory DNS Control Panel - UI Setup & Run Guide

A full-featured production-ready DNS management UI built with React, Vite, Tailwind CSS, and Playwright E2E tests.

## Features

✅ **Admin Panel**
- User management (CRUD with validation)
- Zone management with bulk import
- DNS record management (A, AAAA, CNAME, MX, TXT, SRV, NS)
- Server management
- GeoDNS rules with location-based routing
- Audit logs with CSV export
- Admin dashboard with real-time stats

✅ **User Panel**
- Self-service zone management
- Record creation and editing
- Limited access to assigned zones

✅ **Production Features**
- Dark mode with persistent preference
- Role-Based Access Control (RBAC)
- Form validation with inline errors
- CSV bulk import/export with templates
- Notifications/toasts
- Responsive design (desktop & mobile)
- Error handling and retry logic
- Comprehensive E2E tests

## Architecture

```
web/ui/
├── src/
│   ├── components/       # Reusable UI components
│   ├── contexts/         # Auth context
│   ├── hooks/            # Form validation & utilities
│   ├── pages/            # Page components
│   ├── api.js            # Axios instance
│   └── main.jsx          # App entry point
├── tests/
│   ├── e2e.spec.js       # Original E2E tests
│   ├── e2e.full.spec.js  # Comprehensive E2E tests
│   ├── fixtures/         # CSV test data
│   └── playwright.config.js
├── tailwind.config.cjs   # Tailwind CSS config
└── package.json
```

## Quick Start

### 1. Start Postgres

```bash
docker run -d --name hickory-postgres \
  -e POSTGRES_PASSWORD=password \
  -p 5432:5432 \
  postgres:15

sleep 3
docker exec hickory-postgres psql -U postgres -c "CREATE DATABASE hickory;"
```

### 2. Start Control API

```bash
export DATABASE_URL="host=127.0.0.1 user=postgres password=password dbname=hickory"
export ADMIN_USERNAME="admin"
export ADMIN_PASSWORD="admin123"
export JWT_SECRET="replace_with_a_super_secret"

cd ./
cargo build -p control_api --release
./target/release/control_api
```

API runs on `http://localhost:8080`

### 3. Start UI Dev Server

```bash
cd web/ui
npm install
npm run dev -- --port 3000
```

UI available at `http://localhost:3000`

### 4. Run Playwright E2E Tests

```bash
cd web/ui
npm run e2e:install  # First time only
npm run test:e2e
```

## API Endpoints

| Method | Endpoint | Purpose |
|--------|----------|---------|
| POST | `/api/v1/auth/login` | Login |
| GET | `/api/v1/zones` | List zones |
| POST | `/api/v1/zones` | Create zone |
| POST | `/api/v1/zones/bulk` | Bulk import zones |
| GET | `/api/v1/zones/:id/records` | List records |
| POST | `/api/v1/zones/:id/records` | Create record |
| POST | `/api/v1/zones/:id/records/bulk` | Bulk import records |
| PUT | `/api/v1/zones/:zone_id/records/:record_id` | Update record |
| DELETE | `/api/v1/zones/:zone_id/records/:record_id` | Delete record |
| GET | `/api/v1/servers` | List servers |
| POST | `/api/v1/servers` | Create server |
| GET | `/api/v1/users` | List users |
| POST | `/api/v1/users` | Create user |
| PUT | `/api/v1/users/:id` | Update user |
| DELETE | `/api/v1/users/:id` | Delete user |
| GET | `/api/v1/georules` | List geo-routing rules |
| POST | `/api/v1/georules` | Create rule |
| POST | `/api/v1/georules/resolve` | Resolve geolocation |
| DELETE | `/api/v1/georules/:id` | Delete rule |
| GET | `/api/v1/audit` | Get audit logs |
| GET | `/api/v1/admin/stats` | Admin dashboard stats |

## Form Validation

All forms include client-side validation:

- **Username**: 3+ chars, alphanumeric + `_` and `-` only
- **Email**: Valid email format
- **Domain**: Valid domain format (e.g., `example.com`)
- **IP Address**: IPv4 or IPv6 format
- **TTL**: Positive integer

Errors display inline below each field.

## Bulk Import Format

### Zones CSV
```csv
domain
example.com
test.io
```

### Records CSV
```csv
name,record_type,value,ttl
www,A,192.0.2.1,3600
mail,MX,10 mail.example.com,3600
```

Templates available via "Template" button in UI.

## Dark Mode

Toggle via "Dark"/"Light" button in header. Preference persists in localStorage.

## Notifications

Toast notifications appear bottom-right for:
- Successful operations (green)
- Errors (red)
- Info messages (blue)
- Warnings (yellow)

Auto-dismiss after 3 seconds or click × to close.

## Testing

### Run all E2E tests
```bash
npm run test:e2e
```

### Run specific test file
```bash
npx playwright test tests/e2e.full.spec.js
```

### Run with UI
```bash
npx playwright test --ui
```

### Run headless with retries
```bash
npx playwright test --retries=2 --reporter=html
```

## Production Deployment

### Environment Variables
```bash
VITE_API_BASE=https://api.example.com/
JWT_SECRET=production_secret_key_here
DATABASE_URL=postgresql://user:password@host/dbname
ADMIN_USERNAME=admin
ADMIN_PASSWORD=strong_password_here
```

### Build for Production
```bash
npm run build
npm run preview
```

### Docker Build
```bash
docker build -f Dockerfile -t hickory-ui:latest .
docker run -p 3000:3000 hickory-ui:latest
```

## Troubleshooting

**UI won't connect to API?**
- Check `api.js` — `baseURL` must match running API
- By default the API allows three origins: `localhost:3000`, `localhost:5173` and
  `localhost:8081`.  If you change the port you must update `env/api.env` or set
  `ALLOWED_ORIGINS` accordingly.
- Check browser console for CORS errors
- Ensure API is running and accessible

**Playwright tests timeout?**
- Increase timeout: `npx playwright test --timeout=60000`
- Ensure UI is running on port 3000
- Ensure API is running on port 8080

**Dark mode not working?**
- Check browser localStorage: `localStorage.setItem('dark', '1')`
- Clear cache and reload

**Zone/record operations fail?**
- Check token in localStorage
- Re-login if token expired
- Check API logs for SQL errors

## Contributing

1. Make changes to `src/`
2. Test locally: `npm run dev`
3. Run E2E tests: `npm run test:e2e`
4. Commit with descriptive message

## Security Notes

⚠️ **Development Only**
- JWT secret hardcoded in tests
- CORS allows any origin
- No HTTPS/TLS in dev

🔒 **Production**
- Use strong JWT secret
- Enable HTTPS
- Restrict CORS origins
- Use environment variables
- Implement rate limiting
- Add request validation
- Enable security headers
- Use database connection pooling
- Implement audit logging

## Performance

- Lazy load routes
- Memoize expensive components
- Debounce search inputs
- Paginate large lists
- Use React.memo for tables
- Optimize bundle: `npm run build`

## License

Apache 2.0 + MIT (dual-licensed with Hickory DNS)
