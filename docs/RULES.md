# NetSentinel — Development Rules & Coding Standards

## 1. General Principles

- **Follow PRD and ARCHITECTURE first** — never build features outside the defined scope
- **Keep code clean and simple** — prefer readable over clever; self-documenting variable names
- **Avoid logic duplication** — extract shared logic into helpers/services before copy-pasting
- **Make small, focused changes** — one logical change per commit; avoid mega-PRs
- **Write self-explanatory code** — comments explain *why*, not *what*
- **Fail loudly** — raise explicit exceptions with clear messages; never silently swallow errors
- **No hardcoded secrets** — all credentials, secrets, and config go in `.env` files only

---

## 2. Backend Rules (Python / FastAPI)

### Language & Style
- Python 3.10+ required; Python 3.12 recommended
- Follow **PEP 8** for formatting; 4-space indentation, max 100 chars per line
- Use **type hints** on all function signatures (parameters + return types)
- Use **Pydantic v2** models for all request/response schemas (no raw dicts in routes)
- Use **SQLAlchemy ORM** only — no raw SQL strings

### Project Structure Rules
```
backend/
├── app/
│   ├── api/          # Route handlers only — no business logic here
│   ├── auth/         # JWT, bcrypt, dependency injection
│   ├── database/     # ORM models + session management
│   ├── dns/          # PCAP parsing and DNS feature extraction
│   ├── ml/           # ModelManager, RuleEngine, RiskScorer
│   └── schemas/      # Pydantic input/output schemas
```
- **`api/`** — route handlers only; delegate to `ml/`, `dns/` for logic
- **`dns/`** — feature extraction must be stateless (no DB calls)
- **`ml/`** — `model_loader.py` is a singleton; never re-load models per request
- **`schemas/`** — never import SQLAlchemy models; use Pydantic only

### Security Rules
- Always hash passwords with bcrypt before storage — never store plaintext
- Always validate JWT tokens via dependency injection (`Depends(get_current_user)`)
- CORS: in production, replace `allow_origins=["*"]` with explicit trusted origins
- Never commit `.env` files; only commit `.env.example`

### Error Handling
- Use `HTTPException` with appropriate status codes (400, 401, 403, 404, 422, 500)
- Non-DNS PCAP files → `422 Unprocessable Entity`
- Corrupt/invalid PCAP files → `400 Bad Request`
- Unauthorized access → `401 Unauthorized` or `403 Forbidden`

---

## 3. Frontend Rules (React / Vite / Tailwind)

### Language & Style
- JavaScript (ES2022+) — no TypeScript unless explicitly introduced
- Use **functional components** with hooks only (no class components)
- One component per file; filename matches the exported component name
- Use `axios` via the shared service (`src/services/api.js`) — never call `fetch` directly

### Project Structure Rules
```
frontend/src/
├── components/   # Shared/reusable UI components (Navbar, Footer, RiskGauge, etc.)
├── pages/        # Route-level page components (one per page)
├── services/     # Axios API client with JWT interceptors
├── context/      # React Context providers (AuthContext)
└── utils/        # Pure utility helper functions
```
- **`components/`** — must be stateless or self-contained; no API calls inside components
- **`pages/`** — pages can call services; import components from `components/`
- **`services/`** — all API calls go here; handle token injection in the axios interceptor
- **`context/`** — global auth state only; keep context providers minimal

### Styling Rules
- Use **Tailwind CSS** utility classes only — no inline `style={{}}` objects
- Follow the dark cybersecurity theme: dark backgrounds, cyan/green accent colors
- All interactive elements must have hover states and focus rings
- Never use hardcoded pixel values — use Tailwind spacing scale

### State Management
- Use React Context (`AuthContext`) for auth state only
- Use local `useState` / `useEffect` for component-level state
- No Redux or external state manager unless explicitly approved

---

## 4. ML / Data Science Rules (scripts/)

### Feature Engineering
- The 14 features must be **identical** between training (`scripts/`) and inference (`backend/app/dns/`)
- Never add timestamp or raw string domain tokens to features — data leakage prevention
- All feature extraction must be **stateless** (per-query, no session history)

### Model Versioning
- All trained models saved to `models/vN/` with `metadata.json` (metrics, date, sample count)
- `models/active_version.json` controls which version is loaded at runtime
- Never delete old model versions — archive them in `models/`

### Script Rules
- Scripts in `scripts/` are one-time or batch-run utilities — not imported by the backend
- Each script must be runnable standalone: `python scripts/train_model.py`
- Scripts write outputs to `docs/` (exploration reports) or `models/` (artifacts)

---

## 5. Testing Rules

- All backend tests go in `backend/tests/`
- Use **Pytest** with **FastAPI TestClient** and **HTTPX**
- Every new API route must have at least one positive and one negative test
- Run the full suite before any merge: `python -m pytest backend/tests -v`
- Tests must not depend on external services or live network access

---

## 6. Git & Version Control

- **Never commit**: `.env`, `__pycache__/`, `node_modules/`, `*.pyc`, `netsentinel.db`
- Commit message format: `<type>: <short description>` (e.g. `feat: add risk gauge component`)
- Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`
- Keep `.gitignore` up to date — check before every `git add .`
