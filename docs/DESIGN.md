# NetSentinel — Design System & UI/UX Direction

## 1. Design Philosophy

NetSentinel uses a **cybersecurity dark-mode aesthetic** — professional, high-contrast, and data-dense. The UI should feel like a real SOC (Security Operations Center) monitoring dashboard: authoritative, technical, and precise.

**Core Principles:**
- Dark backgrounds with vibrant accent colors for critical data
- High information density without clutter
- Every interactive element must have clear hover/focus feedback
- Data visualization takes center stage (gauges, tables, cards)

---

## 2. Color Palette

| Token | Hex | Usage |
|:---|:---|:---|
| Background Primary | `#0a0f1e` | Page backgrounds |
| Background Surface | `#111827` | Cards, modals, sidebars |
| Background Elevated | `#1f2937` | Input fields, dropdowns |
| Border | `#374151` | Dividers, card borders |
| Text Primary | `#f9fafb` | Headings, main content |
| Text Secondary | `#9ca3af` | Labels, metadata, captions |
| Text Muted | `#6b7280` | Placeholders, disabled states |
| Accent Cyan | `#06b6d4` | Primary CTA, links, highlights |
| Accent Green | `#10b981` | Success, LOW RISK, benign |
| Accent Yellow | `#f59e0b` | Warning, MODERATE RISK |
| Accent Orange | `#f97316` | HIGH RISK |
| Accent Red | `#ef4444` | Error, CRITICAL THREAT |
| Accent Purple | `#8b5cf6` | Admin / special features |

### Risk Level Color Mapping
- **LOW RISK (0–29)**: `#10b981` (green)
- **MODERATE RISK (30–59)**: `#f59e0b` (yellow)
- **HIGH RISK (60–79)**: `#f97316` (orange)
- **CRITICAL THREAT (80–100)**: `#ef4444` (red)

---

## 3. Typography

- **Font Family**: System default via Tailwind (`font-sans`) — Inter / system-ui stack
- **Headings**: `font-bold`, sizes `text-2xl` to `text-4xl`
- **Body**: `text-base` (`1rem`), `text-gray-300`
- **Labels / Captions**: `text-sm`, `text-gray-400`
- **Monospace (features, scores)**: `font-mono`, `text-cyan-400`
- **Code / Technical values**: Use `<code>` tags styled with `bg-gray-800 rounded px-1`

---

## 4. Component Standards

### Cards
```
bg-gray-900 border border-gray-700 rounded-xl p-6 shadow-lg
```
- All data cards use this base style
- Hover: `hover:border-cyan-500/50 transition-colors`

### Buttons
| Type | Classes |
|:---|:---|
| Primary | `bg-cyan-600 hover:bg-cyan-500 text-white font-semibold rounded-lg px-4 py-2` |
| Secondary | `bg-gray-700 hover:bg-gray-600 text-gray-200 rounded-lg px-4 py-2` |
| Danger | `bg-red-600 hover:bg-red-500 text-white rounded-lg px-4 py-2` |
| Ghost | `text-cyan-400 hover:text-cyan-300 underline-offset-2 hover:underline` |

### Form Inputs
```
bg-gray-800 border border-gray-600 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500
text-white rounded-lg px-4 py-2 w-full outline-none transition
```

### Risk Gauge (SVG)
- Circular SVG gauge component at center of the result page
- Color changes dynamically based on risk level
- Inner text shows score (e.g., `72`) and risk label (`HIGH RISK`)
- Stroke: 8px, radius: 80px

### Tables (Deep Packet Inspection)
- Striped rows: alternating `bg-gray-900` and `bg-gray-800/50`
- Header: `bg-gray-800 text-gray-400 text-xs uppercase tracking-wider`
- Monospace font for domain names and numeric values
- Truncate long domains with `truncate max-w-xs` + tooltip on hover

### Navigation
- Fixed top navbar: `bg-gray-900/95 backdrop-blur border-b border-gray-700`
- Active route: `text-cyan-400 border-b-2 border-cyan-400`
- Inactive: `text-gray-400 hover:text-white`

---

## 5. Iconography

- Use **Lucide React** icons throughout (`lucide-react` package)
- Icon size: `w-5 h-5` for inline icons, `w-6 h-6` for card headers
- Icons paired with text always use `flex items-center gap-2`

Key icons in use:
- `Shield` — branding / auth pages
- `Activity` — analysis / dashboard
- `Upload` — file upload
- `AlertTriangle` — warnings / high risk
- `CheckCircle` — success / benign
- `Settings` — admin panel
- `LogOut` — logout action

---

## 6. Layout & Spacing

- **Page max-width**: `max-w-7xl mx-auto px-4 sm:px-6 lg:px-8`
- **Section spacing**: `py-8` between major sections
- **Card grid**: `grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6`
- **Form layout**: `space-y-4` for stacked form fields
- Responsive breakpoints: `sm` (640px), `md` (768px), `lg` (1024px), `xl` (1280px)

---

## 7. Animation & Transitions

- All color/border transitions: `transition-colors duration-200`
- All opacity transitions: `transition-opacity duration-300`
- Loading spinner: `animate-spin` on a `Border-t-2 border-cyan-500` circle
- Risk gauge fill: CSS `stroke-dashoffset` transition `duration-700 ease-out`
- Page-level fade-in: `animate-fade-in` (custom keyframe in Tailwind config if needed)

---

## 8. Accessibility

- All interactive elements must be keyboard-navigable
- Focus rings: `focus:ring-2 focus:ring-cyan-500 focus:outline-none`
- Color is never the sole indicator of state (always pair with text/icon)
- All images must have `alt` attributes
- Form fields must have associated `<label>` elements
