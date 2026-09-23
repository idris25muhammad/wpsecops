---
name: WP-SecOps
description: Centralized WordPress security scanner with a daylight mission-console interface
colors:
  primary: "#0369a1"
  primary-action: "#0284c7"
  secondary: "#047857"
  ground: "#f2f4f6"
  surface: "#ffffff"
  ink: "#101418"
  border: "#e3e6ea"
  text-body: "#374151"
  text-muted: "#6b7280"
  success: "#16a34a"
  warning: "#d97706"
  danger: "#dc2626"
  info: "#0284c7"
  teal-accent: "#0f766e"
typography:
  display:
    fontFamily: "Segoe UI, system-ui, -apple-system, sans-serif"
    fontWeight: 800
    letterSpacing: "0.02em"
  body:
    fontFamily: "Segoe UI, system-ui, -apple-system, sans-serif"
    fontSize: "14px"
    fontWeight: 400
  mono:
    fontFamily: "Consolas, Cascadia Mono, SFMono-Regular, Menlo, monospace"
    fontWeight: 400
rounded:
  sm: "6px"
  md: "8px"
  lg: "12px"
spacing:
  xs: "4px"
  sm: "8px"
  md: "16px"
  lg: "24px"
  xl: "32px"
components:
  button-primary:
    backgroundColor: "{colors.primary-action}"
    textColor: "#ffffff"
    rounded: "{rounded.md}"
    padding: "10px 16px"
  button-primary-hover:
    backgroundColor: "{colors.primary}"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text-body}"
    rounded: "{rounded.md}"
    padding: "10px 16px"
  input-field:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.md}"
    padding: "10px 16px"
  card:
    backgroundColor: "{colors.surface}"
    rounded: "{rounded.lg}"
    height: "auto"
  nav-item-active:
    backgroundColor: "#f0f9ff"
    textColor: "{colors.primary}"
    rounded: "{rounded.md}"
    padding: "10px 12px"
  nav-item:
    textColor: "{colors.text-muted}"
    rounded: "{rounded.md}"
    padding: "10px 12px"
---

# Design System: WP-SecOps

## Overview

**Creative North Star: "The Daylight Mission Console"**

WP-SecOps is a centralized WordPress security scanner, and its interface is built to read like an instrumented operations console in full daylight - not a darkened hacker terminal. The ground is a quiet neutral gray, every surface is a clean white panel divided by hairline rules, and status is carried by deliberate, light-tinted semantic color rather than neon glow. The aesthetic refuses the "AI-generated dark dashboard" default outright: no purple/indigo accents, no glass, no gradients, no decorative grids, no glow.

Density is high but ordered. The operator (an internal security admin) needs to scan a list of targets, read a status, and find a vulnerability without hunting. Tables carry the primary load - scan history, per-server matrices, dependency health - styled for fast scanning with clear column alignment, tabular numerals, and mono data. Expression lives in precise details: the two-tone sky/emerald wordmark in Orbitron, the sky shield tile, the thin left accent of the page header, and consistent semantic badges.

**Key Characteristics:**
- Light, neutral ground with white hairline-bordered surfaces
- Semantic status color used deliberately (never neon, never purple/indigo)
- Orbitron for the wordmark only; IBM Plex Sans for UI; IBM Plex Mono for tabular data
- High data density with fast-scannable tables and badges
- Flat-by-default elevation; a subtle panel shadow and modal scrims only

## Colors

The palette is a restrained neutral scale carrying one sky primary, one emerald secondary, and a small set of semantic status colors used as light-tinted badges. Restraint is the point: color marks state, it does not decorate.

### Primary
- **Sky Primary** (#0369a1): the brand's `WP` mark, the active sidebar route tint, link/emphasis text, and the shield icon. Set as `brand` in the Tailwind config.
- **Sky Action** (#0284c7): solid primary buttons and the primary focus ring. Slightly brighter than Primary so actions read as interactive.

### Secondary
- **Emerald** (#047857): the brand's `SecOps` mark and secondary success-affirming accents (wordmark only).

### Neutral
- **Ground** (#f2f4f6): the page background behind all surfaces.
- **Surface** (#ffffff): cards, sidebar, header band, inputs, tables.
- **Ink** (#101418): primary text/headings.
- **Body Text** (#374151): secondary text and body copy.
- **Muted** (#6b7280): labels, timestamps, metadata.
- **Border** (#e3e6ea): hairline rules between and around surfaces.

### Semantic
- **Success** (#16a34a) with a light tint background (#f0fdf4) for "Selesai / scanned" badges and zero-vuln indicators.
- **Warning** (#d97706) with light amber (#fffbeb) for "Pending" badges.
- **Danger** (#dc2626) with light red (#fef2f2) for "Gagal / failed" badges and vulnerability counts.
- **Info** (#0284c7) with light sky (#f0f9ff) for informational badges and links.
- **Teal Accent** (#0f766e) with light teal (#f0fdfa) for the "running scans / active worker" widget, kept distinct from sky to avoid purple-family slop.

### Named Rules
**The Rarity Rule.** Semantic and accent colors appear as small badges, tinted backgrounds, and hairline accents - never as full-bleed fills, gradients, or glow. Their scarcity is what makes status legible.

**The No-Purple Rule.** No purple, violet, or indigo anywhere in the system. Teal replaces indigo when a distinct widget accent is needed.

## Typography

**Display Font:** Segoe UI (system-ui / sans-serif) - bold weight used for the wordmark.
**Body Font:** Segoe UI (system-ui, -apple-system, sans-serif) - the workhorse UI face.
**Label/Mono Font:** Consolas / Cascadia Mono (with SFMono-Regular, Menlo fallback) - for data, numerics, URLs, timestamps, raw output.

**Character:** The system uses common, broadly available fonts so the interface always renders clearly and legibly on the operator's machine. A crisp system sans for reading and operating, a system mono for anything that is data, and a heavy weight of the same sans reserved for the brand wordmark. This is an operations console, not a marketing site - the type hierarchy is functional and restrained, with no webfont dependency.

### Hierarchy
- **Display** (Segoe UI, 800, ~18–24px, tracking 0.02em): the WP-SecOps wordmark only, in the sidebar and login. Never used for page headings.
- **Title** (IBM Plex Sans, 700, 20px / 1.2): page-level headings (e.g. "Dashboard Admin", "Scan History").
- **Card Label** (IBM Plex Sans, 700, 12px): card titles and table headers, uppercase with wide tracking where it denotes a section.
- **Body** (Segoe UI, 400, 14px / 1.5, ~65–75ch): main content, table text.
- **Mono Data** (Consolas/Cascadia Mono, 400–600, 11–14px): URLs, timestamps, durations, counts, raw scanner output. Tabular numerals are on by default (`font-feature-settings: "tnum"`).

### Named Rules
**The Wordmark-Only Rule.** The heavy system-sans wordmark appears exactly twice in the UI - the sidebar wordmark and the login card. Any third use is a regression.

**The Mono-Is-Data Rule.** Monospace marks data, never decoration: URLs, IDs, durations, counts, and raw logs. Headings and labels stay in the sans face.

**The No-Webfont Rule.** No webfont dependency. Only common system fonts (Segoe UI, Consolas/Cascadia) are used so text never renders as broken or illegible glyphs.

## Layout

The shell is a fixed 224px white sidebar on the left and a flexible content area on `#f2f4f6`. Content is padded at `32px` (`p-8`) on desktop. Vertical rhythm uses a consistent spacing scale (`4/8/16/24/32px`) with more space above a heading than below it.

KPI and status cards sit in responsive grids (`grid-cols-2 md:grid-cols-4`), collapsing to one or two columns on narrow viewports. Tables use full-width, left-aligned, hairline-ruled rows with generous cell padding (`px-5/6 py-3`) and clear column headers. Data-dense tables get horizontal scroll on mobile (`overflow-x-auto`) rather than shrinking columns to unreadable widths.

### Named Rules
**The Table-First Rule.** The primary surfaces are tables. Give them full width, clear headers, tabular numerals, and horizontal scroll on mobile - never compress a data column to illegibility.

## Elevation & Depth

The system is **flat-by-default**. Depth is conveyed primarily by the neutral ground behind white surfaces and hairline borders, not by shadows. A single subtle `shadow-sm` softens the page-header band and top-level panels; interactive surfaces are flat at rest.

Modal dialogs use a dark scrim (`bg-black/60`, optionally with a slight `backdrop-blur`) to focus attention on the dialog - the only place a scrim is used. There is no neon glow, no inner glow, and no colored shadow anywhere.

### Named Rules
**The Flat-By-Default Rule.** Surfaces are flat at rest. Shadows appear only as a subtle `shadow-sm` on the header band and top-level panels; modals isolate content with a dark scrim, never a glow.

## Shapes

The form language is consistently **softly rectangular**. Corners use a small radius family: `rounded-lg` (12px) for cards and panels, `rounded-md` (8px) for buttons and inputs, `rounded-sm` (6px) for small chips, and `rounded-full` for status pills and live-indicator dots. Borders are 1px hairline (`#e3e6ea` / `#e5e7eb`) on every surface - no thick or colored side borders on cards (side-accent borders are an explicit anti-pattern).

Icons are a single consistent family: 24px-viewbox stroke SVGs, `stroke-width 2`, `round` caps/joins, in the current text color. No emoji icons, no filled-vs-outline mixing.

### Named Rules
**The Hairline Rule.** Every surface border is 1px and neutral. Thick borders, colored borders, and one-sided accent borders on cards are banned - a 12px side-tab on a vulnerability card was removed because it reads as generated slop.

## Components

### Buttons
- **Shape:** Softly rectangular (8px radius).
- **Primary:** Solid sky action (#0284c7), white text, ~10px/16px padding. Used for "Masuk", "Filter", "Tambah Server", and other single primary actions.
- **Hover / Focus:** Hover lightens to sky primary (#0369a1); focus shows a `focus-visible` 2px sky outline with offset, plus a soft `ring` on inputs.
- **Secondary:** White background, gray border, gray text (e.g. "Prev/Next", "Lihat Laporan"). Hover darkens the surface to `gray-100`/`gray-300`.
- **Ghost / Text:** Link-style actions in sky (#0284c7) with underline on hover (e.g. "Lihat Semua History →", "Laporan →").

### Chips / Badges
- **Style:** Small pill (full radius) with a light-tinted background, a matching 1px tinted border, and a darker same-hue text color. Example: "Selesai" = `bg-green-50 text-green-600 border-green-200`.
- **State:** Semantic by status - green (success), red (danger), amber (pending), sky (info), teal (running). Badges are the primary way status is communicated across tables and cards.

### Cards / Containers
- **Corner Style:** 12px radius (`rounded-xl`).
- **Background:** White (#ffffff).
- **Shadow Strategy:** Flat at rest; optional `shadow-sm` on the page-header band and top-level panels (see Elevation).
- **Border:** 1px hairline (#e3e6ea).
- **Internal Padding:** 20px (`p-5`) for KPI cards, up to 24px (`px-6 py-4`) for table cards.

### Inputs / Fields
- **Style:** White background, 1px gray-300 border, 8px radius, ~10px/16px padding, gray-400 placeholder.
- **Focus:** Border shifts to sky (#0284c7) plus a soft sky ring (`focus:ring-sky-100`); a visible 2px `focus-visible` outline for keyboard users.
- **Error:** Red border + red-tinted background, matching the danger semantic (used on the login error alert).

### Navigation
- **Style:** A white 224px sidebar with a top border-separated brand block and a bottom user/logout block. Nav items are `text-sm`, gray-600 at rest, and switch to a sky tint (`bg-sky-50 text-sky-800 font-semibold`) when active. Hover raises to `bg-gray-100 text-gray-900`. Each item pairs a 16px stroke icon with its label. On mobile the sidebar slides away and returns via a fixed toggle button.

### Vulnerability Card (signature)
- A white card (12px radius, hairline border) listing a finding: badge row (confidence + severity + scanner), title, version, CVEs, evidence, and an AI-recommendation action. Severity is communicated by a tinted badge, not a thick left border. Raw output and scanner logs render in a light `gray-50` mono block with `whitespace-pre-wrap`.

## Do's and Don'ts

### Do:
- **Do** use light-tinted semantic badges (`bg-green-50 text-green-600 border-green-200`) to communicate status - their scarcity makes them legible.
- **Do** keep tables full-width with tabular numerals, clear headers, and `overflow-x-auto` on mobile.
- **Do** use the bold system-sans wordmark and system mono for actual data (URLs, IDs, durations, raw output).
- **Do** use the sky action (#0284c7) for primary buttons and links, and the sky/emerald two-tone for the wordmark.
- **Do** apply the 2px sky `focus-visible` outline to interactive elements for keyboard accessibility.

### Don't:
- **Don't** use webfonts or custom typefaces - stick to common system fonts (Segoe UI, Consolas/Cascadia) so text never breaks.
- **Don't** use purple, violet, or indigo - use teal when a distinct widget accent is needed.
- **Don't** use neon glow, gradients, glass/backdrop-blur as decoration, or colored shadows.
- **Don't** add decorative grid or blueprint backgrounds to plain surfaces.
- **Don't** put thick or one-sided colored borders on cards (no 4px side-tab accents).
- **Don't** use Orbitron for page headings, or monospace for decorative text.
- **Don't** use emoji as icons - use the consistent stroke-SVG set.
- **Don't** let tables compress to illegibility on mobile; scroll them horizontally instead.
