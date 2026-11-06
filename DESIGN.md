---
name: "CodeGuardian AI"
description: "An evidence-first security workspace with obsidian surfaces, sage accents, and restrained glass chrome."
colors:
  ground: "#141717"
  surface: "#101313"
  raised: "#1b2020"
  hover: "#222929"
  border: "#2a3030"
  rule: "#242a29"
  control: "#3c4542"
  text: "#eef2f0"
  muted: "#a0aaa5"
  quiet: "#8e9993"
  accent: "#83cfb3"
  high: "#f09291"
  medium: "#dfbd7e"
  low: "#8db6dd"
  critical: "#f080a0"
  accent-wash: "#1c2c26"
  red-wash: "#302222"
  amber-wash: "#2e291e"
  blue-wash: "#212c35"
  glass: "rgba(20,23,23,.83)"
  chart-1: "#83cfb3"
  grid: "#2a3230"
  light-ground: "#f4f6f4"
  light-surface: "#fff"
  light-raised: "#edf0ee"
  light-hover: "#e4e9e6"
  light-border: "#d9dfdb"
  light-rule: "#e7ebe8"
  light-control: "#bcc7bf"
  light-text: "#19251e"
  light-muted: "#56665b"
  light-quiet: "#617065"
  light-accent: "#236d50"
  light-high: "#ae3e3d"
  light-medium: "#8b641c"
  light-low: "#35648f"
  light-critical: "#a82c52"
  light-accent-wash: "#e5f0e9"
  light-red-wash: "#fcece9"
  light-amber-wash: "#f8f0df"
  light-blue-wash: "#e7eff6"
  light-glass: "rgba(244,246,244,.88)"
  light-chart-1: "#267e5a"
  light-grid: "#e2e7e3"
  primary-ink: "#11291f"
typography:
  headline:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "27px"
    fontWeight: 600
    lineHeight: 1.3
    letterSpacing: "-1px"
  title:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "15px"
    fontWeight: 600
    lineHeight: 1.4
  panel-title:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "14px"
    fontWeight: 500
  body:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: 1.55
  label:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "11px"
    fontWeight: 400
  button:
    fontFamily: "Public Sans, sans-serif"
    fontSize: "12px"
    fontWeight: 500
  metric:
    fontFamily: "IBM Plex Mono, monospace"
    fontSize: "28px"
    fontWeight: 400
    lineHeight: 1.4
    letterSpacing: "-1px"
  code-meta:
    fontFamily: "IBM Plex Mono, monospace"
    fontSize: "11px"
    fontWeight: 400
rounded:
  tag: "4px"
  field: "5px"
  control: "6px"
  settings: "8px"
  panel: "10px"
  dialog: "14px"
spacing:
  "4": "4px"
  "6": "6px"
  "8": "8px"
  "10": "10px"
  "12": "12px"
  "14": "14px"
  "16": "16px"
  "18": "18px"
  "20": "20px"
  "24": "24px"
  "32": "32px"
components:
  button-primary:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.primary-ink}"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "0 13px"
    height: "35px"
  button-secondary:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "0 13px"
    height: "35px"
  button-secondary-hover:
    backgroundColor: "{colors.hover}"
  button-text:
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    padding: "4px 0"
  button-primary-light:
    backgroundColor: "{colors.light-accent}"
    textColor: "{colors.light-surface}"
    typography: "{typography.button}"
    rounded: "{rounded.control}"
    padding: "0 13px"
    height: "35px"
  search-field:
    backgroundColor: "{colors.ground}"
    textColor: "{colors.quiet}"
    typography: "{typography.label}"
    rounded: "{rounded.field}"
    padding: "0 9px"
    height: "32px"
  nav-item:
    textColor: "{colors.quiet}"
    rounded: "{rounded.control}"
    width: "44px"
    height: "43px"
  nav-item-active:
    textColor: "{colors.accent}"
  severity-high:
    backgroundColor: "{colors.red-wash}"
    textColor: "{colors.high}"
    typography: "{typography.label}"
    rounded: "{rounded.tag}"
    padding: "0 7px"
  severity-medium:
    backgroundColor: "{colors.amber-wash}"
    textColor: "{colors.medium}"
    typography: "{typography.label}"
    rounded: "{rounded.tag}"
    padding: "0 7px"
  severity-low:
    backgroundColor: "{colors.blue-wash}"
    textColor: "{colors.low}"
    typography: "{typography.label}"
    rounded: "{rounded.tag}"
    padding: "0 7px"
  neutral-tag:
    textColor: "{colors.muted}"
    typography: "{typography.label}"
    rounded: "{rounded.tag}"
    padding: "1px 6px"
  panel:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.text}"
    rounded: "{rounded.panel}"
  finding-row:
    textColor: "{colors.text}"
    padding: "15px 20px"
  dialog:
    backgroundColor: "{colors.glass}"
    textColor: "{colors.text}"
    rounded: "{rounded.dialog}"
---

# Design System: CodeGuardian AI

## Overview

**Creative North Star: "Data terminal"**

CodeGuardian AI is a compact, professional review workspace. Obsidian surfaces, a sage action color, and a steady text hierarchy keep findings, source locations, and evidence legible during sustained review. The established direction is the “Data terminal” recorded in `.taste-skill/direction.json`; the implemented system is the visual authority for this extraction.

Public Sans carries interface language while IBM Plex Mono aligns counts, paths, identifiers, and source evidence. The requested liquid-glass character appears in sticky chrome and the import dialog. Working panels remain opaque, and the dark and light themes preserve the same hierarchy and component geometry.

This is an extraction of `app/globals.css`, the shipped components, and the desktop, light, mobile, and review captures in `.impeccable/review/`. It records observed decisions; it does not claim a separate visual-world workshop or user-approved metaphor. The frontmatter is the portable token layer. Its unprefixed colors describe the default dark theme, and `light-` colors describe the corresponding `data-theme="light"` overrides. The CSS custom properties remain the implementation source.

**Key Characteristics:**

- Dense, task-focused layouts with clear reading order.
- Quiet neutral structure with sage actions and semantic severity colors.
- One-pixel selection edges on navigation, tabs, and the finding inbox.
- Restrained glass chrome around opaque evidence surfaces.
- Responsive review composition with labeled bottom navigation on phones.

## Colors

The palette combines softly green-tinted neutrals with a sage primary accent and compact semantic severity treatments.

### Primary

- **Sage action:** `accent` identifies primary actions, focused controls, selections, positive status, and the default trend line. The dark primary button uses `primary-ink`; light mode uses the light surface color for its label.
- **Sage wash:** `accent-wash` supports restrained positive or supporting emphasis where the component already uses it.
- **Trend stroke:** `chart-1` follows sage in dark mode and has its own stronger light-theme value for chart visibility.

### Semantic status

- **Soft coral:** `high` pairs with `red-wash` for high-severity findings. Critical findings share the wash and use `critical` rose for the label.
- **Muted amber:** `medium` pairs with `amber-wash` for medium severity and warning context.
- **Quiet blue:** `low` pairs with `blue-wash` for low severity.
- Informational status uses the neutral muted text and raised surface. Positive status uses the primary sage. Severity always has a text label; color is supplemental.

### Neutral

- **Obsidian ground:** `ground` is the dark workspace canvas; `surface` is the deeper opaque working plane. Their light counterparts form a pale green-gray canvas and white working plane.
- **Raised and hover planes:** `raised` separates secondary bands and selected rows; `hover` gives buttons a stronger response.
- **Structural edges:** `border` outlines panels, `rule` divides rows, and `control` gives controls and keyboard hints definition.
- **Reading hierarchy:** `text` carries primary content, `muted` supporting copy, and `quiet` metadata. Chart grid lines use `grid`; axes follow muted text.
- **Glass:** `glass` is the existing alpha background used by chrome and the dialog; preserve its CSS color format.

**The Selection Edge Rule.** Use the established one-pixel sage edge for active navigation, source tabs, and selected findings. Theme choices use an outlined selected state.

## Typography

**Interface Font:** Public Sans, sans-serif. The app imports regular, medium, semibold, and bold weights locally through Fontsource.

**Label/Mono Font:** IBM Plex Mono, monospace, regular weight. Technical labels use this face selectively; ordinary interface labels stay in Public Sans.

The hierarchy is deliberately compact: the page headline is distinct without becoming a marketing display, and numbers are prominent enough to compare without dominating the work.

### Hierarchy

- **Headline:** the frontmatter headline role is the desktop page title; the responsive implementation reduces it to (25px) at the tablet breakpoint and (24px) on phones.
- **Title and panel title:** the title role is the global section heading; the smaller medium-weight panel-title role is the common panel heading.
- **Body:** the base interface role. Supporting paragraphs commonly use (12px); dense metadata and labels use the label role.
- **Metrics:** the mono metric role is the standard overview number. The first overview metric rises to (32px) on desktop; the remaining count roles and phone overrides are context-specific.
- **Code metadata:** the mono label role identifies file paths, line locations, rule identifiers, and snapshots.

**The Evidence Type Rule.** Use the sans face for reading and actions; use the mono face for counts, paths, code, rule identifiers, and snapshot metadata.

## Layout

The desktop shell uses a fixed left rail (64px), a sticky top bar (66px), and a centered main region with a maximum width of (1600px) and horizontal gutters of (32px). Content uses compact grouped spacing, not a single forced spacing increment; the frontmatter records the recurring values.

The overview uses a two-column grid with a wider findings area and a supporting column. Metrics form a four-column strip separated by rules. The review workspace is a single joined frame: an inbox (250px), a flexible source area, and an explanation area (310px), with no gaps between those three panes. Settings use a description column beside a settings panel.

Responsive behavior is established at these boundaries:

- At a minimum width of (1600px), the review side columns grow to (270px) and (340px), and reading areas gain space.
- At a maximum width of (1250px), gutters become (24px), and the review side columns narrow.
- At a maximum width of (1050px), overview panels stack, report panels stack, and the explanation area moves below the source while the inbox spans both rows.
- At a maximum width of (760px), the rail becomes (54px), metrics become a two-column grid, heading actions move below the title, and settings sections stack.
- At a maximum width of (540px), navigation becomes a fixed labeled bottom bar (58px), main gutters become (16px), overview support panels stack, and review becomes inbox, source, then explanation. The inbox uses two columns within its bounded scroll area. Secondary table columns disappear while finding identity and severity remain.

Do not convert the desktop three-pane review composition into a universal layout requirement. It is the current review surface's use of the shared spacing and hierarchy.

## Elevation & Depth

Depth comes mainly from opaque tonal layers and fine borders. Ordinary panels do not use shadows. Sticky chrome introduces the requested liquid-glass character through alpha backgrounds and backdrop blur; modal and transient feedback receive the only strong shadows.

### Shadow Vocabulary

- **Dialog:** `0 20px 70px #0005` separates the import dialog from its backdrop.
- **Toast:** `0 8px 35px #0004` separates transient feedback from the working canvas.

The top bar uses a backdrop blur of (22px) with saturation (125%); phone navigation uses a blur of (22px). The import dialog uses a blur of (30px), and its dark backdrop uses a blur of (5px). The sidecar carries these effects because the portable component schema cannot represent them.

**The Glass on Chrome Rule.** Reserve translucent blur for the top bar, phone navigation, dialog, and dialog backdrop. Keep source, evidence, and result panels opaque.

## Shapes

The form language is softly rectangular. Tags have the smallest corners, then fields and controls, then settings containers and main panels; dialogs receive the largest established radius. Use the corresponding frontmatter shape role rather than introducing new radii. One-pixel borders and dividers carry most structure. Fully rounded shapes are reserved for small status dots and the user avatar.

The source, inbox, and explanation areas share one clipped outer panel. Their internal edges are dividers, not separately rounded cards. Main action buttons are compact rectangles, and tabs use an edge indicator rather than filled capsules.

## Components

### Buttons

Compact and explicit. Primary actions use sage fill and the theme-appropriate primary label; secondary actions use an opaque surface and a control border. Text actions are quiet until hover. The base control is (35px) high with an icon gap of (8px); phone review actions have their existing slightly taller treatment.

Secondary hover changes the background and border. Primary hover uses brightness (1.08). Shared keyboard focus uses a (2px) sage outline with an offset of (4px). Disabled controls use opacity (.55) and a not-allowed cursor. Color and background changes transition over (150ms); reduced-motion preference removes transitions and animations.

### Chips

Severity chips combine a small status dot, readable label, semantic foreground, and a subdued wash. They are compact rounded rectangles, not interactive filter pills. Neutral tags use a thin border and muted text. Numeric count badges use mono type on a raised neutral surface.

### Cards / Containers

Opaque working panels use the panel radius, surface fill, and a single border. A panel heading normally has padding of (19px 20px). Row-based contents retain their own padding and dividers; containers do not add decorative elevation. Repository identity appears in a wider shared strip with padding of (19px 21px). Settings panels use their smaller shape role and padding of (20px).

### Inputs / Fields

Search combines an outline icon, a compact text field, and an optional keyboard hint on the ground color. It uses the field radius and shifts its border to sage on focus within. The inner search input suppresses the general outer outline so the containing field supplies the focus cue. Select controls use the same field radius and height on an opaque surface. Textareas use the field radius, control border, and ground background.

### Navigation

Desktop navigation is an icon rail with accessible names and hover titles. The active item changes to sage and adds the thin edge marker; hover uses a raised neutral fill. Phone navigation exposes short labels under the icons. Source and dialog tabs use muted inactive text, primary active text, and the same thin sage underline. Preserve the sticky chrome geometry and content clearance.

### Finding rows and review inbox

Finding rows combine a readable title, mono source location, severity chip, analyzer evidence, and a trailing direction icon. Rows use thin dividers and a raised hover plane. The review inbox adapts that pattern into a compact selectable list; the current finding adds a raised plane and the sage edge. Keep severity distinct from evidence classification.

### Dialog and feedback

The import dialog is the strongest glass surface, with a bounded width (570px), layered heading and underline tabs, an opaque-looking translucent body, and a clearly separated footer. Toasts are compact bordered feedback surfaces, positioned above phone navigation. Empty states remain quiet and centered, with concise explanatory copy and a relevant action when available.

## Do's and Don'ts

### Do:

- Do preserve semantic token roles in both themes; light mode changes palette, not hierarchy.
- Do pair severity color with readable severity text, and retain evidence labels beside findings.
- Do use mono numerals and metadata where comparison and exact identification matter.
- Do keep the visible focus treatment, reduced-motion behavior, and labeled phone navigation.
- Do keep chart axes, snapshot labels, and data context visible.
- Do use opaque working surfaces and restrained translucent chrome.

### Don't:

- Don't replace the selection edge with filled pill tabs.
- Don't turn ordinary counts or metadata into a wall of status color.
- Don't add glow, ambient panel shadows, or blurred backgrounds behind source evidence.
- Don't shrink the established small text to fit additional columns; use the responsive column reductions.
- Don't treat illustrative tonal ramps in the sidecar as new application palette tokens.

## Connected workspace upgrade (2026-11-06)

The public surface is an honest sign-in/onboarding page, never a sample dashboard. The operated surface uses a 220px labeled navigation rail (icon rail on tablets; bottom navigation on mobile), actual persisted counts and explicit empty/error states. Preserve Public Sans and IBM Plex Mono, the obsidian/sage palette, and opaque source/evidence panels.

Liquid glass is intentionally confined to navigation, notifications, confirmation overlays and the sign-in panel. It uses translucent surfaces, fine specular edges and restrained blur. A slow organic outline and an evidence-flow line connect the landing narrative; task controls use brief press/arrival feedback. All animation and transitions are disabled under `prefers-reduced-motion: reduce`. Never simulate scan progress or invent security scores.

Primary responsive cutoffs: 1250, 1000 and 760px. Review columns collapse from finding list/source/evidence into two columns, then a vertical mobile flow. Source and diffs remain read-only; export requires human acknowledgement. The interface never offers a fake demo login, automatic repository mutation or an unavailable paid AI action.
