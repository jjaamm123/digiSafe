# DigiSafe Project Context

This document outlines the architecture, tech stack, and recent implementations for the **DigiSafe Threat Detector** project. It serves as a context reference for future AI sessions.

## 1. Project Overview
DigiSafe is an AI-powered cyber threat detection tool. It consists of two main parts:
1. **Next.js Backend (`admin-dashboard`)**: Handles AI logic, vector embeddings, and database telemetry.
2. **Chrome Extension (`extension`)**: A Manifest V3 browser extension that scans emails (Gmail) and posts (LinkedIn) to provide real-time threat intelligence via a glassmorphic UI overlay.

---

## 2. Next.js Backend Architecture
**Path:** `admin-dashboard/`
**Stack:** Next.js (App Router), TypeScript, `@google/genai`, `@supabase/supabase-js`

### API Route: `POST /api/scan`
- **Location:** `app/api/scan/route.ts`
- **Responsibilities:**
  1. Receives raw text from the Chrome extension.
  2. Generates a vector embedding using Google's `embedding-001` model.
  3. Queries Supabase using `match_threats` RPC to find previously seen threats (Cosine similarity > 0.90). If a match is found, it bypasses the LLM to save latency/costs.
  4. If no match is found, it prompts **Gemini 2.5 Flash** to analyze the text, using structured JSON output to return `classification`, `riskScore`, `indicators`, and `flaggedPhrases`.
  5. Inserts a telemetry record into the Supabase `scan_events` table (saving the raw text length, score, and the vector embedding).

### Database (Supabase + pgvector)
- The `scan_events` table stores telemetry.
- **pgvector** is enabled and an `embedding vector(768)` column is attached to the table.
- A custom PL/pgSQL RPC function named `match_threats` performs the semantic similarity search.

---

## 3. Chrome Extension Architecture
**Path:** `extension/`
**Stack:** WXT Framework, React 18, Tailwind CSS, TypeScript, Vite

The extension was recently migrated from vanilla JS to a modern React/Tailwind architecture using the **WXT framework**.

### Background Service Worker
- **Location:** `src/entrypoints/background.ts`
- **Purpose:** Acts as a network relay. Because Gmail and LinkedIn have strict Content Security Policies (CSP) that block `fetch` requests to `localhost:3000`, the content scripts send a message (`SCAN_REQUEST`) to the background worker. The background worker safely makes the HTTP POST request to the Next.js API and returns the data.

### Content Scripts & UI
- **Locations:** `src/entrypoints/gmail.content/index.tsx` & `linkedin.content/index.tsx`
- **Injection:** We use WXT's `createShadowRootUi` to inject a declarative Shadow DOM into the host pages. 
- **Styling Bypass:** Tailwind CSS is manually compiled as a string (`import tailwindCss from '@/assets/tailwind.css?inline';`) and injected directly via a `<style>` tag inside the Shadow DOM. This totally isolates our UI from Gmail's CSS and completely bypasses Gmail's CSP restrictions regarding external stylesheets.
- **Detection Logic:** A `MutationObserver` watches the DOM for email bodies (`.a3s.aiL` in Gmail) or feed updates, debounces for 1.5 seconds, and automatically fires a scan request.

### UI Component (`ThreatReportModal.tsx`)
- Starts as a small, non-intrusive floating blue button (with a shield icon) in the bottom-right corner.
- While fetching, it displays a loading spinner inside the button.
- Once the scan succeeds, clicking the button expands it into a fully styled, glassmorphic React modal showing a risk progress bar, threat indicators, and red-highlighted flagged phrases.

---

## 4. Recent Fixes & Quirks Addressed
- **Vite/WXT Conflict:** WXT 0.21.4 mandates Vite 6/Rolldown, which currently fails on Windows due to NPM binding bugs. We explicitly downgraded to `wxt@0.19.16` and `vite@5.4.11` to ensure stable compilation.
- **Gemini Model:** Updated the embedding model from `text-embedding-004` to `embedding-001` to ensure compatibility with older API keys/regions.
- **Database Schema:** Removed `event_id` from the Next.js insertion logic and the `match_threats` RPC, as the legacy database schema only uses a primary `id`.
- **Extension HMR vs CSP:** Gmail's CSP blocks Vite's HMR websocket. Therefore, when updating content scripts in development, a manual reload via `chrome://extensions/` followed by a page refresh is required.
