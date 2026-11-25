# CIPA Wiretap, VPPA Video Pixel & HIPAA Tracker Auditor (API + MCP Server)

**Bulk-audit 1,000+ US e-commerce stores, healthcare/wellness clinics, media sites, and SaaS platforms in minutes via ultra-fast, zero-browser HTTP for the highest-severity 2025–2026 US website wiretapping, video-pixel, health-tracker, and Global Privacy Control (GPC) lawsuit & enforcement triggers.**

Outputs a deterministic `complianceScore` (`0–100`), prioritized `findings[]`, CMP & script-gating fingerprint (`detectedCmp` + `ungatedSessionReplayVendors` + `ungatedChatWidgetVendors` + `ungatedAdPixelVendors`), neutral B2B `coldOutreachHook`, and ready-to-paste **Prior-Consent Script Gate Wrapper + Pre-Chat CIPA Recording Disclosure Widget + `/.well-known/gpc.json` + CCPA "Your Privacy Choices" HTML/JS snippets**.

Zero OpenAI/LLM keys required. Built for **Privacy & CMP Agencies (`OneTrust`, `Cookiebot`, `Usercentrics`, `Osano`, `Ketch`)**, **Healthcare Marketing Agencies**, **E-Commerce Compliance Consultants**, **Clay**, **n8n**, **Apify Dataset Chaining**, and **AI Agents via MCP (`Claude Desktop`, `Cursor`, `Windsurf`)**.

---

## Late-2026 US Statutory Enforcement Landscape (Verified Regulatory Accuracy)

US companies face **2,200+ website tracker lawsuits and arbitration mass-filings per year** alongside **$5,000-per-violation** statutory demand letters and multi-state Attorney General sweeps across four distinct legal frameworks:

1. **California Invasion of Privacy Act (`CIPA Cal. Penal Code §§ 631 & 632`) & Federal Wiretap Act (`ECPA 18 U.S.C. § 2511`)**
   - Carries a **`$5,000` per-violation statutory damages framework** (`Cal. Penal Code § 637.2`) when websites allow third-party session-replay vendors (`FullStory`, `Hotjar`, `Microsoft Clarity`, `LogRocket`, `Mouseflow`) or third-party live-chat / AI chatbot SDKs (`Intercom`, `Drift`, `Zendesk`, `Gorgias`, `Tidio`, `Ada`, `Qualified`) to intercept keystrokes, mouse movements, or chat communications in real time before prior opt-in consent.
   - **Important Late-2026 `SB 690` Statutory Distinction:** **California `SB 690` (signed September 30, 2026, effective January 1, 2027)** narrows private civil lawsuits *only* under CIPA's pen-register / trap-and-trace clause (`Cal. Penal Code § 638.51`, shifting commercial `§ 638.51` enforcement to the California Attorney General), while **leaving `CIPA §§ 631 & 632` wiretapping and confidential-communication eavesdropping claims over ungated third-party live-chat widgets, AI chatbots, and session-replay scripts untouched as an active private litigation trigger**!
2. **Video Privacy Protection Act (`VPPA 18 U.S.C. § 2710`)**
   - Exposes website operators to **`$2,500` statutory liquidated damages per violation** when pages embed video players (`YouTube`, `Vimeo`, `Wistia`, `JW Player`, `Mux`, `Brightcove`, `Vidyard`, `<video>`) alongside ungated ad-tech identity pixels (`Meta Pixel`, `TikTok Pixel`, `LinkedIn Insight`, `Snap`, `Pinterest`, `Reddit`, `X`, `Criteo`, `Google Ads`) capable of transmitting video-viewing URLs/titles paired with persistent user IDs (`c_user`, `_fbp`, `_ttp`) without separate, standalone video-sharing consent (`18 U.S.C. § 2710(b)(2)(B)`).
3. **Healthcare & Sensitive Intake Form Pixel Exposure (`HIPAA 45 CFR §§ 164.502(e), 164.508` post-*AHA v. Becerra*, `WA My Health My Data Act (MHMDA)`, & FTC Health Breach Actions)**
   - While *AHA v. Becerra* (2024) vacated HHS OCR's guidance only as to unauthenticated general-info browsing, **loading non-BAA ad pixels or session-replay scripts on `/book`, `/appointment`, `/intake`, `/patient`, `/schedule`, `/telehealth`, or `/consultation` forms collecting identifiable health, symptom, insurance, or appointment inputs remains critical exposure** (note: generic CMP cookie banners do *not* satisfy `45 CFR § 164.508` written HIPAA authorizations) under **HIPAA**, **Washington My Health My Data Act (`RCW 19.373` private right of action)**, and **FTC Health Breach / Section 5 enforcement**.
4. **CCPA/CPRA Global Privacy Control (`GPC` / `/.well-known/gpc.json`) & `"Your Privacy Choices"` (`Cal. Civ. Code § 1798.135`)**
   - Coordinated CA CPPA, CA AG, CO AG, and CT AG sweeps enforce honoring browser `Sec-GPC: 1` / `navigator.globalPrivacyControl` opt-out signals (with `/.well-known/gpc.json` declaring site GPC support) and providing a conspicuous `"Do Not Sell or Share My Personal Information"` / `"Your Privacy Choices"` opt-out link whenever ad-tech pixels are active.

### Agency & Outbound Lead-Gen ROI Math

| Metric | Manual DevTools / Privacy Audit | Bulk HTTP Audit (`healthy_addax/cipa-vppa-wiretap-pixel-auditor`) |
| :--- | :--- | :--- |
| **1,000 Clinics / Stores Audited** | ~160 hours of manual inspection | **~3–6 minutes (zero-Playwright HTTP engine)** |
| **Cost for 1,000 Sites** | $6,000+ privacy analyst time | **`$15.005`** (audit + hooks) or **`$25.005`** (with HTML/JS fix packs) |
| **Deliverables Included** | Manual notes | **CMP + ungated chat/replay/pixel list + VPPA & HIPAA form flags + `gpc.json` check + outreach hook + HTML/JS consent-gate code** |
| **Apify Free Tier (`$5.00/mo` credit)** | — | **Audit ~199 to ~333 sites every month for `$0`** |

> **Fair Pay-Per-Event Billing Guarantee:**
> - Invalid URLs, unreachable sites, non-HTML binary files (`application/pdf`, images), `robots.txt`-disallowed pages, and SSRF-blocked targets are **never billed (`$0`)**.
> - `remediation-pack-generated` (`$0.01`) is **only billed when `includeRemediationPack: true` AND `findings.length > 0`** — OneTrust/CMP-gated sites and clean brochure sites with zero findings are never charged for snippets they don't need!

---

## Core Heuristic Checks Per Site

For every target URL (supports full URLs like `https://clinic.example.com` and bare domains like `shop.example.com`), the Actor inspects the homepage, probes `/.well-known/gpc.json`, and fetches up to `maxLegalPagesPerDomain` (default `3`, max `5`) auto-discovered internal same-origin pages (`/appointment`, `/book`, `/intake`, `/schedule`, `/videos`, `/watch`, `/demo`, `/privacy`, `/contact`):

1. **Session-Replay & Third-Party Chat Wiretap Detection (`wiretapChatAndReplayCheck`)**
   - **Session Replay**: `fullstory`, `hotjar`, `microsoft-clarity`, `logrocket`, `mouseflow`, `lucky-orange`, `crazy-egg`, `contentsquare`, `smartlook`, `posthog-replay`.
   - **Third-Party Live & AI Chat**: `intercom`, `drift`, `zendesk-chat`, `gorgias-chat`, `tidio`, `livechat`, `hubspot-chat`, `crisp`, `ada-chat`, `qualified`.
   - **CMP & Script-Gating Verification (`detectedCmp`)**: Detects `onetrust`, `usercentrics`, `cookiebot`, `osano`, `termly`, `trustarc`, `ketch`, `securiti`, `didomi`, `iubenda`, `complianz`, `custom-cmp`, or `none`, and verifies whether each tracker `<script>` is **consent-gated** (`type="text/plain"`, `class="optanon-category-..."`, `data-cookieconsent`, `data-usercentrics`, `gtag('consent', 'default', ... 'denied')`) vs. **ungated eager load (`CRITICAL`)**, plus whether real-time third-party chat recording is disclosed.
2. **VPPA Video + Ad-Pixel Co-Presence Check (`vppaVideoPixelCheck`)**
   - Detects embedded video providers (`youtube`, `youtube-nocookie`, `vimeo`, `wistia`, `jwplayer`, `mux`, `vidyard`, `brightcove`, `html5-video`) firing alongside ungated ad-tech pixels (`meta-pixel`, `tiktok-pixel`, `google-ads`, `linkedin-insight`, `pinterest-tag`, `snap-pixel`, `reddit-pixel`, `x-pixel`, `criteo`) without standalone VPPA consent.
3. **Healthcare / Sensitive Intake Form Pixel Leak Check (`sensitiveFormPixelCheck`)**
   - Detects medical/healthcare/wellness appointment & patient intake forms (`appointment`, `patient`, `symptom`, `diagnosis`, `medication`, `insurance`, `treatment`, `telehealth`) firing ungated ad pixels or session-replay scripts directly on the intake page.
4. **GPC (`/.well-known/gpc.json`) & CCPA Opt-Out Link Check (`gpcAndOptOutCheck`)**
   - Probes `https://<origin>/.well-known/gpc.json` for `{"gpc": true}` and checks for `"Your Privacy Choices"` / `"Do Not Sell or Share My Personal Information"` opt-out controls when ad pixels are active.

---

## Input Parameters

| Field | Type | Default | Description |
| :--- | :--- | :---: | :--- |
| `urls` | `string[]` / RequestList | `["https://example.com"]` | Store, clinic, media, or SaaS URLs or bare domains (`"clinic.example.com"` or `"https://shop.example.com"`). |
| `url` | `string` | *Optional* | Single URL/domain shorthand for Clay HTTP columns, webhooks, or MCP calls. |
| `datasetId` | `string` | *Optional* | Upstream Apify Dataset ID (e.g. from **Google Maps Scraper** or **Shopify Store Scraper**) to auto-import URLs and deduplicate with `urls`. |
| `datasetUrlField` | `string` | *Auto-detect* | Optional field override for `datasetId` items (auto-detects `website`, `url`, `domain`, `shopUrl`, `storeUrl`, `clinicUrl`, `practiceUrl`, `appUrl`). |
| `maxLegalPagesPerDomain` | `integer` | `3` | Max discovered internal same-origin subpages fetched per site (`0–5`). |
| `includeRemediationPack` | `boolean` | `true` | Generates Prior-Consent Script Gate + Pre-Chat CIPA Disclosure + `/.well-known/gpc.json` + CCPA Opt-Out HTML/JS snippets when findings exist (`+$0.01/site`). |
| `checkWiretapChatAndReplay` | `boolean` | `true` | Audit ungated session-replay & third-party live/AI chat scripts (`CIPA §§ 631/632` & `ECPA`). |
| `checkVppaVideoPixels` | `boolean` | `true` | Audit embedded video + ungated ad-pixel co-presence (`VPPA 18 U.S.C. § 2710`). |
| `checkSensitiveIntakePixels` | `boolean` | `true` | Audit healthcare/patient/appointment intake forms for non-BAA ad pixels & session replay (`HIPAA` & `WA MHMDA`). |
| `checkGpcAndOptOut` | `boolean` | `true` | Probe `/.well-known/gpc.json` and check CCPA `"Your Privacy Choices"` opt-out links. |
| `respectRobotsTxt` | `boolean` | `true` | Respect domain `/robots.txt` rules before fetching pages. |
| `maxUrls` | `integer` | `100` | Safety ceiling on total sites audited in one run (`1–5000`). |
| `maxConcurrency` | `integer` | `5` | Parallel HTTP site workers (`1–20`). |
| `domainDelayMs` | `integer` | `300` | Polite delay in milliseconds between requests to the same hostname (`0–30000`). |
| `requestTimeoutMs` | `integer` | `12000` | Strict timeout per HTTP request in milliseconds (`2000–60000`). |

---

## Output Dataset Sample (JSON)

```json
{
  "url": "radianthealthclinic.example.com",
  "normalizedInputUrl": "https://radianthealthclinic.example.com",
  "finalUrl": "https://radianthealthclinic.example.com/",
  "domain": "radianthealthclinic.example.com",
  "auditedAt": "2026-11-25T05:45:00.000Z",
  "status": "audited",
  "httpStatus": 200,
  "pageTitle": "RadiantHealth Dermatology & Skincare Clinic — Book Online",
  "detectedLanguage": "en",
  "sitePlatform": "healthcare-web",
  "siteVertical": "healthcare_or_wellness",
  "detectedCmp": "none",
  "consentModeV2Detected": false,
  "loadTimeMs": 148,
  "pagesFetchedCount": 3,
  "pagesFetched": [
    "https://radianthealthclinic.example.com/",
    "https://radianthealthclinic.example.com/appointment",
    "https://radianthealthclinic.example.com/privacy"
  ],
  "errorMessage": null,
  "complianceScore": 0,
  "riskTier": "CRITICAL",
  "sessionReplayVendors": ["microsoft-clarity"],
  "ungatedSessionReplayVendors": ["microsoft-clarity"],
  "chatWidgetVendors": ["intercom"],
  "ungatedChatWidgetVendors": ["intercom"],
  "preChatRecordingDisclosureFound": false,
  "wiretapRiskFound": true,
  "embeddedVideoProviders": ["youtube"],
  "adPixelVendors": ["meta-pixel"],
  "ungatedAdPixelVendors": ["meta-pixel"],
  "vppaRiskFound": true,
  "sensitiveIntakeFormFound": true,
  "sensitiveFormPixelLeakFound": true,
  "gpcWellKnownFound": false,
  "gpcSupportDeclared": false,
  "ccpaPrivacyChoicesLinkFound": false,
  "gpcOrOptOutRiskFound": true,
  "findingsCount": 7,
  "coldOutreachHook": "While running a technical CIPA/VPPA/HIPAA pixel check on your clinic/healthcare site (radianthealthclinic.example.com), we noticed Meta Pixel + Microsoft Clarity fires directly on your patient/appointment intake flow without prior consent or BAA server-side scrubbing, and Microsoft Clarity + Intercom loads eagerly on page load before visitor opt-in consent (no CMP script gate detected) (plus 2 additional tracker/privacy signals) — happy to share the audit report and ready-to-paste HTML/JS prior-consent script gate, pre-chat CIPA disclosure, and GPC snippets if helpful for your team.",
  "remediationPackGenerated": true,
  "recommendedNextActors": [
    {
      "actorSlug": "healthy_addax/wcag-eaa-ada-auditor",
      "actorUrl": "https://apify.com/healthy_addax/wcag-eaa-ada-auditor",
      "mcpEndpointUrl": "https://mcp.apify.com/?tools=healthy_addax/wcag-eaa-ada-auditor",
      "reason": "Pair your CIPA/VPPA/HIPAA tracker check on radianthealthclinic.example.com with a headless Chromium ADA Title III / WCAG 2.2 Level AA & Accessibility Overlay (accessiBe/UserWay) audit with red-box visual screenshot proof."
    },
    {
      "actorSlug": "healthy_addax/eu-withdrawal-omnibus-auditor",
      "actorUrl": "https://apify.com/healthy_addax/eu-withdrawal-omnibus-auditor",
      "mcpEndpointUrl": "https://mcp.apify.com/?tools=healthy_addax/eu-withdrawal-omnibus-auditor",
      "reason": "If radianthealthclinic.example.com serves UK/EU visitors, audit it via fast HTTP for the mandatory EU 2-Step Electronic Withdrawal Button (Directive 2023/2673 Art. 11a / BGB § 356a), abolished EU ODR links, EmpCo green claims, and Omnibus 30-day pricing."
    },
    {
      "actorSlug": "healthy_addax/us-click-to-cancel-auditor",
      "actorUrl": "https://apify.com/healthy_addax/us-click-to-cancel-auditor",
      "mcpEndpointUrl": "https://mcp.apify.com/?tools=healthy_addax/us-click-to-cancel-auditor",
      "reason": "If radianthealthclinic.example.com offers subscriptions, memberships, or recurring patient/wellness plans, audit it for US Click-to-Cancel & Auto-Renewal Laws (CA AB 2863, NY/NYC Oct 2026 Rule, CO SB 25-145 B2B SaaS, ROSCA & CA SB 478 drip fees)."
    }
  ],
  "disclaimer": "Automated technical heuristic signals for human review only; does not constitute legal advice or formal regulatory certification."
}
```

---

## Connect as an AI Agent MCP Tool (`Claude Desktop`, `Cursor`, `Windsurf`)

This Actor natively runs an **Apify Standby Streamable HTTP MCP Server** (`/mcp`) exposing `audit_cipa_vppa_wiretap_risk`:

- **Hosted Apify MCP URL**: `https://mcp.apify.com/?tools=healthy_addax/cipa-vppa-wiretap-pixel-auditor`

### `claude_desktop_config.json` / `.cursor/mcp.json`

```json
{
  "mcpServers": {
    "cipa-vppa-wiretap-pixel-auditor": {
      "url": "https://mcp.apify.com/?tools=healthy_addax/cipa-vppa-wiretap-pixel-auditor",
      "headers": {
        "Authorization": "Bearer <YOUR_APIFY_TOKEN>"
      }
    }
  }
}
```

Example prompt in Claude / Cursor:
> *"Use `audit_cipa_vppa_wiretap_risk` to inspect `clinic.example.com` for CIPA §§ 631/632 ungated chat & session-replay scripts, VPPA video + Meta Pixel leaks, HIPAA/MHMDA intake trackers, and `/.well-known/gpc.json`, then implement the returned prior-consent script gate and pre-chat recording disclosure snippets."*

---

## Complete 4-Actor US + EU + ADA + Privacy Compliance Suite

| Compliance Layer | Actor | Engine & Speed |
| :--- | :--- | :--- |
| **CIPA Wiretap (`§§ 631/632`), VPPA Video Pixels (`18 U.S.C. § 2710`), HIPAA/MHMDA Intake Trackers & `GPC`/`CCPA` Opt-Outs** | **`healthy_addax/cipa-vppa-wiretap-pixel-auditor`** *(This Actor)* | **Zero-Playwright Pinned HTTP** (~150–400ms/site, `$0.015`/site) |
| **US Click-to-Cancel, Auto-Renewal Laws (`CA AB 2863`, `NY/NYC ARL`, `CO SB 25-145 B2B SaaS`), `ROSCA` & `CA SB 478` Drip Fees** | **[`healthy_addax/us-click-to-cancel-auditor`](https://apify.com/healthy_addax/us-click-to-cancel-auditor)** | **Zero-Playwright Pinned HTTP** (~150–400ms/site, `$0.015`/site) |
| **ADA Title III / WCAG 2.2 Level AA, European Accessibility Act (`EAA`) & Overlay Widgets (`accessiBe`/`UserWay`)** | **[`healthy_addax/wcag-eaa-ada-auditor`](https://apify.com/healthy_addax/wcag-eaa-ada-auditor)** | **Headless Chromium + `axe-core`** (Red-box PNG visual proof + HTML diffs) |
| **EU Withdrawal Button (`Directive 2023/2673 Art. 11a`), Dead EU ODR Links, `EmpCo` Green Claims & `Omnibus` 30-Day Pricing** | **[`healthy_addax/eu-withdrawal-omnibus-auditor`](https://apify.com/healthy_addax/eu-withdrawal-omnibus-auditor)** | **Zero-Playwright Pinned HTTP** (~150–400ms/store, `$0.015`/store) |

---

## Security & Operational Guarantees

- **Zero-Browser Attack Surface & Low Memory**: Runs on `apify/actor-node:22` (`256 MB` min RAM) with zero headless browser overhead and deterministic static HTML/script parsing.
- **Anti-DNS-Rebinding & 128-Bit IPv6 SSRF Protection**: Every hostname is validated against private IPv4/IPv6 ranges and cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, IPv4-mapped/NAT64/6to4 IPv6), with resolved safe IPs **pinned directly at the Node TCP socket `lookup` layer** and validated across every HTTP redirect hop (max 5 hops).
- **Bounded Memory & Polite Crawling**: Responses are capped at `2 MB` (both wire and decompressed gzip/deflate/brotli) with `12s` strict timeouts, `robots.txt` compliance, and per-domain rate limiting.

---

## Legal Disclaimer

> **Automated technical heuristic signals for human review only; does not constitute legal advice or formal regulatory certification.**
>
> Static HTTP HTML inspection identifies publicly visible `<script>`, `<iframe>`, `<video>`, `<form>`, and `/.well-known/gpc.json` markup on inspected pages. Dynamically injected tags inside Google Tag Manager containers, server-side event proxies, signed HIPAA Business Associate Agreements (BAAs), or state-specific statutory exemptions require human verification and review by qualified US privacy counsel.
