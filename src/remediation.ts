import type {
  ComplianceFinding,
  DetectedCmp,
  DiscoveredPrivacyLinks,
  GpcAndOptOutCheckResult,
  RecommendedNextActor,
  RemediationPack,
  RiskTier,
  SensitiveFormPixelCheckResult,
  SitePlatform,
  SiteVertical,
  VppaVideoPixelCheckResult,
  WiretapChatAndReplayCheckResult,
} from './types.js';

export const US_WIRETAP_VPPA_HIPAA_STATUTORY_SUMMARY =
  'Late-2026 US tracker & pixel enforcement spans four active statutory fronts: (1) California Invasion of Privacy Act (CIPA Cal. Penal Code §§ 631 & 632; $5,000 statutory damages framework under § 637.2) & Federal Wiretap Act (ECPA 18 U.S.C. § 2511) — note that California SB 690 (signed Sept 30, 2026, effective Jan 1, 2027) narrows private lawsuits ONLY under the pen-register clause (§ 638.51, shifting § 638.51 enforcement to the CA Attorney General), while leaving CIPA §§ 631 & 632 wiretapping and confidential-communication eavesdropping claims over ungated third-party live-chat widgets, AI chatbots, and session-replay scripts untouched as an active private litigation trigger; (2) Video Privacy Protection Act (VPPA 18 U.S.C. § 2710; $2,500 statutory liquidated damages) when embedded video players fire alongside ungated ad-tech identity pixels without standalone video-sharing consent; (3) Healthcare & Sensitive Intake Pixel rules under HIPAA (45 CFR §§ 164.502(e), 164.508 post-AHA v. Becerra for appointment/patient intake forms — cookie banners are not HIPAA authorizations), Washington My Health My Data Act (MHMDA, RCW 19.373), and FTC Health Breach actions; and (4) CCPA/CPRA Global Privacy Control (GPC / /.well-known/gpc.json) & "Your Privacy Choices" opt-out mandates (Cal. Civ. Code § 1798.135).';

export function buildFindingsAndScore(params: {
  homeUrl: string;
  discoveredLinks: DiscoveredPrivacyLinks;
  wiretapChatAndReplay: WiretapChatAndReplayCheckResult;
  vppaVideoPixel: VppaVideoPixelCheckResult;
  sensitiveFormPixel: SensitiveFormPixelCheckResult;
  gpcAndOptOut: GpcAndOptOutCheckResult;
}): {
  findings: ComplianceFinding[];
  complianceScore: number;
  riskTier: RiskTier;
} {
  const {
    homeUrl,
    discoveredLinks,
    wiretapChatAndReplay,
    vppaVideoPixel,
    sensitiveFormPixel,
    gpcAndOptOut,
  } = params;

  const findings: ComplianceFinding[] = [];
  let deductions = 0;

  // 1. CIPA §§ 631 & 632 / ECPA Session-Replay & Third-Party Chat Wiretap Checks
  if (wiretapChatAndReplay.checked) {
    if (wiretapChatAndReplay.ungatedSessionReplayVendors.length > 0) {
      deductions += 35;
      findings.push({
        ruleId: 'US-CIPA-631-632-UNGATED-SESSION-REPLAY',
        title: 'Ungated Session-Replay SDK Recording User Interactions Before Affirmative Consent',
        regulation:
          'California Invasion of Privacy Act (CIPA Cal. Penal Code §§ 631 & 632; $5,000 statutory framework under § 637.2 — unaffected by CA SB 690 § 638.51 pen-register carveout) & Federal Wiretap Act (ECPA 18 U.S.C. § 2511)',
        severity: 'CRITICAL',
        pageUrl: wiretapChatAndReplay.foundOnPages[0] || homeUrl,
        evidence:
          wiretapChatAndReplay.wiretapEvidence.find((e) => e.includes('session-replay')) ||
          `Session-replay vendor(s) [${wiretapChatAndReplay.ungatedSessionReplayVendors.join(', ')}] load eagerly on page load without CMP script-blocking attributes (detectedCmp: ${wiretapChatAndReplay.detectedCmp}).`,
        recommendation:
          'Gate all session-replay scripts behind prior opt-in consent (e.g., `type="text/plain"` with CMP consent category activation), mask all form inputs (`data-private` / strict input masking), and suppress replay completely when `navigator.globalPrivacyControl === true`.',
      });
    }

    if (wiretapChatAndReplay.ungatedChatWidgetVendors.length > 0) {
      deductions += 30;
      findings.push({
        ruleId: 'US-CIPA-631-632-UNGATED-THIRD-PARTY-CHAT',
        title: 'Ungated Third-Party Live-Chat / AI Chatbot SDK Booting Without Prior Wiretap Consent',
        regulation:
          'California Invasion of Privacy Act (CIPA Cal. Penal Code §§ 631 & 632 — untouched by SB 690 for third-party chat eavesdropping) & Federal ECPA (18 U.S.C. § 2511)',
        severity: 'CRITICAL',
        pageUrl: wiretapChatAndReplay.foundOnPages[0] || homeUrl,
        evidence:
          wiretapChatAndReplay.wiretapEvidence.find((e) => e.includes('chat SDK')) ||
          `Third-party chat SDK(s) [${wiretapChatAndReplay.ungatedChatWidgetVendors.join(', ')}] initialize eagerly without prior-consent script gating.`,
        recommendation:
          'Defer loading third-party live-chat and AI chatbot SDKs until the visitor clicks a pre-chat launcher gate and affirmatively consents to real-time chat recording and third-party vendor processing.',
      });
    }

    if (
      wiretapChatAndReplay.chatWidgetVendors.length > 0 &&
      !wiretapChatAndReplay.preChatRecordingDisclosureFound
    ) {
      deductions += 15;
      findings.push({
        ruleId: 'US-CIPA-631-632-MISSING-CHAT-RECORDING-DISCLOSURE',
        title: 'Third-Party Chat Widget Present Without Explicit Real-Time Chat Recording Disclosure',
        regulation:
          'California Invasion of Privacy Act (CIPA Cal. Penal Code §§ 631 & 632) & State All-Party Wiretap Consent Laws',
        severity: 'HIGH',
        pageUrl: discoveredLinks.privacyPolicyUrl || homeUrl,
        evidence: `Detected third-party chat widget(s) [${wiretapChatAndReplay.chatWidgetVendors.join(', ')}], but inspected pages lacked explicit pre-chat or privacy-notice language disclosing real-time chat recording/transcription by a third-party vendor.`,
        recommendation:
          'Add a clear pre-chat consent banner before the first message can be typed stating that chat messages are recorded and processed in real time by your named third-party chat/AI provider, linked to your Privacy Policy.',
      });
    }
  }

  // 2. VPPA (18 U.S.C. § 2710) Video + Ad-Pixel Co-Presence Check
  if (vppaVideoPixel.checked && vppaVideoPixel.vppaRiskFound) {
    deductions += 35;
    findings.push({
      ruleId: 'US-VPPA-2710-VIDEO-AD-PIXEL-CO-PRESENCE',
      title: 'Embedded Video Player Co-Present With Ungated Ad-Tech Identity Pixel(s) Without Standalone VPPA Consent',
      regulation:
        'Video Privacy Protection Act (VPPA 18 U.S.C. § 2710 — $2,500 statutory liquidated damages per violation; standalone consent rule § 2710(b)(2)(B))',
      severity: 'CRITICAL',
      pageUrl: vppaVideoPixel.foundOnPages[0] || discoveredLinks.videoPageUrl || homeUrl,
      evidence:
        vppaVideoPixel.vppaEvidence[0] ||
        `Embedded video provider(s) [${vppaVideoPixel.ungatedVideoProviders.join(', ')}] co-exist with ungated ad pixel(s) [${vppaVideoPixel.ungatedAdPixelVendors.join(', ')}] capable of pairing video URLs/titles with persistent user IDs.`,
      recommendation:
        'Block all third-party ad-tech pixels (`Meta Pixel`, `TikTok`, `LinkedIn`, `Snap`, etc.) on pages with video embeds unless separate, standalone VPPA video-sharing opt-in consent is obtained, or strip video titles/paths from pixel payloads.',
    });
  }

  // 3. Healthcare / Sensitive Intake Form Pixel Exposure (HIPAA post-AHA v. Becerra & WA MHMDA)
  if (sensitiveFormPixel.checked && sensitiveFormPixel.sensitiveFormPixelLeakFound) {
    deductions += 40;
    findings.push({
      ruleId: 'US-HIPAA-MHMDA-SENSITIVE-INTAKE-PIXEL-LEAK',
      title: 'Non-BAA Ad Pixel or Session-Replay Tracker Firing on Healthcare / Sensitive Intake Form Page',
      regulation:
        'HIPAA Privacy Rule (45 CFR § 164.502(e) post-AHA v. Becerra for patient/appointment intake flows), Washington My Health My Data Act (MHMDA, RCW 19.373), & FTC Health Breach / Section 5 Enforcement',
      severity: 'CRITICAL',
      pageUrl:
        sensitiveFormPixel.sensitiveFormPages[0] || discoveredLinks.intakeOrBookingUrl || homeUrl,
      evidence:
        sensitiveFormPixel.evidence[0] ||
        `Ungated tracker(s) [${sensitiveFormPixel.ungatedTrackersOnFormPages.join(', ')}] fire on sensitive appointment/patient intake form page(s).`,
      recommendation:
        'Immediately remove all non-BAA client-side ad pixels (`Meta`, `TikTok`, `Google Ads`) and session-replay scripts (`Clarity`, `FullStory`, `Hotjar`) from `/appointment`, `/book`, `/intake`, `/patient`, and `/telehealth` routes; route any conversion analytics exclusively through a HIPAA-compliant server-side proxy that scrubs health/PHI parameters.',
    });
  }

  // 4. CCPA/CPRA Global Privacy Control (`/.well-known/gpc.json`) & "Your Privacy Choices" Opt-Out Link
  if (gpcAndOptOut.checked && gpcAndOptOut.adTrackersPresent) {
    if (!gpcAndOptOut.ccpaPrivacyChoicesLinkFound) {
      deductions += 20;
      findings.push({
        ruleId: 'US-CCPA-1798-135-MISSING-PRIVACY-CHOICES-OPT-OUT',
        title: 'Ad-Tech Trackers Active Without "Your Privacy Choices" / "Do Not Sell or Share" Opt-Out Link',
        regulation:
          'CCPA/CPRA (Cal. Civ. Code § 1798.135 & 11 CCR § 7013) & Multi-State Consumer Privacy Opt-Out Mandates',
        severity: 'HIGH',
        pageUrl: homeUrl,
        evidence:
          'Third-party ad-tech pixels were detected on the site, but no visible "Your Privacy Choices" or "Do Not Sell or Share My Personal Information" opt-out link or footer control was found.',
        recommendation:
          'Publish a conspicuous "Your Privacy Choices" / "Do Not Sell or Share My Personal Information" link in the global website footer wired to immediately disable ad-tech sharing tags upon opt-out.',
      });
    }

    if (!gpcAndOptOut.gpcSupportDeclared && !gpcAndOptOut.clientGpcListenerDetected) {
      deductions += 10;
      findings.push({
        ruleId: 'US-CCPA-CPRA-GPC-SIGNAL-UNDECLARED',
        title: 'Ad-Tech Trackers Active Without /.well-known/gpc.json or Global Privacy Control (GPC) Signal Handling',
        regulation:
          'CCPA/CPRA Global Privacy Control Mandate (Cal. Civ. Code § 1798.135(e), 11 CCR § 7025) & W3C GPC /.well-known/gpc.json Specification',
        severity: 'MODERATE',
        pageUrl: gpcAndOptOut.gpcEndpointUrl || homeUrl,
        evidence: `Probing ${gpcAndOptOut.gpcEndpointUrl || '/.well-known/gpc.json'} did not return {"gpc": true} (HTTP ${gpcAndOptOut.gpcHttpStatus ?? 'missing'}) and no client-side \`navigator.globalPrivacyControl\` listener was detected while ad-tech pixels are active.`,
        recommendation:
          'Serve `{"gpc": true, "lastUpdate": "YYYY-MM-DD"}` at `/.well-known/gpc.json` and check `navigator.globalPrivacyControl === true` (and `Sec-GPC: 1` headers) to automatically suppress ad-tech pixels for opted-out browsers.',
      });
    }
  }

  const severityOrder: Record<ComplianceFinding['severity'], number> = {
    CRITICAL: 0,
    HIGH: 1,
    MODERATE: 2,
    LOW: 3,
  };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const complianceScore = Math.max(0, Math.min(100, 100 - deductions));

  let riskTier: RiskTier;
  if (findings.some((f) => f.severity === 'CRITICAL') || complianceScore <= 35) {
    riskTier = 'CRITICAL';
  } else if (findings.some((f) => f.severity === 'HIGH') || complianceScore <= 70) {
    riskTier = 'HIGH';
  } else if (findings.length > 0 || complianceScore <= 85) {
    riskTier = 'MODERATE';
  } else {
    riskTier = 'LOW';
  }

  return { findings, complianceScore, riskTier };
}

function prettyVendor(slug: string): string {
  const names: Record<string, string> = {
    'meta-pixel': 'Meta Pixel',
    'tiktok-pixel': 'TikTok Pixel',
    'google-ads': 'Google Ads',
    'linkedin-insight': 'LinkedIn Insight',
    'pinterest-tag': 'Pinterest Tag',
    'snap-pixel': 'Snap Pixel',
    'reddit-pixel': 'Reddit Pixel',
    'x-pixel': 'X Pixel',
    criteo: 'Criteo',
    'microsoft-clarity': 'Microsoft Clarity',
    fullstory: 'FullStory',
    hotjar: 'Hotjar',
    logrocket: 'LogRocket',
    mouseflow: 'Mouseflow',
    'lucky-orange': 'Lucky Orange',
    'crazy-egg': 'Crazy Egg',
    contentsquare: 'Contentsquare',
    smartlook: 'Smartlook',
    'posthog-replay': 'PostHog Replay',
    intercom: 'Intercom',
    drift: 'Drift',
    'zendesk-chat': 'Zendesk Chat',
    'gorgias-chat': 'Gorgias Chat',
    tidio: 'Tidio',
    livechat: 'LiveChat',
    'hubspot-chat': 'HubSpot Chat',
    crisp: 'Crisp',
    'ada-chat': 'Ada AI Chat',
    qualified: 'Qualified',
    youtube: 'YouTube',
    'youtube-nocookie': 'YouTube (nocookie)',
    vimeo: 'Vimeo',
    wistia: 'Wistia',
    jwplayer: 'JW Player',
    mux: 'Mux',
    vidyard: 'Vidyard',
    brightcove: 'Brightcove',
    'html5-video': 'HTML5 <video>',
  };
  return names[slug] || slug;
}

/**
 * Generates a neutral, factual 1-2 sentence B2B outreach observation tailored for
 * Privacy/CMP Agencies, Healthcare Marketing Agencies, and E-Commerce Compliance Consultants.
 */
export function generateColdOutreachHook(params: {
  domain: string;
  siteVertical: SiteVertical;
  detectedCmp: DetectedCmp;
  wiretapChatAndReplay: WiretapChatAndReplayCheckResult;
  vppaVideoPixel: VppaVideoPixelCheckResult;
  sensitiveFormPixel: SensitiveFormPixelCheckResult;
  gpcAndOptOut: GpcAndOptOutCheckResult;
  findings: ComplianceFinding[];
}): string {
  const {
    domain,
    siteVertical,
    detectedCmp,
    wiretapChatAndReplay,
    vppaVideoPixel,
    sensitiveFormPixel,
    gpcAndOptOut,
    findings,
  } = params;

  if (findings.length === 0) {
    if (detectedCmp !== 'none') {
      return `An automated technical privacy & pixel review of ${domain} confirmed prior-consent script gating (${detectedCmp}), GPC/opt-out support, and zero ungated CIPA, VPPA, or sensitive-form tracker exposures.`;
    }
    return `An automated technical scan of ${domain} found zero ungated session-replay scripts, third-party chat wiretap triggers, VPPA video-pixel leaks, or sensitive intake trackers on inspected public pages.`;
  }

  const observations: string[] = [];

  if (sensitiveFormPixel.sensitiveFormPixelLeakFound) {
    const trackerList = sensitiveFormPixel.ungatedTrackersOnFormPages.slice(0, 2).map(prettyVendor);
    const trackers = trackerList.join(' + ');
    const fireVerb = trackerList.length > 1 ? 'fire' : 'fires';
    observations.push(
      `${trackers} ${fireVerb} directly on your patient/appointment intake flow without BAA server-side scrubbing or HIPAA § 164.508 authorization`,
    );
  }

  if (
    wiretapChatAndReplay.ungatedSessionReplayVendors.length > 0 ||
    wiretapChatAndReplay.ungatedChatWidgetVendors.length > 0
  ) {
    const wiretapList = [
      ...wiretapChatAndReplay.ungatedSessionReplayVendors.map(prettyVendor),
      ...wiretapChatAndReplay.ungatedChatWidgetVendors.map(prettyVendor),
    ].slice(0, 2);
    const wiretapTools = wiretapList.join(' + ');
    const loadVerb = wiretapList.length > 1 ? 'load' : 'loads';
    observations.push(
      `${wiretapTools} ${loadVerb} eagerly on page load before visitor opt-in consent${detectedCmp === 'none' ? ' (no CMP script gate detected)' : ''}`,
    );
  } else if (
    wiretapChatAndReplay.chatWidgetVendors.length > 0 &&
    !wiretapChatAndReplay.preChatRecordingDisclosureFound
  ) {
    const chatName = prettyVendor(wiretapChatAndReplay.chatWidgetVendors[0]);
    observations.push(
      `${chatName} initializes without a visible pre-chat third-party recording disclosure`,
    );
  }

  if (vppaVideoPixel.vppaRiskFound) {
    const vid = prettyVendor(vppaVideoPixel.ungatedVideoProviders[0] || 'video');
    const pix = prettyVendor(vppaVideoPixel.ungatedAdPixelVendors[0] || 'ad pixel');
    observations.push(
      `embedded ${vid} player pages run ungated ${pix} tracking without standalone video-sharing consent`,
    );
  }

  if (gpcAndOptOut.adTrackersPresent && !gpcAndOptOut.ccpaPrivacyChoicesLinkFound) {
    observations.push(
      `active ad pixels lack a footer "Your Privacy Choices" opt-out link and /.well-known/gpc.json declaration`,
    );
  } else if (gpcAndOptOut.adTrackersPresent && !gpcAndOptOut.gpcSupportDeclared) {
    observations.push(`/.well-known/gpc.json is not yet published for Global Privacy Control browsers`);
  }

  const topTwo = observations.slice(0, 2).join(', and ');
  const extraCount = Math.max(0, observations.length - 2);
  const suffix =
    extraCount > 0 ? ` (plus ${extraCount} additional tracker/privacy signal${extraCount > 1 ? 's' : ''})` : '';

  const verticalLabel =
    siteVertical === 'healthcare_or_wellness'
      ? `your clinic/healthcare site (${domain})`
      : siteVertical === 'ecommerce_or_dtc'
        ? `your storefront (${domain})`
        : `your site (${domain})`;

  return `While running a technical CIPA/VPPA/HIPAA pixel check on ${verticalLabel}, we noticed ${topTwo}${suffix} — happy to share the audit report and ready-to-paste HTML/JS prior-consent script gate, pre-chat CIPA disclosure, and GPC snippets if helpful for your team.`;
}

/**
 * Generates ready-to-paste remediation pack:
 * 1) Prior-Consent Script Gate Wrapper (HTML/JS) with automatic GPC (`navigator.globalPrivacyControl`) suppression
 * 2) Pre-Chat CIPA §§ 631/632 Recording & Third-Party Vendor Disclosure Gate Widget (HTML/JS)
 * 3) `/.well-known/gpc.json` static file payload
 * 4) CCPA/CPRA "Your Privacy Choices" (`Cal. Civ. Code § 1798.135`) Footer Link + Opt-Out Modal (HTML/JS)
 */
export function generateRemediationPack(params: {
  domain: string;
  sitePlatform: SitePlatform;
  siteVertical: SiteVertical;
  detectedCmp: DetectedCmp;
  wiretapChatAndReplay: WiretapChatAndReplayCheckResult;
  sensitiveFormPixel: SensitiveFormPixelCheckResult;
}): RemediationPack {
  const {
    domain,
    sitePlatform,
    siteVertical,
    detectedCmp,
    wiretapChatAndReplay,
    sensitiveFormPixel,
  } = params;

  const chatVendorLabel =
    wiretapChatAndReplay.chatWidgetVendors.length > 0
      ? wiretapChatAndReplay.chatWidgetVendors.map(prettyVendor).join(' / ')
      : 'our third-party customer messaging & AI support provider';

  const todayIsoDate = new Date().toISOString().slice(0, 10);

  const priorConsentScriptGateHtmlJs = `<!-- CIPA §§ 631/632, ECPA & VPPA Prior-Consent Script Gate Wrapper (${domain}) -->
<!-- 1. Convert eager session-replay, ad-pixel & video-tracking <script> tags to type="text/plain" with data-cipa-consent-category and data-src: -->
<!-- Example:
<script
  type="text/plain"
  data-cipa-consent-category="analytics_replay"
  data-src="https://www.clarity.ms/tag/YOUR_TAG_ID"></script>
<script
  type="text/plain"
  data-cipa-consent-category="ad_pixels_vppa"
  data-src="https://connect.facebook.net/en_US/fbevents.js"></script>
-->
<div id="cipa-vppa-consent-banner" role="region" aria-label="Privacy and Tracking Consent" hidden
  style="position:fixed;bottom:16px;left:16px;right:16px;max-width:640px;z-index:9999;background:#111827;color:#f9fafb;padding:18px 20px;border-radius:10px;box-shadow:0 10px 25px rgba(0,0,0,0.25);font-family:system-ui,sans-serif;">
  <p style="margin:0 0 10px;font-size:0.9rem;line-height:1.45;">
    <strong>Privacy, Analytics &amp; Video Preferences:</strong> ${domain} uses optional analytics, session diagnostics, and advertising pixels only with your express prior consent. Lookups from Global Privacy Control (<code>Sec-GPC: 1</code>) are automatically honored.
  </p>
  <label for="cipa-vppa-standalone-video-optin" style="display:flex;align-items:flex-start;gap:8px;font-size:0.82rem;margin-bottom:12px;color:#e5e7eb;">
    <!-- CRITICAL: Never add "checked" by default (VPPA 18 U.S.C. § 2710(b)(2)(B) standalone opt-in) -->
    <input id="cipa-vppa-standalone-video-optin" type="checkbox" style="margin-top:2px;" />
    <span>I also separately consent to sharing video-viewing interactions on ${domain} with advertising partners.</span>
  </label>
  <div style="display:flex;gap:10px;flex-wrap:wrap;">
    <button type="button" id="cipa-consent-reject-btn"
      style="padding:8px 14px;border:1px solid #6b7280;background:transparent;color:#f9fafb;border-radius:6px;cursor:pointer;">
      Decline Optional Trackers
    </button>
    <button type="button" id="cipa-consent-accept-btn"
      style="padding:8px 16px;border:none;background:#2563eb;color:#ffffff;border-radius:6px;font-weight:600;cursor:pointer;">
      Accept Selected
    </button>
  </div>
</div>
<script>
(function () {
  var STORAGE_KEY = 'cipa_vppa_consent_v1';
  var gpcEnabled = Boolean(navigator.globalPrivacyControl === true);

  function activateGatedScripts(allowedCategories) {
    if (gpcEnabled) return; // Strictly suppress ad/replay trackers when GPC is active
    var nodes = document.querySelectorAll('script[type="text/plain"][data-cipa-consent-category]');
    nodes.forEach(function (oldScript) {
      var cat = oldScript.getAttribute('data-cipa-consent-category') || '';
      if (allowedCategories.indexOf(cat) === -1) return;
      var replacement = document.createElement('script');
      replacement.type = 'text/javascript';
      var deferredSrc = oldScript.getAttribute('data-src');
      if (deferredSrc) {
        replacement.src = deferredSrc;
        replacement.async = true;
      } else {
        replacement.text = oldScript.textContent || '';
      }
      oldScript.parentNode.replaceChild(replacement, oldScript);
    });
  }

  if (gpcEnabled) {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ gpc: true, categories: [], updatedAt: new Date().toISOString() }));
    return;
  }

  try {
    var saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
    if (saved && Array.isArray(saved.categories)) {
      activateGatedScripts(saved.categories);
      return;
    }
  } catch (_) {}

  var banner = document.getElementById('cipa-vppa-consent-banner');
  var acceptBtn = document.getElementById('cipa-consent-accept-btn');
  var rejectBtn = document.getElementById('cipa-consent-reject-btn');
  var vppaBox = document.getElementById('cipa-vppa-standalone-video-optin');
  if (!banner || !acceptBtn || !rejectBtn) return;
  banner.hidden = false;

  acceptBtn.addEventListener('click', function () {
    var cats = ['analytics_replay'];
    if (vppaBox && vppaBox.checked) cats.push('ad_pixels_vppa');
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ categories: cats, consentedAt: new Date().toISOString() }));
    window.__cipaConsentGranted = true;
    banner.hidden = true;
    activateGatedScripts(cats);
  });

  rejectBtn.addEventListener('click', function () {
    localStorage.setItem(STORAGE_KEY, JSON.stringify({ categories: [], consentedAt: new Date().toISOString() }));
    banner.hidden = true;
  });
})();
</script>`;

  const preChatCipaDisclosureWidgetHtmlJs = `<!-- CIPA §§ 631 & 632 Pre-Chat Wiretap & Third-Party Recording Consent Gate (${domain}) -->
<div id="cipa-prechat-gate" style="position:fixed;bottom:20px;right:20px;z-index:9998;font-family:system-ui,sans-serif;">
  <button type="button" id="cipa-open-prechat-btn"
    style="padding:11px 18px;border:none;border-radius:999px;background:#111827;color:#ffffff;font-weight:600;cursor:pointer;box-shadow:0 4px 14px rgba(0,0,0,0.2);">
    Chat with Support
  </button>
  <div id="cipa-prechat-modal" role="dialog" aria-labelledby="cipa-prechat-title" hidden
    style="width:320px;background:#ffffff;border:1px solid #d1d5db;border-radius:12px;padding:16px;margin-top:10px;box-shadow:0 12px 28px rgba(0,0,0,0.18);">
    <h3 id="cipa-prechat-title" style="margin:0 0 8px;font-size:0.95rem;color:#111827;">Live &amp; AI Chat Recording Notice</h3>
    <p style="margin:0 0 10px;font-size:0.82rem;line-height:1.45;color:#374151;">
      To assist you, chat messages are recorded, transcribed, and processed in real time on behalf of <strong>${domain}</strong> by <strong>${chatVendorLabel}</strong> in accordance with our <a href="/privacy" style="color:#1d4ed8;">Privacy Policy</a>.
    </p>
    <label for="cipa-prechat-consent-checkbox" style="display:flex;align-items:flex-start;gap:8px;font-size:0.82rem;color:#111827;margin-bottom:12px;cursor:pointer;">
      <!-- CRITICAL: Must default to UNCHECKED prior to chat SDK initialization -->
      <input id="cipa-prechat-consent-checkbox" type="checkbox" required style="margin-top:2px;" />
      <span>I consent to real-time chat recording and third-party processing before starting chat.</span>
    </label>
    <button type="button" id="cipa-start-chat-confirmed-btn"
      style="width:100%;padding:9px 12px;border:none;border-radius:6px;background:#1d4ed8;color:#ffffff;font-weight:600;cursor:pointer;">
      Agree &amp; Start Chat
    </button>
  </div>
</div>
<script>
(function () {
  var openBtn = document.getElementById('cipa-open-prechat-btn');
  var modal = document.getElementById('cipa-prechat-modal');
  var cb = document.getElementById('cipa-prechat-consent-checkbox');
  var startBtn = document.getElementById('cipa-start-chat-confirmed-btn');
  if (!openBtn || !modal || !cb || !startBtn) return;

  openBtn.addEventListener('click', function () {
    modal.hidden = !modal.hidden;
  });

  startBtn.addEventListener('click', function () {
    if (!cb.checked) {
      cb.reportValidity();
      return;
    }
    window.cipaPreChatConsentIso = new Date().toISOString();
    modal.hidden = true;
    openBtn.hidden = true;
    // Dynamically inject your chat SDK ONLY after affirmative pre-chat consent:
    var chatScript = document.querySelector('script[type="text/plain"][data-cipa-chat-src]');
    if (chatScript) {
      var live = document.createElement('script');
      live.src = chatScript.getAttribute('data-cipa-chat-src');
      live.async = true;
      document.head.appendChild(live);
    }
  });
})();
</script>`;

  const wellKnownGpcJson = JSON.stringify(
    {
      gpc: true,
      lastUpdate: todayIsoDate,
    },
    null,
    2,
  );

  const ccpaPrivacyChoicesFooterHtmlJs = `<!-- CCPA/CPRA Cal. Civ. Code § 1798.135 "Your Privacy Choices" & GPC Opt-Out Control (${domain}) -->
<a href="#your-privacy-choices" id="ccpa-privacy-choices-link"
  style="display:inline-flex;align-items:center;gap:6px;font-size:0.875rem;color:#1f2937;text-decoration:underline;">
  <span aria-hidden="true">&#x2611;&#xFE0F;</span> Your Privacy Choices (Do Not Sell or Share My Personal Information)
</a>
<dialog id="ccpa-optout-dialog" aria-labelledby="ccpa-optout-title"
  style="max-width:440px;width:92%;border:1px solid #d1d5db;border-radius:10px;padding:20px;font-family:system-ui,sans-serif;">
  <h2 id="ccpa-optout-title" style="margin:0 0 8px;font-size:1.05rem;">Your Privacy Choices</h2>
  <p id="ccpa-gpc-status-banner" style="margin:0 0 12px;font-size:0.85rem;color:#374151;">
    Opt out of cross-context behavioral advertising pixels ("sale" or "sharing" under California Civil Code § 1798.135).
  </p>
  <div style="display:flex;gap:10px;justify-content:flex-end;">
    <button type="button" id="ccpa-close-dialog-btn"
      style="padding:8px 12px;border:1px solid #d1d5db;background:#f9fafb;border-radius:6px;cursor:pointer;">Close</button>
    <button type="button" id="ccpa-confirm-optout-btn"
      style="padding:8px 14px;border:none;background:#111827;color:#ffffff;border-radius:6px;font-weight:600;cursor:pointer;">
      Opt Out of Sale / Sharing
    </button>
  </div>
</dialog>
<script>
(function () {
  var link = document.getElementById('ccpa-privacy-choices-link');
  var dlg = document.getElementById('ccpa-optout-dialog');
  var closeBtn = document.getElementById('ccpa-close-dialog-btn');
  var optOutBtn = document.getElementById('ccpa-confirm-optout-btn');
  var statusBanner = document.getElementById('ccpa-gpc-status-banner');
  if (navigator.globalPrivacyControl === true && statusBanner) {
    statusBanner.textContent = 'Global Privacy Control (GPC) signal detected — sale/sharing ad pixels are automatically disabled for your browser.';
  }
  if (!link || !dlg) return;
  link.addEventListener('click', function (e) { e.preventDefault(); dlg.showModal(); });
  closeBtn.addEventListener('click', function () { dlg.close(); });
  optOutBtn.addEventListener('click', function () {
    localStorage.setItem('cipa_vppa_consent_v1', JSON.stringify({ gpc: true, optedOut: true, categories: [], updatedAt: new Date().toISOString() }));
    statusBanner.textContent = 'Your opt-out preference has been saved and ad-sharing tags are disabled.';
  });
})();
</script>`;

  const hipaaSensitiveFormScrubbingGuidance = sensitiveFormPixel.sensitiveFormPixelLeakFound
    ? `CRITICAL HEALTHCARE / INTAKE ACTION (${domain}): Remove [${sensitiveFormPixel.ungatedTrackersOnFormPages.join(', ')}] immediately from ${sensitiveFormPixel.sensitiveFormPages.join(', ')}. Under HIPAA (45 CFR §§ 164.502(e), 164.508 post-AHA v. Becerra — generic CMP cookie banners do NOT constitute valid written HIPAA authorizations), Washington My Health My Data Act (RCW 19.373), and FTC Health Breach orders, appointment/patient/symptom intake pages must never transmit URL paths, query strings, IP addresses, or form field events directly to non-BAA ad networks or session-replay clouds. Isolate booking forms on a tracker-free route or subdomain and route aggregate conversion counts exclusively through a BAA-covered server-side gateway with strict PHI/health-attribute stripping.`
    : null;

  return {
    sitePlatform,
    siteVertical,
    detectedCmp,
    priorConsentScriptGateHtmlJs,
    preChatCipaDisclosureWidgetHtmlJs,
    wellKnownGpcJson,
    ccpaPrivacyChoicesFooterHtmlJs,
    hipaaSensitiveFormScrubbingGuidance,
    regulatoryCoverageSummary: US_WIRETAP_VPPA_HIPAA_STATUTORY_SUMMARY,
    implementationNotes: [
      'Host `wellKnownGpcJson` at `https://' +
        domain +
        '/.well-known/gpc.json` with `Content-Type: application/json` and verify `navigator.globalPrivacyControl === true` suppresses all marketing/sharing pixels on initial load.',
      'Ensure third-party live-chat and AI chatbot scripts (`Intercom`, `Drift`, `Zendesk`, `Gorgias`, `Tidio`, `Ada`, `Qualified`) do NOT open WebSocket/XHR connections until the visitor checks the Pre-Chat CIPA Recording Consent Gate (`CIPA Cal. Penal Code §§ 631 & 632` remain untouched as an active private litigation trigger after CA SB 690 narrows § 638.51 pen-register suits).',
      'On pages embedding `YouTube`, `Vimeo`, `Wistia`, `JW Player`, `Mux`, `Brightcove`, `Vidyard`, or `<video>`, block ad-tech identity pixels (`Meta Pixel`, `TikTok`, `LinkedIn`, `Snap`) unless standalone VPPA consent (`18 U.S.C. § 2710(b)(2)(B)`) is recorded.',
      'Have qualified US privacy counsel review your Privacy Notice, CMP configuration, and HIPAA / WA MHMDA data-flow boundaries.',
    ],
  };
}

export function buildRecommendedNextActors(domain: string): RecommendedNextActor[] {
  return [
    {
      actorSlug: 'healthy_addax/wcag-eaa-ada-auditor',
      actorUrl: 'https://apify.com/healthy_addax/wcag-eaa-ada-auditor',
      mcpEndpointUrl: 'https://mcp.apify.com/?tools=healthy_addax/wcag-eaa-ada-auditor',
      reason: `Pair your CIPA/VPPA/HIPAA tracker check on ${domain} with a headless Chromium ADA Title III / WCAG 2.2 Level AA & Accessibility Overlay (accessiBe/UserWay) audit with red-box visual screenshot proof.`,
    },
    {
      actorSlug: 'healthy_addax/eu-withdrawal-omnibus-auditor',
      actorUrl: 'https://apify.com/healthy_addax/eu-withdrawal-omnibus-auditor',
      mcpEndpointUrl: 'https://mcp.apify.com/?tools=healthy_addax/eu-withdrawal-omnibus-auditor',
      reason: `If ${domain} serves UK/EU visitors, audit it via fast HTTP for the mandatory EU 2-Step Electronic Withdrawal Button (Directive 2023/2673 Art. 11a / BGB § 356a), abolished EU ODR links, EmpCo green claims, and Omnibus 30-day pricing.`,
    },
    {
      actorSlug: 'healthy_addax/us-click-to-cancel-auditor',
      actorUrl: 'https://apify.com/healthy_addax/us-click-to-cancel-auditor',
      mcpEndpointUrl: 'https://mcp.apify.com/?tools=healthy_addax/us-click-to-cancel-auditor',
      reason: `If ${domain} offers subscriptions, memberships, or recurring patient/wellness plans, audit it for US Click-to-Cancel & Auto-Renewal Laws (CA AB 2863, NY/NYC Oct 2026 Rule, CO SB 25-145 B2B SaaS, ROSCA & CA SB 478 drip fees).`,
    },
  ];
}
