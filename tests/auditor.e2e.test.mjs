import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { promisify } from 'node:util';
import zlib from 'node:zlib';

const execFileAsync = promisify(execFile);

import { ApifyRuntimeAdapter } from '../dist/apifyRuntime.js';
import { coerceUrlCandidate, normalizeAuditInput, runBatchAudit } from '../dist/auditor.js';
import { DEFAULT_MAX_RESPONSE_BYTES, fetchSafeHttp } from '../dist/httpClient.js';
import { startStandbyServer } from '../dist/server.js';
import { classifyIpAddress, validateUrlAgainstSsrf } from '../dist/ssrf.js';
import { LEGAL_DISCLAIMER } from '../dist/types.js';

const NON_COMPLIANT_CLINIC_STORE_HOME_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>RadiantHealth Dermatology &amp; Skincare Clinic — Book Online</title>
  <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
  <script>
    fbq('init', '9988776655');
    fbq('track', 'PageView');
  </script>
  <script src="https://www.clarity.ms/tag/radiant_clarity_123"></script>
  <script src="https://widget.intercom.io/widget/radiant_intercom_abc"></script>
</head>
<body>
  <header>
    <nav>
      <a href="/appointment">Book Patient Appointment</a>
      <a href="/privacy">Privacy Policy</a>
    </nav>
  </header>
  <main>
    <h1>Medical Dermatology, Telehealth Consultations &amp; Clinical Skincare</h1>
    <p>Watch Dr. Carter explain our acne &amp; rosacea treatment protocol:</p>
    <iframe width="560" height="315" src="https://www.youtube.com/embed/dQw4w9WgXcQ" title="Treatment Overview"></iframe>
    <p><a href="/appointment">Schedule Your Dermatology Intake Visit</a></p>
  </main>
  <footer>
    <a href="/privacy">Privacy Policy</a>
  </footer>
</body>
</html>`;

const NON_COMPLIANT_CLINIC_APPOINTMENT_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Patient Appointment &amp; Symptom Intake — RadiantHealth Clinic</title>
  <script src="https://connect.facebook.net/en_US/fbevents.js"></script>
  <script src="https://www.clarity.ms/tag/radiant_clarity_123"></script>
</head>
<body>
  <h1>Schedule Your Patient Consultation</h1>
  <form id="patient-intake-form" action="/api/book" method="post">
    <label for="patient_name">Patient Full Name</label>
    <input id="patient_name" name="patient_name" type="text" required />
    <label for="dob">Date of Birth</label>
    <input id="dob" name="date_of_birth" type="date" required />
    <label for="symptom_notes">Primary Symptoms or Diagnosis</label>
    <textarea id="symptom_notes" name="symptoms" placeholder="Describe your symptoms or condition"></textarea>
    <label for="ins_plan">Health Insurance Provider</label>
    <input id="ins_plan" name="insurance_provider" type="text" />
    <button type="submit">Request Telehealth Appointment</button>
  </form>
</body>
</html>`;

const NON_COMPLIANT_PRIVACY_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Privacy Policy — RadiantHealth Clinic</title></head>
<body>
  <h1>Privacy Policy</h1>
  <p>We collect standard website analytics and cookies to improve our services.</p>
</body>
</html>`;

const COMPLIANT_ONETRUST_HOME_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Vanguard Modern Commerce — Privacy-First Storefront</title>
  <script src="https://cdn.cookielaw.org/scripttemplates/otSDKStub.js" data-domain-script="018f-test"></script>
  <!-- Properly OneTrust consent-gated Meta Pixel, Clarity & Intercom SDKs -->
  <script type="text/plain" class="optanon-category-C0004" src="https://connect.facebook.net/en_US/fbevents.js"></script>
  <script type="text/plain" class="optanon-category-C0002" src="https://www.clarity.ms/tag/gated_clarity_999"></script>
  <script type="text/plain" class="optanon-category-C0003" src="https://widget.intercom.io/widget/gated_intercom_999"></script>
</head>
<body>
  <header>
    <nav>
      <a href="/privacy">Privacy Policy</a>
      <a href="/privacy-choices">Your Privacy Choices</a>
    </nav>
  </header>
  <main>
    <h1>Precision Everyday Gear</h1>
    <!-- Decorative silent ambient background video loop must NOT trigger false VPPA risk -->
    <video autoplay muted loop playsinline src="/hero-loop.mp4"></video>
    <!-- Self-closed non-video widget iframe before YouTube must NOT swallow subsequent iframes -->
    <iframe src="/status-badge" title="Store Status" />
    <iframe width="560" height="315" src="https://www.youtube-nocookie.com/embed/abc123xyz" title="Product Walkthrough"></iframe>
    <div id="prechat-consent-box">
      <label for="prechat_cipa_ok">
        <input type="checkbox" id="prechat_cipa_ok" name="prechat_cipa_consent" />
        By starting a live chat, you consent to real-time chat recording and third-party chat vendor processing under our Privacy Policy.
      </label>
    </div>
  </main>
  <footer>
    <a href="/privacy">Privacy Policy</a> |
    <a href="/privacy-choices">Your Privacy Choices (Do Not Sell or Share My Personal Information)</a>
  </footer>
</body>
</html>`;

const COMPLIANT_ONETRUST_PRIVACY_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Privacy Policy — Vanguard Modern Commerce</title></head>
<body>
  <h1>Privacy Notice</h1>
  <p>Global Privacy Control (GPC) signals are honored automatically via /.well-known/gpc.json. Chat conversations may be recorded and processed by our third-party chat service provider only after express opt-in consent.</p>
</body>
</html>`;

const CLEAN_BROCHURE_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Granite Peak Structural Engineering PLLC</title></head>
<body>
  <main>
    <h1>Commercial &amp; Municipal Structural Engineering</h1>
    <p>Independent structural engineering consultancy serving Colorado and Wyoming since 2004.</p>
  </main>
  <footer><a href="/privacy">Privacy Policy</a></footer>
</body>
</html>`;

function listenLocalServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      res.setHeader('Connection', 'close');
      handler(req, res);
    });
    srv.listen(0, '127.0.0.1', () => {
      const addr = srv.address();
      resolve({
        server: srv,
        baseUrl: `http://127.0.0.1:${addr.port}`,
        close: () =>
          new Promise((r) => {
            srv.close(() => r());
            srv.closeAllConnections?.();
          }),
      });
    });
  });
}

describe('CIPA Wiretap, VPPA Video Pixel & HIPAA Tracker Auditor — Full Offline E2E Suite', () => {
  const servers = [];
  let nonCompliantClinicUrl = '';
  let compliantOneTrustUrl = '';
  let cleanBrochureUrl = '';
  let robotsBlockedUrl = '';
  let tempStorageDir = '';
  let previousStorageEnv;

  before(async () => {
    process.env.ALLOW_LOCALHOST_FOR_TESTS = '1';
    previousStorageEnv = process.env.APIFY_LOCAL_STORAGE_DIR;
    tempStorageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cipa-vppa-auditor-e2e-'));
    process.env.APIFY_LOCAL_STORAGE_DIR = tempStorageDir;

    // 1. Non-compliant store/clinic (gzip homepage + /appointment intake form + /privacy + missing gpc.json + /brochure.pdf + /redirect-imds + /oversized)
    const badSrv = await listenLocalServer((req, res) => {
      const urlPath = (req.url || '/').split('?')[0];
      if (urlPath === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('User-agent: *\nAllow: /\n');
        return;
      }
      if (urlPath === '/') {
        const gz = zlib.gzipSync(Buffer.from(NON_COMPLIANT_CLINIC_STORE_HOME_HTML, 'utf8'));
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Encoding': 'gzip',
        });
        res.end(gz);
        return;
      }
      if (urlPath === '/appointment') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(NON_COMPLIANT_CLINIC_APPOINTMENT_HTML);
        return;
      }
      if (urlPath === '/privacy') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(NON_COMPLIANT_PRIVACY_HTML);
        return;
      }
      if (urlPath === '/.well-known/gpc.json') {
        res.writeHead(404, { 'Content-Type': 'text/plain' });
        res.end('Not found');
        return;
      }
      if (urlPath === '/brochure.pdf') {
        res.writeHead(200, { 'Content-Type': 'application/pdf' });
        res.end(Buffer.from('%PDF-1.4 binary mock payload'));
        return;
      }
      if (urlPath === '/redirect-imds') {
        res.writeHead(302, { Location: 'http://169.254.169.254/latest/meta-data/' });
        res.end();
        return;
      }
      if (urlPath === '/oversized') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end('<html><body>' + 'A'.repeat(3.1 * 1024 * 1024) + '</body></html>');
        return;
      }
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not found');
    });
    servers.push(badSrv);
    nonCompliantClinicUrl = badSrv.baseUrl;

    // 2. Compliant OneTrust-gated site with /.well-known/gpc.json ({"gpc": true}), "Your Privacy Choices", and pre-chat consent
    const okSrv = await listenLocalServer((req, res) => {
      const urlPath = (req.url || '/').split('?')[0];
      if (urlPath === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('User-agent: *\nAllow: /\n');
        return;
      }
      if (urlPath === '/') {
        const br = zlib.brotliCompressSync(Buffer.from(COMPLIANT_ONETRUST_HOME_HTML, 'utf8'));
        res.writeHead(200, {
          'Content-Type': 'text/html; charset=utf-8',
          'Content-Encoding': 'br',
        });
        res.end(br);
        return;
      }
      if (urlPath === '/privacy' || urlPath === '/privacy-choices') {
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
        res.end(COMPLIANT_ONETRUST_PRIVACY_HTML);
        return;
      }
      if (urlPath === '/.well-known/gpc.json') {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ gpc: true, lastUpdate: '2026-11-01' }));
        return;
      }
      res.writeHead(404);
      res.end();
    });
    servers.push(okSrv);
    compliantOneTrustUrl = okSrv.baseUrl;

    // 3. Clean brochure site with zero trackers, chat, or video
    const brochureSrv = await listenLocalServer((req, res) => {
      const urlPath = (req.url || '/').split('?')[0];
      if (urlPath === '/.well-known/gpc.json') {
        res.writeHead(404);
        res.end();
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(CLEAN_BROCHURE_HTML);
    });
    servers.push(brochureSrv);
    cleanBrochureUrl = brochureSrv.baseUrl;

    // 4. robots.txt Disallow: / site
    const robotsSrv = await listenLocalServer((req, res) => {
      const urlPath = (req.url || '/').split('?')[0];
      if (urlPath === '/robots.txt') {
        res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('User-agent: *\nDisallow: /\n');
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end('<html><body>Blocked</body></html>');
    });
    servers.push(robotsSrv);
    robotsBlockedUrl = robotsSrv.baseUrl;
  });

  after(async () => {
    for (const s of servers) {
      await s.close();
    }
    if (previousStorageEnv === undefined) {
      delete process.env.APIFY_LOCAL_STORAGE_DIR;
    } else {
      process.env.APIFY_LOCAL_STORAGE_DIR = previousStorageEnv;
    }
    if (tempStorageDir) {
      fs.rmSync(tempStorageDir, { recursive: true, force: true });
    }
  });

  it('1. Bare domain normalization & SSRF / Anti-DNS-Rebinding guard block IMDS, RFC1918, IPv6 mapped, and enforce 2MB cap', async () => {
    assert.equal(coerceUrlCandidate('clinic.example.com'), 'https://clinic.example.com');
    assert.equal(
      coerceUrlCandidate('https://clinic.example.com/appointment'),
      'https://clinic.example.com/appointment',
    );
    assert.equal(coerceUrlCandidate('file:///etc/passwd'), 'file:///etc/passwd');

    for (const blockedTarget of [
      'http://169.254.169.254/latest/meta-data/',
      'http://10.0.0.1/admin',
      'http://192.168.1.1/',
      'http://172.16.5.4/',
      'http://[::ffff:169.254.169.254]/latest/meta-data/',
      'http://[0:0:0:0:0:ffff:169.254.169.254]/',
      'http://metadata.google.internal/computeMetadata/v1/',
      'http://127.0.0.1:8080/',
      'http://localhost:3000/',
      'http://[::1]:4321/',
      'file:///etc/passwd',
    ]) {
      const check = await validateUrlAgainstSsrf(blockedTarget, { allowLocalhost: false });
      assert.equal(check.allowed, false, `Expected SSRF guard to block ${blockedTarget}`);
    }

    assert.equal(classifyIpAddress('93.184.216.34', false).allowed, true);
    assert.equal(classifyIpAddress('2606:4700:4700::1111', false).allowed, true);

    const rebind = await validateUrlAgainstSsrf('https://evil-rebind.example.com', {
      allowLocalhost: false,
      dnsLookup: async () => [
        { address: '93.184.216.34', family: 4 },
        { address: '169.254.169.254', family: 4 },
      ],
    });
    assert.equal(rebind.allowed, false);

    const oversized = await fetchSafeHttp(`${nonCompliantClinicUrl}/oversized`, {
      allowLocalhost: true,
    });
    assert.equal(oversized.ok, true);
    assert.equal(oversized.truncated, true);
    assert.equal(oversized.byteLength, DEFAULT_MAX_RESPONSE_BYTES);
  });

  it('2. Non-compliant store/clinic (ungated Meta Pixel + Clarity + Intercom + YouTube + /appointment patient intake + missing gpc.json & "Your Privacy Choices"): flags CIPA §§ 631/632, VPPA, HIPAA/MHMDA & GPC/Opt-Out, generates remediation pack, and bills exact PPE ($0.03)', async () => {
    const runtime = new ApifyRuntimeAdapter();
    const res = await runBatchAudit(
      {
        urls: [nonCompliantClinicUrl],
        includeRemediationPack: true,
        maxLegalPagesPerDomain: 3,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );

    assert.equal(res.items.length, 1);
    const item = res.items[0];
    assert.equal(item.status, 'audited');
    assert.equal(item.siteVertical, 'healthcare_or_wellness');
    assert.equal(item.detectedCmp, 'none');
    assert.ok(item.pagesFetchedCount >= 3, 'Should inspect homepage + /appointment + /privacy');

    assert.deepEqual(item.ungatedSessionReplayVendors, ['microsoft-clarity']);
    assert.deepEqual(item.ungatedChatWidgetVendors, ['intercom']);
    assert.equal(item.preChatRecordingDisclosureFound, false);
    assert.equal(item.wiretapRiskFound, true);

    assert.ok(item.embeddedVideoProviders.includes('youtube'));
    assert.ok(item.ungatedAdPixelVendors.includes('meta-pixel'));
    assert.equal(item.vppaRiskFound, true);

    assert.equal(item.sensitiveIntakeFormFound, true);
    assert.equal(item.sensitiveFormPixelLeakFound, true);

    assert.equal(item.gpcWellKnownFound, false);
    assert.equal(item.gpcSupportDeclared, false);
    assert.equal(item.ccpaPrivacyChoicesLinkFound, false);
    assert.equal(item.gpcOrOptOutRiskFound, true);

    const ruleIds = item.findings.map((f) => f.ruleId);
    assert.ok(ruleIds.includes('US-CIPA-631-632-UNGATED-SESSION-REPLAY'));
    assert.ok(ruleIds.includes('US-CIPA-631-632-UNGATED-THIRD-PARTY-CHAT'));
    assert.ok(ruleIds.includes('US-CIPA-631-632-MISSING-CHAT-RECORDING-DISCLOSURE'));
    assert.ok(ruleIds.includes('US-VPPA-2710-VIDEO-AD-PIXEL-CO-PRESENCE'));
    assert.ok(ruleIds.includes('US-HIPAA-MHMDA-SENSITIVE-INTAKE-PIXEL-LEAK'));
    assert.ok(ruleIds.includes('US-CCPA-1798-135-MISSING-PRIVACY-CHOICES-OPT-OUT'));
    assert.ok(ruleIds.includes('US-CCPA-CPRA-GPC-SIGNAL-UNDECLARED'));

    assert.equal(item.complianceScore, 0);
    assert.equal(item.riskTier, 'CRITICAL');

    // Outreach hook, HTML/JS remediation pack & ALL THREE sister Actors cross-linked
    assert.match(item.coldOutreachHook, /Meta Pixel|Microsoft Clarity/i);
    assert.equal(item.remediationPackGenerated, true);
    assert.ok(item.remediationPack);
    assert.match(item.remediationPack.priorConsentScriptGateHtmlJs, /data-cipa-consent-category/);
    assert.match(item.remediationPack.preChatCipaDisclosureWidgetHtmlJs, /Intercom/);
    assert.doesNotMatch(
      item.remediationPack.priorConsentScriptGateHtmlJs,
      /<input[^>]*\bchecked\b/i,
    );
    assert.doesNotMatch(
      item.remediationPack.preChatCipaDisclosureWidgetHtmlJs,
      /<input[^>]*\bchecked\b/i,
    );
    assert.equal(JSON.parse(item.remediationPack.wellKnownGpcJson).gpc, true);
    assert.match(item.remediationPack.ccpaPrivacyChoicesFooterHtmlJs, /Your Privacy Choices/);
    assert.ok(item.remediationPack.hipaaSensitiveFormScrubbingGuidance);
    assert.match(item.remediationPack.regulatoryCoverageSummary, /SB 690/);

    const nextSlugs = item.recommendedNextActors.map((a) => a.actorSlug);
    assert.deepEqual(nextSlugs, [
      'healthy_addax/wcag-eaa-ada-auditor',
      'healthy_addax/eu-withdrawal-omnibus-auditor',
      'healthy_addax/us-click-to-cancel-auditor',
    ]);
    assert.equal(item.disclaimer, LEGAL_DISCLAIMER);

    // Exact PPE billing: $0.005 + $0.015 + $0.01 = $0.03
    assert.equal(res.billing.chargedCounts['actor-start'], 1);
    assert.equal(res.billing.chargedCounts['url-audited'], 1);
    assert.equal(res.billing.chargedCounts['remediation-pack-generated'], 1);
    assert.equal(res.billing.estimatedTotalUsd, 0.03);
  });

  it('3. Compliant site with OneTrust script gating (type="text/plain" class="optanon-category-C0004"), /.well-known/gpc.json ({"gpc": true}), "Your Privacy Choices" link, and pre-chat recording consent -> complianceScore 100, LOW risk, $0 remediation charge', async () => {
    const runtime = new ApifyRuntimeAdapter();
    const res = await runBatchAudit(
      {
        urls: [compliantOneTrustUrl],
        includeRemediationPack: true,
        maxLegalPagesPerDomain: 3,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );

    assert.equal(res.items.length, 1);
    const okItem = res.items[0];
    assert.equal(okItem.status, 'audited');
    assert.equal(okItem.detectedCmp, 'onetrust');
    assert.deepEqual(okItem.sessionReplayVendors, ['microsoft-clarity']);
    assert.deepEqual(okItem.ungatedSessionReplayVendors, []);
    assert.deepEqual(okItem.chatWidgetVendors, ['intercom']);
    assert.deepEqual(okItem.ungatedChatWidgetVendors, []);
    assert.equal(okItem.preChatRecordingDisclosureFound, true);
    assert.equal(okItem.wiretapRiskFound, false);

    assert.deepEqual(okItem.adPixelVendors, ['meta-pixel']);
    assert.deepEqual(okItem.ungatedAdPixelVendors, []);
    // Self-closed iframe before YouTube must NOT swallow youtube-nocookie, and decorative <video autoplay muted loop> must be ignored
    assert.deepEqual(okItem.embeddedVideoProviders, ['youtube-nocookie']);
    assert.equal(okItem.vppaRiskFound, false);

    assert.equal(okItem.gpcWellKnownFound, true);
    assert.equal(okItem.gpcSupportDeclared, true);
    assert.equal(okItem.ccpaPrivacyChoicesLinkFound, true);
    assert.equal(okItem.gpcOrOptOutRiskFound, false);

    assert.equal(okItem.complianceScore, 100);
    assert.equal(okItem.riskTier, 'LOW');
    assert.equal(okItem.findingsCount, 0);
    assert.equal(okItem.remediationPackGenerated, false);
    assert.equal(res.billing.chargedCounts['remediation-pack-generated'], 0);

    // Verify linear O(N) robots.txt wildcard matching never backtracks exponentially on hostile patterns
    const { parseRobotsTxt, evaluateRobotsRules } = await import('../dist/robots.js');
    const hostileRobots = parseRobotsTxt('User-agent: *\nDisallow: /*a*a*a*a*a*a*a*a*a*a*a*a*a*a*b$\n');
    const t0 = Date.now();
    const robEval = evaluateRobotsRules('/' + 'a'.repeat(120) + 'c', hostileRobots.rules);
    assert.equal(robEval.allowed, true);
    assert.ok(Date.now() - t0 < 50, 'Hostile wildcard robots.txt must evaluate in <50ms');
  });

  it('4. Clean brochure site with zero trackers, chat, or video -> complianceScore 100, LOW risk, $0 remediation charge', async () => {
    const runtime = new ApifyRuntimeAdapter();
    const res = await runBatchAudit(
      {
        urls: [cleanBrochureUrl],
        includeRemediationPack: true,
        maxLegalPagesPerDomain: 3,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );

    assert.equal(res.items.length, 1);
    const clean = res.items[0];
    assert.equal(clean.status, 'audited');
    assert.deepEqual(clean.sessionReplayVendors, []);
    assert.deepEqual(clean.chatWidgetVendors, []);
    assert.deepEqual(clean.adPixelVendors, []);
    assert.deepEqual(clean.embeddedVideoProviders, []);
    assert.equal(clean.wiretapRiskFound, false);
    assert.equal(clean.vppaRiskFound, false);
    assert.equal(clean.sensitiveFormPixelLeakFound, false);
    assert.equal(clean.gpcOrOptOutRiskFound, false);
    assert.equal(clean.complianceScore, 100);
    assert.equal(clean.riskTier, 'LOW');
    assert.equal(clean.findingsCount, 0);
    assert.equal(clean.remediationPackGenerated, false);
    assert.equal(res.billing.chargedCounts['remediation-pack-generated'], 0);
  });

  it('5. robots.txt disallow, binary Content-Type (application/pdf), and SSRF / 302 IMDS redirect -> $0 url-audited charge', async () => {
    const runtime = new ApifyRuntimeAdapter();
    const res = await runBatchAudit(
      {
        urls: [
          robotsBlockedUrl,
          `${nonCompliantClinicUrl}/brochure.pdf`,
          'http://169.254.169.254/latest/meta-data/',
          `${nonCompliantClinicUrl}/redirect-imds`,
        ],
        respectRobotsTxt: true,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );

    assert.equal(res.items.length, 4);
    assert.equal(res.items[0].status, 'blocked_robots');
    assert.equal(res.items[1].status, 'error');
    assert.match(res.items[1].errorMessage || '', /application\/pdf/i);
    assert.equal(res.items[2].status, 'blocked_ssrf');
    assert.equal(res.items[3].status, 'blocked_ssrf');

    assert.equal(res.billing.chargedCounts['url-audited'], 0);
    assert.equal(res.billing.chargedCounts['remediation-pack-generated'], 0);
  });

  it('6. datasetId chaining, path-traversal ("..") rejection, maxBudgetUsd cap, and creator $0 run compatibility', async () => {
    const runtime = new ApifyRuntimeAdapter();

    // 6a. Exact $0.03 budget ($0.005 actor-start + $0.015 url-audited + $0.01 remediation-pack = 1 site max)
    const capped = await runBatchAudit(
      {
        urls: [nonCompliantClinicUrl, compliantOneTrustUrl, cleanBrochureUrl],
        includeRemediationPack: true,
        maxBudgetUsd: 0.03,
        maxConcurrency: 1,
        domainDelayMs: 0,
      },
      { runtime, allowLocalhost: true },
    );
    assert.equal(capped.items.length, 1);
    assert.equal(capped.stoppedDueToBudgetCap, true);
    assert.ok(capped.billing.estimatedTotalUsd <= 0.03 + 1e-6);

    // 6b. Creator $0 test run ({ eventChargeLimitReached: false, chargedCount: 0 })
    const creatorRuntime = new ApifyRuntimeAdapter();
    creatorRuntime.sdkCharge = async () => ({ eventChargeLimitReached: false, chargedCount: 0 });
    const creatorRun = await runBatchAudit(
      {
        urls: [nonCompliantClinicUrl, compliantOneTrustUrl],
        includeRemediationPack: true,
        domainDelayMs: 0,
      },
      { runtime: creatorRuntime, allowLocalhost: true },
    );
    assert.equal(creatorRun.items.length, 2);
    assert.equal(creatorRun.stoppedDueToBudgetCap, false);

    // 6c. datasetId chaining from local storage
    const leadsDir = path.join(tempStorageDir, 'datasets', 'clinic-leads');
    fs.mkdirSync(leadsDir, { recursive: true });
    fs.writeFileSync(
      path.join(leadsDir, '000000001.json'),
      JSON.stringify([
        { clinicName: 'Vanguard', clinicUrl: compliantOneTrustUrl },
        { clinicName: 'Duplicate', url: compliantOneTrustUrl },
      ]),
      'utf8',
    );
    const chainedRun = await runBatchAudit(
      { datasetId: 'clinic-leads', domainDelayMs: 0 },
      { runtime, allowLocalhost: true },
    );
    assert.equal(chainedRun.items.length, 1);
    assert.equal(chainedRun.items[0].complianceScore, 100);

    // 6d. datasetId traversal attempts must be strictly rejected
    assert.deepEqual(await runtime.loadUrlsFromDataset('..'), []);
    assert.deepEqual(await runtime.loadUrlsFromDataset('../default'), []);
    assert.deepEqual(await runtime.loadUrlsFromDataset('bad/slash'), []);
  });

  it('7. Standby /health, ACTOR_STANDBY_PORT priority, /scan, and /mcp JSON-RPC 2.0 (audit_cipa_vppa_wiretap_risk) + CLI entrypoint', async () => {
    const probeSrv = await listenLocalServer((_req, res) => res.end());
    const freePort = Number(new URL(probeSrv.baseUrl).port);
    await probeSrv.close();

    const prevStandbyPort = process.env.ACTOR_STANDBY_PORT;
    process.env.ACTOR_STANDBY_PORT = String(freePort);
    let standby;
    try {
      standby = await startStandbyServer({
        host: '127.0.0.1',
        allowLocalhost: true,
      });
      assert.equal(standby.port, freePort, 'Must bind to ACTOR_STANDBY_PORT when set');
    } finally {
      if (prevStandbyPort === undefined) {
        delete process.env.ACTOR_STANDBY_PORT;
      } else {
        process.env.ACTOR_STANDBY_PORT = prevStandbyPort;
      }
    }

    const standbyBase = `http://127.0.0.1:${standby.port}`;

    try {
      // 7a. GET /health with Apify readiness header
      const healthRes = await fetch(`${standbyBase}/health`, {
        headers: { 'x-apify-container-server-readiness-probe': '1' },
      });
      assert.equal(healthRes.status, 200);
      const healthJson = await healthRes.json();
      assert.equal(healthJson.status, 'ok');
      assert.equal(healthJson.service, 'cipa-vppa-wiretap-pixel-auditor');
      assert.equal(healthJson.endpoints.mcp, '/mcp');

      // 7b. MCP initialize + notifications/initialized + tools/list
      const initRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'initialize',
          params: {
            protocolVersion: '2025-03-26',
            capabilities: {},
            clientInfo: { name: 'e2e-mcp-client', version: '1.0.0' },
          },
        }),
      });
      assert.equal(initRes.status, 200);
      const initBody = await initRes.json();
      assert.equal(initBody.result.serverInfo.name, 'cipa-vppa-wiretap-pixel-auditor');

      const notifRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
      });
      assert.equal(notifRes.status, 202);

      const listRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'tools/list' }),
      });
      const listBody = await listRes.json();
      assert.deepEqual(
        listBody.result.tools.map((t) => t.name),
        ['audit_cipa_vppa_wiretap_risk'],
      );

      // 7c. MCP tools/call rejects datasetId-only calls without url/urls
      const missingUrlRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: {
            name: 'audit_cipa_vppa_wiretap_risk',
            arguments: { datasetId: 'clinic-leads' },
          },
        }),
      });
      const missingUrlBody = await missingUrlRes.json();
      assert.equal(missingUrlBody.result.isError, true);

      // 7d. MCP tools/call (audit_cipa_vppa_wiretap_risk) on non-compliant clinic/store
      const callRes = await fetch(`${standbyBase}/mcp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: {
            name: 'audit_cipa_vppa_wiretap_risk',
            arguments: {
              url: nonCompliantClinicUrl,
              includeRemediationPack: true,
              maxLegalPagesPerDomain: 3,
            },
          },
        }),
      });
      assert.equal(callRes.status, 200);
      const callBody = await callRes.json();
      assert.equal(callBody.result.isError, false);
      const report = JSON.parse(callBody.result.content[0].text);
      assert.equal(report.status, 'audited');
      assert.equal(report.wiretapRiskFound, true);
      assert.equal(report.vppaRiskFound, true);
      assert.equal(report.sensitiveFormPixelLeakFound, true);
      assert.equal(report.remediationPackGenerated, true);

      // 7e. CLI Entrypoint (node dist/main.js)
      const cliDir = fs.mkdtempSync(path.join(os.tmpdir(), 'cipa-vppa-cli-test-'));
      try {
        const kvsDefault = path.join(cliDir, 'key_value_stores', 'default');
        fs.mkdirSync(kvsDefault, { recursive: true });
        fs.writeFileSync(
          path.join(kvsDefault, 'INPUT.json'),
          JSON.stringify({
            urls: [compliantOneTrustUrl],
            domainDelayMs: 0,
          }),
          'utf8',
        );

        const { stdout } = await execFileAsync(process.execPath, ['dist/main.js'], {
          cwd: process.cwd(),
          env: {
            ...process.env,
            ALLOW_LOCALHOST_FOR_TESTS: '1',
            APIFY_LOCAL_STORAGE_DIR: cliDir,
          },
          timeout: 15_000,
        });

        assert.match(stdout, /Completed batch audit/);
        const dsFiles = fs
          .readdirSync(path.join(cliDir, 'datasets', 'default'))
          .filter((f) => f.endsWith('.json'));
        assert.equal(dsFiles.length, 1);
      } finally {
        fs.rmSync(cliDir, { recursive: true, force: true });
      }
    } finally {
      await standby.close();
    }
  });

  it('8. .actor/* schemas match WiretapPixelAuditReportItem 100% and strictly satisfy Apify UI character limits (<=58, <=240, <=140)', async () => {
    const actorJson = JSON.parse(fs.readFileSync('.actor/actor.json', 'utf8'));
    const inputSchema = JSON.parse(fs.readFileSync('.actor/input_schema.json', 'utf8'));
    const datasetSchema = JSON.parse(fs.readFileSync('.actor/dataset_schema.json', 'utf8'));
    const ppeJson = JSON.parse(fs.readFileSync('.actor/pay_per_event.json', 'utf8'));

    assert.equal(actorJson.name, 'cipa-vppa-wiretap-pixel-auditor');
    assert.equal(
      actorJson.title,
      'CIPA Wiretap, VPPA Video Pixel & HIPAA Tracker Auditor',
    );
    assert.ok(
      actorJson.title.length <= 58,
      `actor.json title length (${actorJson.title.length}) must be <= 58`,
    );
    assert.ok(
      actorJson.description.length <= 240,
      `actor.json description length (${actorJson.description.length}) must be <= 240`,
    );
    assert.equal(actorJson.minMemoryMbytes, 256);
    assert.equal(actorJson.maxMemoryMbytes, 1024);
    assert.equal(actorJson.usesStandbyMode, true);
    assert.equal(actorJson.webServerMcpPath, '/mcp');

    assert.equal(ppeJson['actor-start'].eventPriceUsd, 0.005);
    assert.equal(ppeJson['url-audited'].eventPriceUsd, 0.015);
    assert.equal(ppeJson['remediation-pack-generated'].eventPriceUsd, 0.01);

    for (const [evKey, evDef] of Object.entries(ppeJson)) {
      assert.ok(
        evDef.eventDescription.length <= 140,
        `PPE "${evKey}" eventDescription (${evDef.eventDescription.length} chars) must be <= 140`,
      );
    }

    const defaults = normalizeAuditInput({});
    for (const [propName, propDef] of Object.entries(inputSchema.properties)) {
      if ('default' in propDef) {
        assert.equal(
          defaults[propName],
          propDef.default,
          `Default mismatch for input property "${propName}"`,
        );
      }
    }

    const runtime = new ApifyRuntimeAdapter();
    const sampleRun = await runBatchAudit(
      { urls: [nonCompliantClinicUrl], domainDelayMs: 0 },
      { runtime, allowLocalhost: true },
    );
    const liveItem = sampleRun.items[0];
    for (const key of Object.keys(datasetSchema.fields.properties)) {
      assert.equal(
        key in liveItem,
        true,
        `Dataset schema property "${key}" must exist on WiretapPixelAuditReportItem`,
      );
    }
    for (const key of Object.keys(liveItem)) {
      assert.equal(
        key in datasetSchema.fields.properties,
        true,
        `WiretapPixelAuditReportItem property "${key}" must be documented in .actor/dataset_schema.json`,
      );
    }
  });
});
