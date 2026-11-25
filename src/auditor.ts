import { ApifyRuntimeAdapter } from './apifyRuntime.js';
import { BillingManager, type BillingSummary } from './billing.js';
import {
  checkSensitiveFormPixels,
  checkVppaVideoPixels,
  checkWiretapChatAndReplay,
  classifySiteAndCmp,
  detectSiteLanguage,
  discoverPrivacyAndSensitiveLinks,
  evaluateGpcAndOptOut,
  selectPriorityInternalSubpages,
  type GpcWellKnownProbe,
  type InspectedPageBundle,
} from './detectors.js';
import { parseHtmlDocument } from './htmlParser.js';
import { DEFAULT_MAX_RESPONSE_BYTES, fetchSafeHttp } from './httpClient.js';
import {
  buildFindingsAndScore,
  buildRecommendedNextActors,
  generateColdOutreachHook,
  generateRemediationPack,
} from './remediation.js';
import { RobotsAndRateGuard } from './robots.js';
import { validateUrlAgainstSsrf, type DnsLookupFn } from './ssrf.js';
import {
  LEGAL_DISCLAIMER,
  PPE_EVENTS,
  type AuditStatus,
  type NormalizedAuditInput,
  type RawActorInput,
  type UrlRequestObject,
  type WiretapPixelAuditReportItem,
} from './types.js';

const MAX_GPC_JSON_BYTES = 64 * 1024;

function clampInt(val: unknown, fallback: number, min: number, max: number): number {
  const num = typeof val === 'number' ? val : Number(val);
  if (Number.isNaN(num) || !Number.isFinite(num)) return fallback;
  return Math.max(min, Math.min(max, Math.floor(num)));
}

/**
 * Normalizes both full URLs (`https://clinic.example.com`) and bare domains
 * (`clinic.example.com` -> `https://clinic.example.com`), while preserving non-HTTP schemes
 * (e.g. `file://`, `ftp://`) so SSRF validation explicitly rejects them.
 */
export function coerceUrlCandidate(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (trimmed.startsWith('//')) {
    return `https:${trimmed}`;
  }
  if (/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(trimmed)) {
    return trimmed;
  }
  if (/^(?:\[[0-9a-fA-F:]+\]|[a-z0-9.-]+\.[a-z]{2,}|localhost)(?::\d+)?(?:[/?#].*)?$/i.test(trimmed)) {
    return `https://${trimmed}`;
  }
  return trimmed;
}

function extractRawUrlStrings(
  rawInput: RawActorInput | null | undefined,
  extraDatasetUrls: string[] = [],
): string[] {
  const collected: string[] = [];

  const appendSingle = (candidate: string) => {
    const coerced = coerceUrlCandidate(candidate);
    if (coerced) collected.push(coerced);
  };

  const appendList = (list?: Array<string | UrlRequestObject>) => {
    if (!Array.isArray(list)) return;
    for (const item of list) {
      if (typeof item === 'string') {
        appendSingle(item);
      } else if (item && typeof item === 'object' && typeof item.url === 'string') {
        appendSingle(item.url);
      }
    }
  };

  if (rawInput) {
    appendList(rawInput.urls);
    appendList(rawInput.startUrls);
    if (typeof rawInput.url === 'string') {
      appendSingle(rawInput.url);
    }
  }

  for (const dsUrl of extraDatasetUrls) {
    appendSingle(dsUrl);
  }

  return Array.from(new Set(collected));
}

export function normalizeAuditInput(
  rawInput: RawActorInput | null | undefined,
  extraDatasetUrls: string[] = [],
  maxUrlsHardCap = 5000,
): NormalizedAuditInput {
  const input = rawInput ?? {};
  const maxUrls = clampInt(input.maxUrls, 100, 1, maxUrlsHardCap);
  const dedupedUrls = extractRawUrlStrings(input, extraDatasetUrls).slice(0, maxUrls);

  const rawBudget = input.maxBudgetUsd ?? input.maxTotalChargeUsd;
  const parsedBudget =
    typeof rawBudget === 'number' && !Number.isNaN(rawBudget) && rawBudget >= 0
      ? rawBudget
      : undefined;

  return {
    urls: dedupedUrls,
    datasetId:
      typeof input.datasetId === 'string' && input.datasetId.trim()
        ? input.datasetId.trim()
        : undefined,
    datasetUrlField:
      typeof input.datasetUrlField === 'string' && input.datasetUrlField.trim()
        ? input.datasetUrlField.trim()
        : undefined,
    maxLegalPagesPerDomain: clampInt(input.maxLegalPagesPerDomain, 3, 0, 5),
    includeRemediationPack: input.includeRemediationPack ?? true,
    checkWiretapChatAndReplay: input.checkWiretapChatAndReplay ?? true,
    checkVppaVideoPixels: input.checkVppaVideoPixels ?? true,
    checkSensitiveIntakePixels: input.checkSensitiveIntakePixels ?? true,
    checkGpcAndOptOut: input.checkGpcAndOptOut ?? true,
    respectRobotsTxt: input.respectRobotsTxt ?? true,
    maxUrls,
    maxConcurrency: clampInt(input.maxConcurrency, 5, 1, 20),
    domainDelayMs: clampInt(input.domainDelayMs, 300, 0, 30_000),
    requestTimeoutMs: clampInt(input.requestTimeoutMs, 12_000, 2_000, 60_000),
    maxBudgetUsd: parsedBudget,
  };
}

function safeExtractHostname(rawUrl: string): string {
  try {
    return new URL(rawUrl).hostname.toLowerCase();
  } catch {
    return 'invalid-host';
  }
}

function isBinaryContentType(contentType: string): boolean {
  const lowerCt = (contentType || '').toLowerCase();
  return (
    /^(?:image|video|audio|font)\//.test(lowerCt) ||
    /\bapplication\/(?:pdf|zip|x-gzip|gzip|octet-stream|msword|vnd\.)\b/.test(lowerCt)
  );
}

function buildBlockedOrErrorItem(params: {
  rawUrl: string;
  normalizedInputUrl: string;
  status: Exclude<AuditStatus, 'audited'>;
  httpStatus?: number | null;
  reason: string;
  loadTimeMs: number;
}): WiretapPixelAuditReportItem {
  const domain = safeExtractHostname(params.normalizedInputUrl || params.rawUrl);
  return {
    url: params.rawUrl,
    normalizedInputUrl: params.normalizedInputUrl,
    finalUrl: null,
    domain,
    auditedAt: new Date().toISOString(),
    status: params.status,
    httpStatus: params.httpStatus ?? null,
    pageTitle: null,
    detectedLanguage: null,
    sitePlatform: 'custom',
    siteVertical: 'general_business',
    detectedCmp: 'none',
    consentModeV2Detected: false,
    loadTimeMs: params.loadTimeMs,
    pagesFetchedCount: 0,
    pagesFetched: [],
    errorMessage: params.reason,
    complianceScore: 0,
    riskTier: 'LOW',
    sessionReplayVendors: [],
    ungatedSessionReplayVendors: [],
    chatWidgetVendors: [],
    ungatedChatWidgetVendors: [],
    preChatRecordingDisclosureFound: false,
    wiretapRiskFound: false,
    wiretapChatAndReplayCheck: {
      checked: false,
      detectedCmp: 'none',
      consentModeV2Detected: false,
      sessionReplayVendors: [],
      ungatedSessionReplayVendors: [],
      gatedSessionReplayVendors: [],
      chatWidgetVendors: [],
      ungatedChatWidgetVendors: [],
      gatedChatWidgetVendors: [],
      preChatRecordingDisclosureFound: false,
      recordingDisclosureSignals: [],
      wiretapEvidence: [],
      foundOnPages: [],
    },
    embeddedVideoProviders: [],
    adPixelVendors: [],
    ungatedAdPixelVendors: [],
    vppaRiskFound: false,
    vppaVideoPixelCheck: {
      checked: false,
      embeddedVideoProviders: [],
      ungatedVideoProviders: [],
      adPixelVendors: [],
      ungatedAdPixelVendors: [],
      gatedAdPixelVendors: [],
      standaloneVideoConsentFound: false,
      coPresentOnSamePage: false,
      vppaRiskFound: false,
      vppaEvidence: [],
      foundOnPages: [],
    },
    sensitiveIntakeFormFound: false,
    sensitiveFormPixelLeakFound: false,
    sensitiveFormPixelCheck: {
      checked: false,
      healthcareOrWellnessContext: false,
      sensitiveIntakeFormFound: false,
      sensitiveFormPages: [],
      matchedSensitiveFields: [],
      ungatedTrackersOnFormPages: [],
      sensitiveFormPixelLeakFound: false,
      evidence: [],
    },
    gpcWellKnownFound: false,
    gpcSupportDeclared: false,
    ccpaPrivacyChoicesLinkFound: false,
    gpcOrOptOutRiskFound: false,
    gpcAndOptOutCheck: {
      checked: false,
      adTrackersPresent: false,
      gpcEndpointUrl: null,
      gpcHttpStatus: null,
      gpcWellKnownFound: false,
      gpcSupportDeclared: false,
      clientGpcListenerDetected: false,
      ccpaPrivacyChoicesLinkFound: false,
      optOutLinkLabel: null,
      optOutUrl: null,
      gpcOrOptOutRiskFound: false,
      evidence: [],
    },
    privacyPolicyUrl: null,
    intakeOrBookingUrl: null,
    videoPageUrl: null,
    optOutUrl: null,
    discoveredLinks: {
      privacyPolicyUrl: null,
      intakeOrBookingUrl: null,
      videoPageUrl: null,
      optOutUrl: null,
      contactUrl: null,
    },
    findingsCount: 0,
    findings: [],
    coldOutreachHook: '',
    remediationPackGenerated: false,
    remediationPack: null,
    recommendedNextActors: buildRecommendedNextActors(domain),
    disclaimer: LEGAL_DISCLAIMER,
  };
}

async function probeWellKnownGpcJson(params: {
  homeFinalUrl: string;
  respectRobotsTxt: boolean;
  effectiveDelayMs: number;
  requestTimeoutMs: number;
  robotsGuard: RobotsAndRateGuard;
  allowLocalhost?: boolean;
  dnsLookup?: DnsLookupFn;
}): Promise<GpcWellKnownProbe> {
  let gpcUrl: string;
  let host: string;
  try {
    const parsed = new URL(params.homeFinalUrl);
    gpcUrl = `${parsed.origin}/.well-known/gpc.json`;
    host = parsed.hostname.toLowerCase();
  } catch {
    return {
      probed: false,
      endpointUrl: null,
      httpStatus: null,
      wellKnownFound: false,
      gpcSupportDeclared: false,
    };
  }

  if (params.respectRobotsTxt) {
    const rob = await params.robotsGuard.checkUrlAllowed(gpcUrl, {
      allowLocalhost: params.allowLocalhost,
      dnsLookup: params.dnsLookup,
    });
    if (!rob.allowed) {
      return {
        probed: false,
        endpointUrl: gpcUrl,
        httpStatus: null,
        wellKnownFound: false,
        gpcSupportDeclared: false,
      };
    }
  }

  await params.robotsGuard.waitForDomainSlot(host, params.effectiveDelayMs);

  const res = await fetchSafeHttp(gpcUrl, {
    maxBytes: MAX_GPC_JSON_BYTES,
    timeoutMs: Math.min(params.requestTimeoutMs, 6_000),
    maxRedirects: 3,
    acceptHeader: 'application/json,text/plain;q=0.8,*/*;q=0.5',
    allowLocalhost: params.allowLocalhost,
    dnsLookup: params.dnsLookup,
    checkRedirectAllowed: params.respectRobotsTxt
      ? async (redirectUrl) => {
          const r = await params.robotsGuard.checkUrlAllowed(redirectUrl, {
            allowLocalhost: params.allowLocalhost,
            dnsLookup: params.dnsLookup,
          });
          return {
            allowed: r.allowed,
            reason: r.allowed ? undefined : 'Disallowed by robots.txt',
          };
        }
      : undefined,
  });

  if (!res.ok || res.statusCode !== 200 || !res.bodyText.trim()) {
    return {
      probed: true,
      endpointUrl: gpcUrl,
      httpStatus: res.statusCode,
      wellKnownFound: false,
      gpcSupportDeclared: false,
    };
  }

  try {
    const parsedJson = JSON.parse(res.bodyText) as unknown;
    if (parsedJson && typeof parsedJson === 'object' && !Array.isArray(parsedJson)) {
      const gpcFlag = (parsedJson as Record<string, unknown>).gpc === true;
      return {
        probed: true,
        endpointUrl: gpcUrl,
        httpStatus: 200,
        wellKnownFound: true,
        gpcSupportDeclared: gpcFlag,
      };
    }
  } catch {
    // Non-JSON 200 fallback (e.g. SPA soft-404 HTML)
  }

  return {
    probed: true,
    endpointUrl: gpcUrl,
    httpStatus: res.statusCode,
    wellKnownFound: false,
    gpcSupportDeclared: false,
  };
}

export interface AuditExecutionDependencies {
  runtime?: ApifyRuntimeAdapter;
  robotsGuard?: RobotsAndRateGuard;
  billing?: BillingManager;
  allowLocalhost?: boolean;
  dnsLookup?: DnsLookupFn;
  pushToDataset?: boolean;
  chargeActorStart?: boolean;
}

export interface BatchAuditResult {
  items: WiretapPixelAuditReportItem[];
  billing: BillingSummary;
  stoppedDueToBudgetCap: boolean;
  engineName: string;
}

export async function auditSingleSite(params: {
  rawUrl: string;
  config: NormalizedAuditInput;
  billing: BillingManager;
  robotsGuard: RobotsAndRateGuard;
  allowLocalhost?: boolean;
  dnsLookup?: DnsLookupFn;
}): Promise<{ item: WiretapPixelAuditReportItem | null; budgetStopped: boolean }> {
  const { rawUrl, config, billing, robotsGuard, allowLocalhost, dnsLookup } = params;
  const startedMs = Date.now();
  const normalizedInputUrl = coerceUrlCandidate(rawUrl);

  // 1. Strict SSRF Pre-Flight Validation
  const ssrf = await validateUrlAgainstSsrf(normalizedInputUrl, { allowLocalhost, dnsLookup });
  if (!ssrf.allowed || !ssrf.normalizedUrl || !ssrf.hostname) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'blocked_ssrf',
        reason: ssrf.reason || 'Blocked by SSRF security policy.',
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  const targetUrl = ssrf.normalizedUrl;
  const hostname = ssrf.hostname;

  // 2. Budget Ceiling Pre-Check before making network calls
  if (!billing.canAfford(PPE_EVENTS.URL_AUDITED, 1)) {
    return { item: null, budgetStopped: true };
  }

  // 3. Polite robots.txt check for homepage
  let effectiveDelayMs = config.domainDelayMs;
  if (config.respectRobotsTxt) {
    const robots = await robotsGuard.checkUrlAllowed(targetUrl, { allowLocalhost, dnsLookup });
    if (!robots.allowed) {
      return {
        item: buildBlockedOrErrorItem({
          rawUrl,
          normalizedInputUrl,
          status: 'blocked_robots',
          reason: `Disallowed by domain robots.txt (${robots.matchedRule || 'Disallow rule'}).`,
          loadTimeMs: Date.now() - startedMs,
        }),
        budgetStopped: false,
      };
    }
    if (robots.crawlDelayMs > effectiveDelayMs) {
      effectiveDelayMs = robots.crawlDelayMs;
    }
  }

  // 4. Polite per-domain delay
  await robotsGuard.waitForDomainSlot(hostname, effectiveDelayMs);

  // Re-check budget after waiting in queue
  if (!billing.canAfford(PPE_EVENTS.URL_AUDITED, 1)) {
    return { item: null, budgetStopped: true };
  }

  // 5. Fetch homepage via anti-DNS-rebinding pinned HTTP client
  const homeRes = await fetchSafeHttp(targetUrl, {
    maxBytes: DEFAULT_MAX_RESPONSE_BYTES,
    timeoutMs: config.requestTimeoutMs,
    maxRedirects: 5,
    allowLocalhost,
    dnsLookup,
    checkRedirectAllowed: config.respectRobotsTxt
      ? async (redirectUrl) => {
          const r = await robotsGuard.checkUrlAllowed(redirectUrl, { allowLocalhost, dnsLookup });
          return {
            allowed: r.allowed,
            reason: r.allowed
              ? undefined
              : `Redirect disallowed by robots.txt (${r.matchedRule || 'Disallow'}).`,
          };
        }
      : undefined,
  });

  if (homeRes.blockedBySsrf) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'blocked_ssrf',
        reason: homeRes.errorMessage || 'Blocked by SSRF redirect policy.',
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  if (homeRes.blockedByRobots) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'blocked_robots',
        reason: homeRes.errorMessage || 'Blocked by domain robots.txt during redirect.',
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  if (!homeRes.ok || homeRes.statusCode === null) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'error',
        httpStatus: homeRes.statusCode,
        reason: homeRes.errorMessage || 'Target site returned an unreachable or non-2xx/3xx HTTP status.',
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  if (isBinaryContentType(homeRes.contentType)) {
    return {
      item: buildBlockedOrErrorItem({
        rawUrl,
        normalizedInputUrl,
        status: 'error',
        httpStatus: homeRes.statusCode,
        reason: `Skipped non-HTML binary resource (Content-Type: ${homeRes.contentType}); $0 billed.`,
        loadTimeMs: Date.now() - startedMs,
      }),
      budgetStopped: false,
    };
  }

  const homeDoc = parseHtmlDocument(homeRes.bodyText, homeRes.finalUrl);
  const inspectedPages: InspectedPageBundle[] = [
    {
      requestedUrl: targetUrl,
      finalUrl: homeRes.finalUrl,
      redirectChain: homeRes.redirectChain,
      doc: homeDoc,
    },
  ];
  const pagesFetched: string[] = [homeRes.finalUrl];

  // 6. Discover and fetch up to `maxLegalPagesPerDomain` internal same-origin pages
  const candidateSubpages = selectPriorityInternalSubpages(
    homeDoc,
    homeRes.finalUrl,
    config.maxLegalPagesPerDomain,
  );

  const finalHomeHost = safeExtractHostname(homeRes.finalUrl);

  for (const subUrl of candidateSubpages) {
    if (config.respectRobotsTxt) {
      const subRobots = await robotsGuard.checkUrlAllowed(subUrl, { allowLocalhost, dnsLookup });
      if (!subRobots.allowed) {
        continue;
      }
    }

    await robotsGuard.waitForDomainSlot(finalHomeHost, effectiveDelayMs);

    const subRes = await fetchSafeHttp(subUrl, {
      maxBytes: DEFAULT_MAX_RESPONSE_BYTES,
      timeoutMs: config.requestTimeoutMs,
      maxRedirects: 5,
      allowLocalhost,
      dnsLookup,
      checkRedirectAllowed: config.respectRobotsTxt
        ? async (redirectUrl) => {
            const r = await robotsGuard.checkUrlAllowed(redirectUrl, { allowLocalhost, dnsLookup });
            return {
              allowed: r.allowed,
              reason: r.allowed ? undefined : 'Disallowed by robots.txt',
            };
          }
        : undefined,
    });

    if (subRes.blockedBySsrf || subRes.blockedByRobots || !subRes.ok || isBinaryContentType(subRes.contentType)) {
      continue;
    }

    const subDoc = parseHtmlDocument(subRes.bodyText || '', subRes.finalUrl);
    inspectedPages.push({
      requestedUrl: subUrl,
      finalUrl: subRes.finalUrl,
      redirectChain: subRes.redirectChain,
      doc: subDoc,
    });
    if (!pagesFetched.includes(subRes.finalUrl)) {
      pagesFetched.push(subRes.finalUrl);
    }
  }

  // 7. Probe `/.well-known/gpc.json` when enabled
  const gpcProbe: GpcWellKnownProbe = config.checkGpcAndOptOut
    ? await probeWellKnownGpcJson({
        homeFinalUrl: homeRes.finalUrl,
        respectRobotsTxt: config.respectRobotsTxt,
        effectiveDelayMs,
        requestTimeoutMs: config.requestTimeoutMs,
        robotsGuard,
        allowLocalhost,
        dnsLookup,
      })
    : {
        probed: false,
        endpointUrl: null,
        httpStatus: null,
        wellKnownFound: false,
        gpcSupportDeclared: false,
      };

  // 8. Charge `url-audited` ONLY now that the site was cleanly fetched and inspected!
  const urlCharge = await billing.chargeEvent(PPE_EVENTS.URL_AUDITED, 1);
  if (!urlCharge.charged) {
    return { item: null, budgetStopped: true };
  }

  // 9. Run all deterministic CIPA, VPPA, HIPAA/MHMDA & GPC/CCPA detectors
  const allDocs = inspectedPages.map((p) => p.doc);
  const domain = finalHomeHost;
  const detectedLanguage = detectSiteLanguage(allDocs);
  const siteInfo = classifySiteAndCmp(allDocs);
  const discoveredLinks = discoverPrivacyAndSensitiveLinks(allDocs);

  const wiretapChatAndReplayCheck = checkWiretapChatAndReplay({
    pages: inspectedPages,
    detectedCmp: siteInfo.detectedCmp,
    consentModeV2Detected: siteInfo.consentModeV2Detected,
    enabled: config.checkWiretapChatAndReplay,
  });

  const vppaVideoPixelCheck = checkVppaVideoPixels({
    pages: inspectedPages,
    consentModeV2Detected: siteInfo.consentModeV2Detected,
    enabled: config.checkVppaVideoPixels,
  });

  const sensitiveFormPixelCheck = checkSensitiveFormPixels({
    pages: inspectedPages,
    healthcareOrWellnessContext: siteInfo.healthcareOrWellnessContext,
    consentModeV2Detected: siteInfo.consentModeV2Detected,
    enabled: config.checkSensitiveIntakePixels,
  });

  const gpcAndOptOutCheck = evaluateGpcAndOptOut({
    pages: inspectedPages,
    adPixelVendors: vppaVideoPixelCheck.adPixelVendors,
    gpcProbe,
    enabled: config.checkGpcAndOptOut,
  });

  const { findings, complianceScore, riskTier } = buildFindingsAndScore({
    homeUrl: homeRes.finalUrl,
    discoveredLinks,
    wiretapChatAndReplay: wiretapChatAndReplayCheck,
    vppaVideoPixel: vppaVideoPixelCheck,
    sensitiveFormPixel: sensitiveFormPixelCheck,
    gpcAndOptOut: gpcAndOptOutCheck,
  });

  const coldOutreachHook = generateColdOutreachHook({
    domain,
    siteVertical: siteInfo.siteVertical,
    detectedCmp: siteInfo.detectedCmp,
    wiretapChatAndReplay: wiretapChatAndReplayCheck,
    vppaVideoPixel: vppaVideoPixelCheck,
    sensitiveFormPixel: sensitiveFormPixelCheck,
    gpcAndOptOut: gpcAndOptOutCheck,
    findings,
  });

  // 10. Optional Remediation Pack (only generated & charged when enabled AND findings.length > 0)
  let remediationPackGenerated = false;
  let remediationPack: WiretapPixelAuditReportItem['remediationPack'] = null;

  if (
    config.includeRemediationPack &&
    findings.length > 0 &&
    billing.canAfford(PPE_EVENTS.REMEDIATION_PACK_GENERATED, 1)
  ) {
    const remCharge = await billing.chargeEvent(PPE_EVENTS.REMEDIATION_PACK_GENERATED, 1);
    if (remCharge.charged) {
      remediationPackGenerated = true;
      remediationPack = generateRemediationPack({
        domain,
        sitePlatform: siteInfo.sitePlatform,
        siteVertical: siteInfo.siteVertical,
        detectedCmp: siteInfo.detectedCmp,
        wiretapChatAndReplay: wiretapChatAndReplayCheck,
        sensitiveFormPixel: sensitiveFormPixelCheck,
      });
    }
  }

  const wiretapRiskFound =
    wiretapChatAndReplayCheck.checked &&
    (wiretapChatAndReplayCheck.ungatedSessionReplayVendors.length > 0 ||
      wiretapChatAndReplayCheck.ungatedChatWidgetVendors.length > 0 ||
      (wiretapChatAndReplayCheck.chatWidgetVendors.length > 0 &&
        !wiretapChatAndReplayCheck.preChatRecordingDisclosureFound));

  const reportItem: WiretapPixelAuditReportItem = {
    url: rawUrl,
    normalizedInputUrl,
    finalUrl: homeRes.finalUrl,
    domain,
    auditedAt: new Date().toISOString(),
    status: 'audited',
    httpStatus: homeRes.statusCode,
    pageTitle: homeDoc.title,
    detectedLanguage,
    sitePlatform: siteInfo.sitePlatform,
    siteVertical: siteInfo.siteVertical,
    detectedCmp: siteInfo.detectedCmp,
    consentModeV2Detected: siteInfo.consentModeV2Detected,
    loadTimeMs: Date.now() - startedMs,
    pagesFetchedCount: pagesFetched.length,
    pagesFetched,
    errorMessage: null,

    complianceScore,
    riskTier,

    sessionReplayVendors: wiretapChatAndReplayCheck.sessionReplayVendors,
    ungatedSessionReplayVendors: wiretapChatAndReplayCheck.ungatedSessionReplayVendors,
    chatWidgetVendors: wiretapChatAndReplayCheck.chatWidgetVendors,
    ungatedChatWidgetVendors: wiretapChatAndReplayCheck.ungatedChatWidgetVendors,
    preChatRecordingDisclosureFound: wiretapChatAndReplayCheck.preChatRecordingDisclosureFound,
    wiretapRiskFound,
    wiretapChatAndReplayCheck,

    embeddedVideoProviders: vppaVideoPixelCheck.embeddedVideoProviders,
    adPixelVendors: vppaVideoPixelCheck.adPixelVendors,
    ungatedAdPixelVendors: vppaVideoPixelCheck.ungatedAdPixelVendors,
    vppaRiskFound: vppaVideoPixelCheck.vppaRiskFound,
    vppaVideoPixelCheck,

    sensitiveIntakeFormFound: sensitiveFormPixelCheck.sensitiveIntakeFormFound,
    sensitiveFormPixelLeakFound: sensitiveFormPixelCheck.sensitiveFormPixelLeakFound,
    sensitiveFormPixelCheck,

    gpcWellKnownFound: gpcAndOptOutCheck.gpcWellKnownFound,
    gpcSupportDeclared: gpcAndOptOutCheck.gpcSupportDeclared,
    ccpaPrivacyChoicesLinkFound: gpcAndOptOutCheck.ccpaPrivacyChoicesLinkFound,
    gpcOrOptOutRiskFound: gpcAndOptOutCheck.gpcOrOptOutRiskFound,
    gpcAndOptOutCheck,

    privacyPolicyUrl: discoveredLinks.privacyPolicyUrl,
    intakeOrBookingUrl:
      discoveredLinks.intakeOrBookingUrl ?? sensitiveFormPixelCheck.sensitiveFormPages[0] ?? null,
    videoPageUrl: discoveredLinks.videoPageUrl ?? vppaVideoPixelCheck.foundOnPages[0] ?? null,
    optOutUrl: discoveredLinks.optOutUrl ?? gpcAndOptOutCheck.optOutUrl,
    discoveredLinks,

    findingsCount: findings.length,
    findings,
    coldOutreachHook,

    remediationPackGenerated,
    remediationPack,

    recommendedNextActors: buildRecommendedNextActors(domain),
    disclaimer: LEGAL_DISCLAIMER,
  };

  return { item: reportItem, budgetStopped: billing.isLimitReached() };
}

export async function runBatchAudit(
  rawInput: RawActorInput | null | undefined,
  deps: AuditExecutionDependencies = {},
): Promise<BatchAuditResult> {
  const runtime = deps.runtime ?? new ApifyRuntimeAdapter();
  await runtime.init();

  let extraDatasetUrls: string[] = [];
  if (typeof rawInput?.datasetId === 'string' && rawInput.datasetId.trim().length > 0) {
    extraDatasetUrls = await runtime.loadUrlsFromDataset(
      rawInput.datasetId,
      rawInput.datasetUrlField,
    );
  }

  const config = normalizeAuditInput(rawInput, extraDatasetUrls);
  const billing = deps.billing ?? new BillingManager(runtime, config.maxBudgetUsd);
  const robotsGuard = deps.robotsGuard ?? new RobotsAndRateGuard();
  const pushToDataset = deps.pushToDataset ?? true;
  const chargeActorStart = deps.chargeActorStart ?? true;

  if (chargeActorStart) {
    const startCharge = await billing.chargeEvent(PPE_EVENTS.ACTOR_START, 1);
    if (!startCharge.charged) {
      return {
        items: [],
        billing: billing.getSummary(),
        stoppedDueToBudgetCap: true,
        engineName: 'zero-playwright-pinned-http',
      };
    }
  }

  if (config.urls.length === 0) {
    return {
      items: [],
      billing: billing.getSummary(),
      stoppedDueToBudgetCap: false,
      engineName: 'zero-playwright-pinned-http',
    };
  }

  const orderedItems: Array<WiretapPixelAuditReportItem | null> = new Array(config.urls.length).fill(null);
  let cursor = 0;
  let stoppedDueToBudgetCap = false;

  const workerCount = Math.min(config.maxConcurrency, config.urls.length);
  const workers = Array.from({ length: workerCount }, async () => {
    while (!stoppedDueToBudgetCap) {
      const index = cursor++;
      if (index >= config.urls.length) break;

      if (billing.isLimitReached() || !billing.canAfford(PPE_EVENTS.URL_AUDITED, 1)) {
        stoppedDueToBudgetCap = true;
        break;
      }

      const targetUrl = config.urls[index];
      const { item, budgetStopped } = await auditSingleSite({
        rawUrl: targetUrl,
        config,
        billing,
        robotsGuard,
        allowLocalhost: deps.allowLocalhost,
        dnsLookup: deps.dnsLookup,
      });

      if (item) {
        orderedItems[index] = item;
        if (pushToDataset) {
          await runtime.pushData(item);
        }
      }

      if (budgetStopped) {
        stoppedDueToBudgetCap = true;
        break;
      }
    }
  });

  await Promise.all(workers);

  const items = orderedItems.filter((x): x is WiretapPixelAuditReportItem => x !== null);

  return {
    items,
    billing: billing.getSummary(),
    stoppedDueToBudgetCap,
    engineName: 'zero-playwright-pinned-http',
  };
}
