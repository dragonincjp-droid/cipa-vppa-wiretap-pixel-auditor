export const LEGAL_DISCLAIMER =
  'Automated technical heuristic signals for human review only; does not constitute legal advice or formal regulatory certification.';

export const PPE_EVENTS = {
  ACTOR_START: 'actor-start',
  URL_AUDITED: 'url-audited',
  REMEDIATION_PACK_GENERATED: 'remediation-pack-generated',
} as const;

export type PpeEventName = (typeof PPE_EVENTS)[keyof typeof PPE_EVENTS];

export type RiskTier = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW';
export type AuditStatus = 'audited' | 'blocked_ssrf' | 'blocked_robots' | 'error';

export type SitePlatform =
  | 'shopify'
  | 'woocommerce'
  | 'wordpress'
  | 'webflow'
  | 'wix'
  | 'squarespace'
  | 'healthcare-web'
  | 'saas-web'
  | 'custom';

export type SiteVertical =
  | 'healthcare_or_wellness'
  | 'ecommerce_or_dtc'
  | 'media_or_video'
  | 'b2b_or_saas'
  | 'general_business';

export type DetectedCmp =
  | 'onetrust'
  | 'usercentrics'
  | 'cookiebot'
  | 'osano'
  | 'termly'
  | 'trustarc'
  | 'ketch'
  | 'securiti'
  | 'didomi'
  | 'iubenda'
  | 'complianz'
  | 'custom-cmp'
  | 'none';

export type SessionReplayVendor =
  | 'fullstory'
  | 'hotjar'
  | 'microsoft-clarity'
  | 'logrocket'
  | 'mouseflow'
  | 'lucky-orange'
  | 'crazy-egg'
  | 'contentsquare'
  | 'smartlook'
  | 'posthog-replay';

export type ChatWidgetVendor =
  | 'intercom'
  | 'drift'
  | 'zendesk-chat'
  | 'gorgias-chat'
  | 'tidio'
  | 'livechat'
  | 'hubspot-chat'
  | 'crisp'
  | 'ada-chat'
  | 'qualified';

export type VideoProvider =
  | 'youtube'
  | 'youtube-nocookie'
  | 'vimeo'
  | 'wistia'
  | 'jwplayer'
  | 'mux'
  | 'vidyard'
  | 'brightcove'
  | 'html5-video';

export type AdPixelVendor =
  | 'meta-pixel'
  | 'tiktok-pixel'
  | 'google-ads'
  | 'linkedin-insight'
  | 'pinterest-tag'
  | 'snap-pixel'
  | 'reddit-pixel'
  | 'x-pixel'
  | 'criteo';

export interface UrlRequestObject {
  url: string;
}

export interface RawActorInput {
  urls?: Array<string | UrlRequestObject>;
  startUrls?: Array<string | UrlRequestObject>;
  url?: string;
  datasetId?: string;
  datasetUrlField?: string;
  maxLegalPagesPerDomain?: number;
  includeRemediationPack?: boolean;
  checkWiretapChatAndReplay?: boolean;
  checkVppaVideoPixels?: boolean;
  checkSensitiveIntakePixels?: boolean;
  checkGpcAndOptOut?: boolean;
  respectRobotsTxt?: boolean;
  maxUrls?: number;
  maxConcurrency?: number;
  domainDelayMs?: number;
  requestTimeoutMs?: number;
  maxBudgetUsd?: number;
  maxTotalChargeUsd?: number;
}

export interface NormalizedAuditInput {
  urls: string[];
  datasetId?: string;
  datasetUrlField?: string;
  maxLegalPagesPerDomain: number;
  includeRemediationPack: boolean;
  checkWiretapChatAndReplay: boolean;
  checkVppaVideoPixels: boolean;
  checkSensitiveIntakePixels: boolean;
  checkGpcAndOptOut: boolean;
  respectRobotsTxt: boolean;
  maxUrls: number;
  maxConcurrency: number;
  domainDelayMs: number;
  requestTimeoutMs: number;
  maxBudgetUsd?: number;
}

export interface ParsedScriptTag {
  src: string;
  resolvedSrc: string;
  dataSrc: string;
  resolvedDataSrc: string;
  type: string;
  id: string;
  className: string;
  dataAttributes: string;
  rawAttrs: string;
  inlineCode: string;
  isConsentGated: boolean;
  gatingMechanism: string | null;
}

export interface ParsedIframeTag {
  src: string;
  resolvedSrc: string;
  dataSrc: string;
  resolvedDataSrc: string;
  title: string;
  id: string;
  className: string;
  dataAttributes: string;
  rawAttrs: string;
  isConsentGated: boolean;
}

export interface ParsedVideoElement {
  src: string;
  resolvedSrc: string;
  poster: string;
  id: string;
  className: string;
  dataAttributes: string;
}

export interface ParsedAnchor {
  href: string;
  resolvedHref: string;
  text: string;
  ariaLabel: string;
  title: string;
  id: string;
  className: string;
  inFooter: boolean;
  inNav: boolean;
}

export interface ParsedControl {
  tag: 'button' | 'input' | 'role-button';
  type: string;
  text: string;
  ariaLabel: string;
  id: string;
  className: string;
  name: string;
  dataAttributes: string;
}

export interface ParsedCheckbox {
  id: string;
  name: string;
  className: string;
  value: string;
  checked: boolean;
  required: boolean;
  associatedText: string;
}

export interface ParsedForm {
  action: string;
  resolvedAction: string;
  method: string;
  id: string;
  className: string;
  inputNamesAndTypes: string[];
  sensitiveHealthFields: string[];
  buttonTexts: string[];
  textSnippet: string;
}

export interface ParsedHtmlDocument {
  url: string;
  title: string | null;
  htmlLang: string | null;
  rawHtml: string;
  visibleText: string;
  scripts: ParsedScriptTag[];
  scriptUrls: string[];
  inlineScripts: string[];
  iframes: ParsedIframeTag[];
  videos: ParsedVideoElement[];
  pixelImgUrls: string[];
  stylesheetUrls: string[];
  jsonLdBlocks: unknown[];
  anchors: ParsedAnchor[];
  controls: ParsedControl[];
  checkboxes: ParsedCheckbox[];
  forms: ParsedForm[];
}

export interface WiretapChatAndReplayCheckResult {
  checked: boolean;
  detectedCmp: DetectedCmp;
  consentModeV2Detected: boolean;
  sessionReplayVendors: SessionReplayVendor[];
  ungatedSessionReplayVendors: SessionReplayVendor[];
  gatedSessionReplayVendors: SessionReplayVendor[];
  chatWidgetVendors: ChatWidgetVendor[];
  ungatedChatWidgetVendors: ChatWidgetVendor[];
  gatedChatWidgetVendors: ChatWidgetVendor[];
  preChatRecordingDisclosureFound: boolean;
  recordingDisclosureSignals: string[];
  wiretapEvidence: string[];
  foundOnPages: string[];
}

export interface VppaVideoPixelCheckResult {
  checked: boolean;
  embeddedVideoProviders: VideoProvider[];
  ungatedVideoProviders: VideoProvider[];
  adPixelVendors: AdPixelVendor[];
  ungatedAdPixelVendors: AdPixelVendor[];
  gatedAdPixelVendors: AdPixelVendor[];
  standaloneVideoConsentFound: boolean;
  coPresentOnSamePage: boolean;
  vppaRiskFound: boolean;
  vppaEvidence: string[];
  foundOnPages: string[];
}

export interface SensitiveFormPixelCheckResult {
  checked: boolean;
  healthcareOrWellnessContext: boolean;
  sensitiveIntakeFormFound: boolean;
  sensitiveFormPages: string[];
  matchedSensitiveFields: string[];
  ungatedTrackersOnFormPages: string[];
  sensitiveFormPixelLeakFound: boolean;
  evidence: string[];
}

export interface GpcAndOptOutCheckResult {
  checked: boolean;
  adTrackersPresent: boolean;
  gpcEndpointUrl: string | null;
  gpcHttpStatus: number | null;
  gpcWellKnownFound: boolean;
  gpcSupportDeclared: boolean;
  clientGpcListenerDetected: boolean;
  ccpaPrivacyChoicesLinkFound: boolean;
  optOutLinkLabel: string | null;
  optOutUrl: string | null;
  gpcOrOptOutRiskFound: boolean;
  evidence: string[];
}

export interface DiscoveredPrivacyLinks {
  privacyPolicyUrl: string | null;
  intakeOrBookingUrl: string | null;
  videoPageUrl: string | null;
  optOutUrl: string | null;
  contactUrl: string | null;
}

export interface ComplianceFinding {
  ruleId: string;
  title: string;
  regulation: string;
  severity: FindingSeverity;
  pageUrl: string;
  evidence: string;
  recommendation: string;
}

export interface RemediationPack {
  sitePlatform: SitePlatform;
  siteVertical: SiteVertical;
  detectedCmp: DetectedCmp;
  priorConsentScriptGateHtmlJs: string;
  preChatCipaDisclosureWidgetHtmlJs: string;
  wellKnownGpcJson: string;
  ccpaPrivacyChoicesFooterHtmlJs: string;
  hipaaSensitiveFormScrubbingGuidance: string | null;
  regulatoryCoverageSummary: string;
  implementationNotes: string[];
}

export interface RecommendedNextActor {
  actorSlug: string;
  actorUrl: string;
  mcpEndpointUrl: string;
  reason: string;
}

export interface WiretapPixelAuditReportItem {
  url: string;
  normalizedInputUrl: string;
  finalUrl: string | null;
  domain: string;
  auditedAt: string;
  status: AuditStatus;
  httpStatus: number | null;
  pageTitle: string | null;
  detectedLanguage: string | null;
  sitePlatform: SitePlatform;
  siteVertical: SiteVertical;
  detectedCmp: DetectedCmp;
  consentModeV2Detected: boolean;
  loadTimeMs: number;
  pagesFetchedCount: number;
  pagesFetched: string[];
  errorMessage: string | null;

  complianceScore: number;
  riskTier: RiskTier;

  sessionReplayVendors: SessionReplayVendor[];
  ungatedSessionReplayVendors: SessionReplayVendor[];
  chatWidgetVendors: ChatWidgetVendor[];
  ungatedChatWidgetVendors: ChatWidgetVendor[];
  preChatRecordingDisclosureFound: boolean;
  wiretapRiskFound: boolean;
  wiretapChatAndReplayCheck: WiretapChatAndReplayCheckResult;

  embeddedVideoProviders: VideoProvider[];
  adPixelVendors: AdPixelVendor[];
  ungatedAdPixelVendors: AdPixelVendor[];
  vppaRiskFound: boolean;
  vppaVideoPixelCheck: VppaVideoPixelCheckResult;

  sensitiveIntakeFormFound: boolean;
  sensitiveFormPixelLeakFound: boolean;
  sensitiveFormPixelCheck: SensitiveFormPixelCheckResult;

  gpcWellKnownFound: boolean;
  gpcSupportDeclared: boolean;
  ccpaPrivacyChoicesLinkFound: boolean;
  gpcOrOptOutRiskFound: boolean;
  gpcAndOptOutCheck: GpcAndOptOutCheckResult;

  privacyPolicyUrl: string | null;
  intakeOrBookingUrl: string | null;
  videoPageUrl: string | null;
  optOutUrl: string | null;
  discoveredLinks: DiscoveredPrivacyLinks;

  findingsCount: number;
  findings: ComplianceFinding[];
  coldOutreachHook: string;

  remediationPackGenerated: boolean;
  remediationPack: RemediationPack | null;

  recommendedNextActors: RecommendedNextActor[];
  disclaimer: string;
}
