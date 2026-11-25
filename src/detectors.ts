import type {
  AdPixelVendor,
  ChatWidgetVendor,
  DetectedCmp,
  DiscoveredPrivacyLinks,
  GpcAndOptOutCheckResult,
  ParsedAnchor,
  ParsedHtmlDocument,
  SensitiveFormPixelCheckResult,
  SessionReplayVendor,
  SitePlatform,
  SiteVertical,
  VideoProvider,
  VppaVideoPixelCheckResult,
  WiretapChatAndReplayCheckResult,
} from './types.js';

export interface InspectedPageBundle {
  requestedUrl: string;
  finalUrl: string;
  redirectChain: string[];
  doc: ParsedHtmlDocument;
}

export interface GpcWellKnownProbe {
  probed: boolean;
  endpointUrl: string | null;
  httpStatus: number | null;
  wellKnownFound: boolean;
  gpcSupportDeclared: boolean;
}

const ASSET_EXTENSION_RE =
  /\.(?:jpg|jpeg|png|gif|webp|avif|svg|ico|css|js|mjs|woff|woff2|ttf|eot|mp4|webm|mp3|zip|tar|gz|rar|xml|json)(?:[?#]|$)/i;

const CMP_PATTERNS: Array<{ cmp: Exclude<DetectedCmp, 'none' | 'custom-cmp'>; regex: RegExp }> = [
  {
    cmp: 'onetrust',
    regex: /\b(?:cdn\.cookielaw\.org|optanon\.blob\.core|OneTrust|OptanonWrapper|optanon-category-)\b/i,
  },
  {
    cmp: 'usercentrics',
    regex: /\b(?:app\.usercentrics\.eu|web\.cmp\.usercentrics\.eu|data-usercentrics|UC_UI)\b/i,
  },
  {
    cmp: 'cookiebot',
    regex: /\b(?:consent\.cookiebot\.com|Cookiebot|data-cookieconsent)\b/i,
  },
  {
    cmp: 'osano',
    regex: /\b(?:cmp\.osano\.com|Osano\.cm)\b/i,
  },
  {
    cmp: 'termly',
    regex: /\b(?:app\.termly\.io|data-termly-category|termly-styles)\b/i,
  },
  {
    cmp: 'trustarc',
    regex: /\b(?:consent\.trustarc\.com|consent-pref\.trustarc\.com|truste\.eu)\b/i,
  },
  {
    cmp: 'ketch',
    regex: /\b(?:global\.ketchcdn\.com|ketch\s*\(\s*['"](?:init|on))\b/i,
  },
  {
    cmp: 'securiti',
    regex: /\b(?:cdn-prod\.securiti\.ai|securiti-sdk)\b/i,
  },
  {
    cmp: 'didomi',
    regex: /\b(?:sdk\.privacy-center\.org|Didomi|didomiConfig)\b/i,
  },
  {
    cmp: 'iubenda',
    regex: /\b(?:cdn\.iubenda\.com|_iub\.csConfiguration|data-iub-purposes)\b/i,
  },
  {
    cmp: 'complianz',
    regex: /\b(?:complianz-gdpr|cmplz-script|data-cmplz)\b/i,
  },
];

const SESSION_REPLAY_PATTERNS: Array<{ vendor: SessionReplayVendor; regex: RegExp }> = [
  {
    vendor: 'fullstory',
    regex: /\b(?:edge\.fullstory\.com|fullstory\.com\/s\/fs\.js|_fs_namespace|FS\.identify)\b/i,
  },
  {
    vendor: 'hotjar',
    regex: /\b(?:static\.hotjar\.com|script\.hotjar\.com|_hjSettings|hjid)\b/i,
  },
  {
    vendor: 'microsoft-clarity',
    regex: /\b(?:clarity\.ms\/tag\/|www\.clarity\.ms|window\.clarity)\b/i,
  },
  {
    vendor: 'logrocket',
    regex: /\b(?:cdn\.lr-ingest\.io|cdn\.lr-in(?:-prod)?\.com|cdn\.logrocket\.io|LogRocket\.init)\b/i,
  },
  {
    vendor: 'mouseflow',
    regex: /\b(?:cdn\.mouseflow\.com|_mfq\.push)\b/i,
  },
  {
    vendor: 'lucky-orange',
    regex: /\b(?:tools\.luckyorange\.com|luckyorange\.com|__lo_site_id)\b/i,
  },
  {
    vendor: 'crazy-egg',
    regex: /\b(?:script\.crazyegg\.com|crazyegg\.com\/pages\/scripts\/)\b/i,
  },
  {
    vendor: 'contentsquare',
    regex: /\b(?:t\.contentsquare\.net|_uxa\.push)\b/i,
  },
  {
    vendor: 'smartlook',
    regex: /\b(?:rec\.smartlook\.com|web-sdk\.smartlook\.com|smartlook\s*\(\s*['"]init['"])\b/i,
  },
  {
    vendor: 'posthog-replay',
    regex: /\b(?:us\.i\.posthog\.com|eu\.i\.posthog\.com|app\.posthog\.com\/static\/array\.js|posthog\.init\s*\()\b/i,
  },
];

const CHAT_WIDGET_PATTERNS: Array<{ vendor: ChatWidgetVendor; regex: RegExp }> = [
  {
    vendor: 'intercom',
    regex: /\b(?:widget\.intercom\.io|js\.intercomcdn\.com|window\.intercomSettings|Intercom\s*\(\s*['"]boot['"])\b/i,
  },
  {
    vendor: 'drift',
    regex: /\b(?:js\.driftt\.com|drift\.load\s*\()\b/i,
  },
  {
    vendor: 'zendesk-chat',
    regex: /\b(?:static\.zdassets\.com\/ekr\/snippet\.js|ekr\.zdassets\.com|zE\s*\(\s*['"](?:webWidget|messenger)['"])\b/i,
  },
  {
    vendor: 'gorgias-chat',
    regex: /\b(?:config\.gorgias\.chat|gorgias-chat-bundle)\b/i,
  },
  {
    vendor: 'tidio',
    regex: /\b(?:code\.tidio\.co|tidioChatApi)\b/i,
  },
  {
    vendor: 'livechat',
    regex: /\b(?:cdn\.livechatinc\.com\/tracking\.js|window\.__lc\s*=)\b/i,
  },
  {
    vendor: 'hubspot-chat',
    regex: /\b(?:js\.usemessages\.com\/conversations-embed\.js|HubSpotConversations|hsConversationsSettings)\b/i,
  },
  {
    vendor: 'crisp',
    regex: /\b(?:client\.crisp\.chat\/l\.js|CRISP_WEBSITE_ID|\$crisp)\b/i,
  },
  {
    vendor: 'ada-chat',
    regex: /\b(?:static\.ada\.support\/embed|window\.adaSettings|adaEmbed)\b/i,
  },
  {
    vendor: 'qualified',
    regex: /\b(?:js\.qualified\.com|qualified\s*\(\s*['"]init['"])\b/i,
  },
];

const AD_PIXEL_PATTERNS: Array<{ vendor: AdPixelVendor; regex: RegExp }> = [
  {
    vendor: 'meta-pixel',
    regex: /\b(?:connect\.facebook\.net\/[^"'\s]*\/fbevents\.js|facebook\.com\/tr\?id=|fbq\s*\(\s*['"]init['"])\b/i,
  },
  {
    vendor: 'tiktok-pixel',
    regex: /\b(?:analytics\.tiktok\.com\/i18n\/pixel|ttq\.load\s*\()\b/i,
  },
  {
    vendor: 'google-ads',
    regex: /\b(?:googleadservices\.com\/pagead\/conversion|googletagmanager\.com\/gtag\/js\?id=AW-|gtag\s*\(\s*['"]config['"]\s*,\s*['"]AW-)\b/i,
  },
  {
    vendor: 'linkedin-insight',
    regex: /\b(?:snap\.licdn\.com\/li\.lms-analytics|px\.ads\.linkedin\.com\/collect|_linkedin_partner_id)\b/i,
  },
  {
    vendor: 'pinterest-tag',
    regex: /\b(?:s\.pinimg\.com\/ct\/core\.js|ct\.pinterest\.com\/v3\/|pintrk\s*\(\s*['"]load['"])\b/i,
  },
  {
    vendor: 'snap-pixel',
    regex: /\b(?:sc-static\.net\/scevent\.min\.js|tr\.snapchat\.com\/|snaptr\s*\(\s*['"]init['"])\b/i,
  },
  {
    vendor: 'reddit-pixel',
    regex: /\b(?:alb\.reddit\.com\/snoogle|rdt\s*\(\s*['"]init['"])\b/i,
  },
  {
    vendor: 'x-pixel',
    regex: /\b(?:static\.ads-twitter\.com\/uwt\.js|analytics\.twitter\.com\/i\/adsct|twq\s*\(\s*['"]init['"])\b/i,
  },
  {
    vendor: 'criteo',
    regex: /\b(?:dynamic\.criteo\.com|static\.criteo\.net\/js\/ld\/ld\.js|window\.criteo_q)\b/i,
  },
];

const VIDEO_IFRAME_OR_SCRIPT_PATTERNS: Array<{ provider: Exclude<VideoProvider, 'html5-video'>; regex: RegExp }> = [
  {
    provider: 'youtube-nocookie',
    regex: /\b(?:www\.)?youtube-nocookie\.com\/embed\//i,
  },
  {
    provider: 'youtube',
    regex: /\b(?:(?:www\.)?youtube\.com\/(?:embed\/|iframe_api)|youtu\.be\/)/i,
  },
  {
    provider: 'vimeo',
    regex: /\b(?:player\.vimeo\.com\/video\/|vimeo\.com\/api\/player\.js)\b/i,
  },
  {
    provider: 'wistia',
    regex: /\b(?:fast\.wistia\.(?:com|net)|wistia_embed|<wistia-player)\b/i,
  },
  {
    provider: 'jwplayer',
    regex: /\b(?:cdn\.jwplayer\.com|content\.jwplatform\.com|jwplayer\s*\()\b/i,
  },
  {
    provider: 'mux',
    regex: /\b(?:stream\.mux\.com|<mux-player|<mux-video)\b/i,
  },
  {
    provider: 'vidyard',
    regex: /\b(?:play\.vidyard\.com|vidyard-player-embed)\b/i,
  },
  {
    provider: 'brightcove',
    regex: /\b(?:players\.brightcove\.net)\b/i,
  },
];

const GOOGLE_CONSENT_MODE_DENIED_RE =
  /gtag\s*\(\s*['"]consent['"]\s*,\s*['"]default['"][\s\S]{0,450}?(?:ad_storage|ad_user_data)\s*:\s*['"]denied['"]/i;

const HEALTHCARE_CONTEXT_RE =
  /\b(clinic|medical|healthcare|health\s+center|hospital|dental|dentist|orthodont|dermatolog|orthopedic|pediatric|psychiatr|psycholog|mental\s+health|behavioral\s+health|telehealth|telemedicine|urgent\s+care|primary\s+care|chiropract|fertility|obgyn|optometr|ophthalmolog|physical\s+therapy|wellness\s+clinic|patient\s+(?:intake|portal|care|appointment)|hipaa|notice\s+of\s+privacy\s+practices|physician|nurse\s+practitioner)\b/i;

const STRICT_CLINICAL_FIELD_RE =
  /\b(patient|symptom|symptoms|diagnosis|medication|medications|prescription|chief[-_ ]?complaint|medical[-_ ]?history|mental[-_ ]?health|telehealth|reason[-_ ]?for[-_ ]?visit)\b/i;

const BOOKING_ROUTE_OR_TITLE_RE =
  /\b(appointment|appointments|book|intake|patient|schedule|telehealth|consultation|visit)\b/i;

const CHAT_RECORDING_DISCLOSURE_RE =
  /\b(?:chat(?:s|\s+conversations?|\s+messages?|\s+sessions?|\s+communications?|\s+interactions?)?\s+(?:may\s+be|are|is|will\s+be)\s+(?:recorded|monitored|transcribed|logged|stored|shared\s+with|processed\s+by)|by\s+(?:starting|using|initiating|opening|continuing)\s+(?:a\s+|live\s+|this\s+|our\s+)?chat[^.]{0,140}?(?:consent|agree|acknowledge)[^.]{0,120}?(?:record|monitor|transcrib|third[- ]party|vendor|service\s+provider)|real[- ]time\s+(?:chat\s+)?(?:recording|monitoring|transcription)|third[- ]party\s+(?:live[- ]chat|chat|ai\s+chat(?:bot)?)\s+(?:provider|vendor|processor|platform)|cipa\s+(?:recording|wiretap)\s+(?:consent|disclosure))\b/i;

const STANDALONE_VPPA_CONSENT_RE =
  /\b(?:consent\s+to\s+share\s+(?:my\s+|your\s+)?video[- ]?(?:viewing|watch)|video\s+privacy\s+protection|vppa\s+consent|share\s+video[- ]?viewing\s+(?:history|activity|information)\s+with\s+(?:advertising|third\s+parties))\b/i;

const CCPA_PRIVACY_CHOICES_RE =
  /\b(your\s+privacy\s+choices|do\s+not\s+sell\s+(?:or\s+share\s+)?my\s+personal\s+information|do\s+not\s+sell\s+or\s+share|limit\s+the\s+use\s+of\s+my\s+sensitive\s+personal\s+information|privacy[-_ ]?choices|do[-_ ]?not[-_ ]?sell)\b/i;

const CLIENT_GPC_SCRIPT_RE = /\bnavigator\.globalPrivacyControl\b|\bSec-GPC\b/i;

function extractPhraseContext(text: string, matchIndex: number, matchLength: number): string {
  const start = Math.max(0, matchIndex - 30);
  const end = Math.min(text.length, matchIndex + matchLength + 44);
  let snippet = text.slice(start, end).replace(/\s+/g, ' ').trim();
  if (start > 0) snippet = `...${snippet}`;
  if (end < text.length) snippet = `${snippet}...`;
  return snippet;
}

export function detectSiteLanguage(pages: ParsedHtmlDocument[]): string {
  for (const p of pages) {
    if (p.htmlLang && /^[a-z]{2,3}$/i.test(p.htmlLang)) {
      return p.htmlLang.toLowerCase();
    }
  }
  return 'en';
}

export interface SiteClassificationSummary {
  sitePlatform: SitePlatform;
  siteVertical: SiteVertical;
  detectedCmp: DetectedCmp;
  consentModeV2Detected: boolean;
  healthcareOrWellnessContext: boolean;
}

export function classifySiteAndCmp(pages: ParsedHtmlDocument[]): SiteClassificationSummary {
  const combinedMarkup = pages
    .map((p) =>
      [
        p.scriptUrls.join(' '),
        p.stylesheetUrls.join(' '),
        p.inlineScripts.join(' ').slice(0, 24_000),
        p.scripts.map((s) => `${s.className} ${s.dataAttributes} ${s.rawAttrs}`).join(' '),
        p.rawHtml.slice(0, 45_000),
      ].join('\n'),
    )
    .join('\n');

  const combinedTextAndTitles = pages
    .map((p) => `${p.url} ${p.title ?? ''} ${p.visibleText}`)
    .join('\n');

  let detectedCmp: DetectedCmp = 'none';
  for (const cPat of CMP_PATTERNS) {
    if (cPat.regex.test(combinedMarkup)) {
      detectedCmp = cPat.cmp;
      break;
    }
  }

  const consentModeV2Detected = GOOGLE_CONSENT_MODE_DENIED_RE.test(combinedMarkup);

  if (
    detectedCmp === 'none' &&
    /\b(?:data-cipa-consent-category|data-consent-category|cookie-consent-banner|window\.__cipaConsentGranted)\b/i.test(
      combinedMarkup,
    )
  ) {
    detectedCmp = 'custom-cmp';
  }

  const healthcareOrWellnessContext = HEALTHCARE_CONTEXT_RE.test(combinedTextAndTitles);

  let sitePlatform: SitePlatform = 'custom';
  if (/\bcdn\.shopify\.com\b|\bShopify\.shop\b|\bshopify-section\b|\bmyshopify\.com\b/i.test(combinedMarkup)) {
    sitePlatform = 'shopify';
  } else if (
    /\/wp-content\/plugins\/woocommerce\/|\bwoocommerce-Price-amount\b|\bwoocommerce_params\b/i.test(
      combinedMarkup,
    )
  ) {
    sitePlatform = 'woocommerce';
  } else if (/\/wp-content\/|\/wp-includes\//i.test(combinedMarkup)) {
    sitePlatform = 'wordpress';
  } else if (/\bdata-wf-site\b|\bwebflow\.js\b|\bwebsite-files\.com\b/i.test(combinedMarkup)) {
    sitePlatform = 'webflow';
  } else if (/\bstatic\.parastorage\.com\b|\bwixstatic\.com\b/i.test(combinedMarkup)) {
    sitePlatform = 'wix';
  } else if (/\bstatic\d*\.squarespace\.com\b|\bSquarespace\.onInitialize\b/i.test(combinedMarkup)) {
    sitePlatform = 'squarespace';
  } else if (healthcareOrWellnessContext) {
    sitePlatform = 'healthcare-web';
  } else if (
    /\b(api\s+docs|start\s+free\s+trial|per\s+seat|b2b\s+saas|developer\s+platform)\b/i.test(
      combinedTextAndTitles,
    )
  ) {
    sitePlatform = 'saas-web';
  }

  let siteVertical: SiteVertical = 'general_business';
  if (healthcareOrWellnessContext) {
    siteVertical = 'healthcare_or_wellness';
  } else if (
    sitePlatform === 'shopify' ||
    sitePlatform === 'woocommerce' ||
    /\b(add\s+to\s+cart|shop\s+now|free\s+shipping|checkout)\b/i.test(combinedTextAndTitles)
  ) {
    siteVertical = 'ecommerce_or_dtc';
  } else if (
    pages.some((p) => p.videos.length > 0 || p.iframes.some((f) => /youtube|vimeo|wistia|jwplayer|mux|vidyard|brightcove/i.test(`${f.src} ${f.dataSrc}`))) &&
    /\b(watch|episode|stream|newsroom|video\s+library|podcast)\b/i.test(combinedTextAndTitles)
  ) {
    siteVertical = 'media_or_video';
  } else if (
    sitePlatform === 'saas-web' ||
    /\b(book\s+a\s+demo|pricing|enterprise|cloud\s+platform|saas)\b/i.test(combinedTextAndTitles)
  ) {
    siteVertical = 'b2b_or_saas';
  }

  return {
    sitePlatform,
    siteVertical,
    detectedCmp,
    consentModeV2Detected,
    healthcareOrWellnessContext,
  };
}

interface PageTrackerScan {
  pageUrl: string;
  sessionReplayAll: Set<SessionReplayVendor>;
  sessionReplayUngated: Set<SessionReplayVendor>;
  sessionReplayGated: Set<SessionReplayVendor>;
  chatAll: Set<ChatWidgetVendor>;
  chatUngated: Set<ChatWidgetVendor>;
  chatGated: Set<ChatWidgetVendor>;
  adPixelsAll: Set<AdPixelVendor>;
  adPixelsUngated: Set<AdPixelVendor>;
  adPixelsGated: Set<AdPixelVendor>;
  videoAll: Set<VideoProvider>;
  videoUngated: Set<VideoProvider>;
  evidenceNotes: string[];
}

function scanSinglePageTrackers(
  bundle: InspectedPageBundle,
  consentModeV2Sitewide: boolean,
): PageTrackerScan {
  const { doc, finalUrl } = bundle;
  const sessionReplayAll = new Set<SessionReplayVendor>();
  const sessionReplayUngated = new Set<SessionReplayVendor>();
  const sessionReplayGated = new Set<SessionReplayVendor>();

  const chatAll = new Set<ChatWidgetVendor>();
  const chatUngated = new Set<ChatWidgetVendor>();
  const chatGated = new Set<ChatWidgetVendor>();

  const adPixelsAll = new Set<AdPixelVendor>();
  const adPixelsUngated = new Set<AdPixelVendor>();
  const adPixelsGated = new Set<AdPixelVendor>();

  const videoAll = new Set<VideoProvider>();
  const videoUngated = new Set<VideoProvider>();
  const evidenceNotes: string[] = [];

  for (const script of doc.scripts) {
    const targetBlob = `${script.resolvedSrc} ${script.resolvedDataSrc} ${script.src} ${script.dataSrc} ${script.inlineCode}`;

    // 1. Session Replay
    for (const srPat of SESSION_REPLAY_PATTERNS) {
      if (srPat.regex.test(targetBlob)) {
        if (
          srPat.vendor === 'posthog-replay' &&
          /disable_session_recording\s*:\s*true/i.test(script.inlineCode)
        ) {
          continue;
        }
        sessionReplayAll.add(srPat.vendor);
        if (script.isConsentGated) {
          sessionReplayGated.add(srPat.vendor);
        } else {
          sessionReplayUngated.add(srPat.vendor);
          evidenceNotes.push(
            `Ungated session-replay script "${srPat.vendor}" (${script.resolvedSrc || 'inline SDK'}) on ${finalUrl}`,
          );
        }
      }
    }

    // 2. Third-Party Chat / AI Chatbot
    for (const chPat of CHAT_WIDGET_PATTERNS) {
      if (chPat.regex.test(targetBlob)) {
        chatAll.add(chPat.vendor);
        if (script.isConsentGated) {
          chatGated.add(chPat.vendor);
        } else {
          chatUngated.add(chPat.vendor);
          evidenceNotes.push(
            `Ungated third-party chat SDK "${chPat.vendor}" (${script.resolvedSrc || 'inline boot'}) on ${finalUrl}`,
          );
        }
      }
    }

    // 3. Ad-Tech Identity / Conversion Pixels
    for (const pxPat of AD_PIXEL_PATTERNS) {
      if (pxPat.regex.test(targetBlob)) {
        adPixelsAll.add(pxPat.vendor);
        const gatedViaConsentMode = pxPat.vendor === 'google-ads' && consentModeV2Sitewide;
        if (script.isConsentGated || gatedViaConsentMode) {
          adPixelsGated.add(pxPat.vendor);
        } else {
          adPixelsUngated.add(pxPat.vendor);
          evidenceNotes.push(
            `Ungated ad pixel "${pxPat.vendor}" (${script.resolvedSrc || 'inline beacon'}) on ${finalUrl}`,
          );
        }
      }
    }

    // 4. Script-injected video players (Wistia, JW Player, Vimeo Player API, YouTube Iframe API)
    for (const vPat of VIDEO_IFRAME_OR_SCRIPT_PATTERNS) {
      if (vPat.regex.test(targetBlob)) {
        videoAll.add(vPat.provider);
        if (!script.isConsentGated) {
          videoUngated.add(vPat.provider);
        }
      }
    }
  }

  // Active <img> pixel beacons outside <noscript>
  for (const imgUrl of doc.pixelImgUrls) {
    for (const pxPat of AD_PIXEL_PATTERNS) {
      if (pxPat.regex.test(imgUrl)) {
        adPixelsAll.add(pxPat.vendor);
        adPixelsUngated.add(pxPat.vendor);
        evidenceNotes.push(`Active <img> tracking pixel "${pxPat.vendor}" (${imgUrl}) on ${finalUrl}`);
      }
    }
  }

  // Embedded <iframe> video players
  for (const frame of doc.iframes) {
    const frameTarget = `${frame.resolvedSrc} ${frame.resolvedDataSrc} ${frame.src} ${frame.dataSrc} ${frame.className}`;
    for (const vPat of VIDEO_IFRAME_OR_SCRIPT_PATTERNS) {
      if (vPat.regex.test(frameTarget)) {
        videoAll.add(vPat.provider);
        if (!frame.isConsentGated) {
          videoUngated.add(vPat.provider);
        }
      }
    }
  }

  // Custom elements (<wistia-player>, <mux-player>, <mux-video>) in active HTML
  const uncommentedNoScript = doc.rawHtml
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ');
  if (/<wistia-player\b/i.test(uncommentedNoScript)) {
    videoAll.add('wistia');
    videoUngated.add('wistia');
  }
  if (/<mux-(?:player|video)\b/i.test(uncommentedNoScript)) {
    videoAll.add('mux');
    videoUngated.add('mux');
  }

  // Native HTML5 <video> elements
  if (doc.videos.length > 0) {
    videoAll.add('html5-video');
    videoUngated.add('html5-video');
  }

  return {
    pageUrl: finalUrl,
    sessionReplayAll,
    sessionReplayUngated,
    sessionReplayGated,
    chatAll,
    chatUngated,
    chatGated,
    adPixelsAll,
    adPixelsUngated,
    adPixelsGated,
    videoAll,
    videoUngated,
    evidenceNotes,
  };
}

function anchorCombinedLabel(a: ParsedAnchor): string {
  return `${a.text} ${a.ariaLabel} ${a.title} ${a.href}`.trim();
}

export function discoverPrivacyAndSensitiveLinks(pages: ParsedHtmlDocument[]): DiscoveredPrivacyLinks {
  let privacyPolicyUrl: string | null = null;
  let intakeOrBookingUrl: string | null = null;
  let videoPageUrl: string | null = null;
  let optOutUrl: string | null = null;
  let contactUrl: string | null = null;

  for (const page of pages) {
    for (const a of page.anchors) {
      if (!a.resolvedHref || !/^https?:/i.test(a.resolvedHref)) continue;
      const label = anchorCombinedLabel(a);

      if (!optOutUrl && CCPA_PRIVACY_CHOICES_RE.test(label)) {
        optOutUrl = a.resolvedHref;
      }

      if (
        !privacyPolicyUrl &&
        /\b(privacy[-_ ]?(?:policy|notice|center)|\bprivacy\b)\b/i.test(label) &&
        !CCPA_PRIVACY_CHOICES_RE.test(label)
      ) {
        privacyPolicyUrl = a.resolvedHref;
      }

      if (
        !intakeOrBookingUrl &&
        /\b(appointment|appointments|book[-_ ]?(?:now|online|appointment|visit|consultation)?|intake|patient[-_ ]?(?:intake|forms?)|schedule|telehealth|consultation)\b/i.test(
          label,
        )
      ) {
        intakeOrBookingUrl = a.resolvedHref;
      }

      if (
        !videoPageUrl &&
        /\b(videos?|watch|webinars?|demos?|tutorials?)\b/i.test(label)
      ) {
        videoPageUrl = a.resolvedHref;
      }

      if (!contactUrl && /\b(contact(?:-us)?|support)\b/i.test(label)) {
        contactUrl = a.resolvedHref;
      }
    }
  }

  return {
    privacyPolicyUrl,
    intakeOrBookingUrl,
    videoPageUrl,
    optOutUrl,
    contactUrl,
  };
}

/**
 * Selects up to `maxPages` same-origin internal subpages from the homepage to inspect,
 * prioritizing `/appointment`, `/book`, `/intake`, `/schedule`, `/videos`, `/watch`, `/demo`, `/privacy`, `/contact`.
 */
export function selectPriorityInternalSubpages(
  homeDoc: ParsedHtmlDocument,
  homeFinalUrl: string,
  maxPages: number,
): string[] {
  if (maxPages <= 0) return [];

  let homeOrigin: string;
  let homeNormalized: string;
  try {
    const u = new URL(homeFinalUrl);
    homeOrigin = u.origin;
    u.hash = '';
    homeNormalized = u.toString();
  } catch {
    return [];
  }

  const scored = new Map<string, number>();

  for (const a of homeDoc.anchors) {
    if (!a.resolvedHref || !/^https?:/i.test(a.resolvedHref)) continue;

    let parsed: URL;
    try {
      parsed = new URL(a.resolvedHref);
    } catch {
      continue;
    }

    if (parsed.origin !== homeOrigin) continue;
    parsed.hash = '';
    const cleanUrl = parsed.toString();
    if (cleanUrl === homeNormalized) continue;

    if (ASSET_EXTENSION_RE.test(parsed.pathname) || /\.pdf(?:[?#]|$)/i.test(parsed.pathname)) {
      continue;
    }

    const label = `${a.text} ${a.ariaLabel} ${a.title} ${parsed.pathname}`.toLowerCase();
    let score = 0;

    // Priority 1: Healthcare / Booking / Patient Intake / Telehealth subpages
    if (
      /\b(appointment|appointments|book[-_\s]*(?:now|online|appointment|consultation|visit)?|\bbook\b|intake|patient|schedule|telehealth|consultation)\b/i.test(
        label,
      )
    ) {
      score = Math.max(score, 100);
    }

    // Priority 2: Embedded Video / Watch / Webinar / Demo pages (VPPA triggers)
    if (/\b(videos?|watch|webinars?|demos?|tutorials?)\b/i.test(label)) {
      score = Math.max(score, 94);
    }

    // Priority 3: Privacy Policy / Your Privacy Choices / Do Not Sell (CIPA & CCPA disclosures)
    if (
      /\b(privacy[-_\s]*(?:policy|notice|choices|center)?|do[-_\s]*not[-_\s]*sell|cookie[-_\s]*policy|legal)\b/i.test(
        label,
      )
    ) {
      score = Math.max(score, 88);
    }

    // Priority 4: Contact / Support / Live Chat pages
    if (/\b(contact(?:-us)?|support|help|chat)\b/i.test(label)) {
      score = Math.max(score, 76);
    }

    if (score > 0) {
      if (a.inFooter || a.inNav) score += 4;
      const prev = scored.get(cleanUrl) ?? 0;
      if (score > prev) {
        scored.set(cleanUrl, score);
      }
    }
  }

  return Array.from(scored.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, maxPages)
    .map(([url]) => url);
}

/**
 * Core Check #1: CIPA §§ 631 & 632 / ECPA Session-Replay & Third-Party Live/AI Chat Wiretap Detection
 */
export function checkWiretapChatAndReplay(params: {
  pages: InspectedPageBundle[];
  detectedCmp: DetectedCmp;
  consentModeV2Detected: boolean;
  enabled: boolean;
}): WiretapChatAndReplayCheckResult {
  const { pages, detectedCmp, consentModeV2Detected, enabled } = params;

  if (!enabled) {
    return {
      checked: false,
      detectedCmp,
      consentModeV2Detected,
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
    };
  }

  const srAll = new Set<SessionReplayVendor>();
  const srUngated = new Set<SessionReplayVendor>();
  const srGated = new Set<SessionReplayVendor>();

  const chAll = new Set<ChatWidgetVendor>();
  const chUngated = new Set<ChatWidgetVendor>();
  const chGated = new Set<ChatWidgetVendor>();

  const wiretapEvidence: string[] = [];
  const recordingDisclosureSignals: string[] = [];
  const foundOnPages = new Set<string>();

  for (const bundle of pages) {
    const scan = scanSinglePageTrackers(bundle, consentModeV2Detected);
    for (const v of scan.sessionReplayAll) srAll.add(v);
    for (const v of scan.sessionReplayUngated) {
      srUngated.add(v);
      foundOnPages.add(bundle.finalUrl);
    }
    for (const v of scan.sessionReplayGated) srGated.add(v);

    for (const v of scan.chatAll) chAll.add(v);
    for (const v of scan.chatUngated) {
      chUngated.add(v);
      foundOnPages.add(bundle.finalUrl);
    }
    for (const v of scan.chatGated) chGated.add(v);

    for (const note of scan.evidenceNotes) {
      if (note.includes('session-replay') || note.includes('chat SDK')) {
        wiretapEvidence.push(note);
      }
    }

    const text = bundle.doc.visibleText;
    const discMatch = CHAT_RECORDING_DISCLOSURE_RE.exec(text);
    if (discMatch && discMatch.index !== undefined) {
      recordingDisclosureSignals.push(
        `Chat recording disclosure "${extractPhraseContext(text, discMatch.index, discMatch[0].length)}" on ${bundle.finalUrl}`,
      );
    }

    for (const cb of bundle.doc.checkboxes) {
      if (
        !cb.checked &&
        /\b(chat|record|transcrib|monitor|third[- ]party)\b/i.test(cb.associatedText) &&
        /\b(consent|agree)\b/i.test(cb.associatedText)
      ) {
        recordingDisclosureSignals.push(
          `Unchecked pre-chat consent checkbox (${cb.id || cb.name || 'checkbox'}) on ${bundle.finalUrl}`,
        );
      }
    }
  }

  // Ensure a vendor that appeared ungated anywhere is classified as ungated overall
  for (const v of srUngated) srGated.delete(v);
  for (const v of chUngated) chGated.delete(v);

  return {
    checked: true,
    detectedCmp,
    consentModeV2Detected,
    sessionReplayVendors: Array.from(srAll),
    ungatedSessionReplayVendors: Array.from(srUngated),
    gatedSessionReplayVendors: Array.from(srGated),
    chatWidgetVendors: Array.from(chAll),
    ungatedChatWidgetVendors: Array.from(chUngated),
    gatedChatWidgetVendors: Array.from(chGated),
    preChatRecordingDisclosureFound: recordingDisclosureSignals.length > 0,
    recordingDisclosureSignals: Array.from(new Set(recordingDisclosureSignals)).slice(0, 5),
    wiretapEvidence: Array.from(new Set(wiretapEvidence)).slice(0, 8),
    foundOnPages: Array.from(foundOnPages),
  };
}

/**
 * Core Check #2: VPPA (18 U.S.C. § 2710) Embedded Video + Ad-Pixel Co-Presence Check
 */
export function checkVppaVideoPixels(params: {
  pages: InspectedPageBundle[];
  consentModeV2Detected: boolean;
  enabled: boolean;
}): VppaVideoPixelCheckResult {
  const { pages, consentModeV2Detected, enabled } = params;

  const pxAll = new Set<AdPixelVendor>();
  const pxUngated = new Set<AdPixelVendor>();
  const pxGated = new Set<AdPixelVendor>();
  const vidAll = new Set<VideoProvider>();
  const vidUngated = new Set<VideoProvider>();

  let standaloneVideoConsentFound = false;
  let coPresentOnSamePage = false;
  const vppaEvidence: string[] = [];
  const foundOnPages = new Set<string>();

  for (const bundle of pages) {
    const scan = scanSinglePageTrackers(bundle, consentModeV2Detected);
    for (const p of scan.adPixelsAll) pxAll.add(p);
    for (const p of scan.adPixelsUngated) pxUngated.add(p);
    for (const p of scan.adPixelsGated) pxGated.add(p);
    for (const v of scan.videoAll) vidAll.add(v);
    for (const v of scan.videoUngated) vidUngated.add(v);

    if (STANDALONE_VPPA_CONSENT_RE.test(bundle.doc.visibleText)) {
      standaloneVideoConsentFound = true;
    }

    if (enabled && scan.videoUngated.size > 0 && scan.adPixelsUngated.size > 0) {
      coPresentOnSamePage = true;
      foundOnPages.add(bundle.finalUrl);
      vppaEvidence.push(
        `Embedded video (${Array.from(scan.videoUngated).join(', ')}) co-present on same page as ungated ad pixel(s) (${Array.from(scan.adPixelsUngated).join(', ')}) at ${bundle.finalUrl}`,
      );
    }
  }

  for (const p of pxUngated) pxGated.delete(p);

  if (!enabled) {
    return {
      checked: false,
      embeddedVideoProviders: Array.from(vidAll),
      ungatedVideoProviders: Array.from(vidUngated),
      adPixelVendors: Array.from(pxAll),
      ungatedAdPixelVendors: Array.from(pxUngated),
      gatedAdPixelVendors: Array.from(pxGated),
      standaloneVideoConsentFound: false,
      coPresentOnSamePage: false,
      vppaRiskFound: false,
      vppaEvidence: [],
      foundOnPages: [],
    };
  }

  const vppaRiskFound = coPresentOnSamePage && !standaloneVideoConsentFound;

  return {
    checked: true,
    embeddedVideoProviders: Array.from(vidAll),
    ungatedVideoProviders: Array.from(vidUngated),
    adPixelVendors: Array.from(pxAll),
    ungatedAdPixelVendors: Array.from(pxUngated),
    gatedAdPixelVendors: Array.from(pxGated),
    standaloneVideoConsentFound,
    coPresentOnSamePage,
    vppaRiskFound,
    vppaEvidence: Array.from(new Set(vppaEvidence)).slice(0, 6),
    foundOnPages: Array.from(foundOnPages),
  };
}

/**
 * Core Check #3: Healthcare & Sensitive Intake Form Pixel Exposure
 * (HIPAA 45 CFR § 164.502(e) & § 164.508 post-AHA v. Becerra, WA My Health My Data Act, & FTC Health Breach)
 */
export function checkSensitiveFormPixels(params: {
  pages: InspectedPageBundle[];
  healthcareOrWellnessContext: boolean;
  consentModeV2Detected: boolean;
  enabled: boolean;
}): SensitiveFormPixelCheckResult {
  const { pages, healthcareOrWellnessContext, consentModeV2Detected, enabled } = params;

  if (!enabled) {
    return {
      checked: false,
      healthcareOrWellnessContext,
      sensitiveIntakeFormFound: false,
      sensitiveFormPages: [],
      matchedSensitiveFields: [],
      ungatedTrackersOnFormPages: [],
      sensitiveFormPixelLeakFound: false,
      evidence: [],
    };
  }

  const sensitiveFormPages = new Set<string>();
  const matchedSensitiveFields = new Set<string>();
  const ungatedTrackersOnFormPages = new Set<string>();
  const evidence: string[] = [];

  for (const bundle of pages) {
    const { doc, finalUrl } = bundle;
    const pageRouteContext = `${finalUrl} ${doc.title ?? ''}`;
    const pageHasHealthContext =
      healthcareOrWellnessContext || HEALTHCARE_CONTEXT_RE.test(`${pageRouteContext} ${doc.visibleText}`);
    const isBookingOrIntakePage = BOOKING_ROUTE_OR_TITLE_RE.test(pageRouteContext);

    let pageHasSensitiveForm = false;

    for (const form of doc.forms) {
      const formMeta = `${form.id} ${form.className} ${form.action} ${form.buttonTexts.join(' ')} ${form.textSnippet}`;
      const hasClinicalField = form.sensitiveHealthFields.some((f) => STRICT_CLINICAL_FIELD_RE.test(f));
      const hasBookingFieldInHealthContext =
        pageHasHealthContext &&
        (form.sensitiveHealthFields.length > 0 ||
          (isBookingOrIntakePage && BOOKING_ROUTE_OR_TITLE_RE.test(formMeta)));

      if (hasClinicalField || hasBookingFieldInHealthContext) {
        pageHasSensitiveForm = true;
        sensitiveFormPages.add(finalUrl);
        for (const f of form.sensitiveHealthFields) {
          matchedSensitiveFields.add(f);
        }
      }
    }

    if (!pageHasSensitiveForm) continue;

    // Under HHS OCR HIPAA guidance (45 CFR §§ 164.502(e), 164.508 post-AHA v. Becerra),
    // generic CMP cookie banners do NOT constitute valid written HIPAA authorizations, and
    // consumer ad networks / session-replay clouds lack HIPAA BAAs on patient intake routes.
    const scan = scanSinglePageTrackers(bundle, consentModeV2Detected);
    const leakingTrackers = Array.from(
      new Set<string>([...scan.adPixelsAll, ...scan.sessionReplayAll]),
    );

    if (leakingTrackers.length > 0) {
      for (const t of leakingTrackers) {
        ungatedTrackersOnFormPages.add(t);
      }
      const fieldSummary =
        Array.from(matchedSensitiveFields).slice(0, 4).join(', ') || 'appointment/intake inputs';
      evidence.push(
        `Non-BAA tracker(s) [${leakingTrackers.join(', ')}] present on sensitive intake/booking form page ${finalUrl} collecting [${fieldSummary}] (cookie banners do not satisfy HIPAA § 164.508 authorization)`,
      );
    }
  }

  return {
    checked: true,
    healthcareOrWellnessContext,
    sensitiveIntakeFormFound: sensitiveFormPages.size > 0,
    sensitiveFormPages: Array.from(sensitiveFormPages),
    matchedSensitiveFields: Array.from(matchedSensitiveFields).slice(0, 10),
    ungatedTrackersOnFormPages: Array.from(ungatedTrackersOnFormPages),
    sensitiveFormPixelLeakFound: ungatedTrackersOnFormPages.size > 0,
    evidence: Array.from(new Set(evidence)).slice(0, 6),
  };
}

/**
 * Core Check #4: CCPA/CPRA Global Privacy Control (`/.well-known/gpc.json`) & "Your Privacy Choices" Opt-Out Link
 */
export function evaluateGpcAndOptOut(params: {
  pages: InspectedPageBundle[];
  adPixelVendors: AdPixelVendor[];
  gpcProbe: GpcWellKnownProbe;
  enabled: boolean;
}): GpcAndOptOutCheckResult {
  const { pages, adPixelVendors, gpcProbe, enabled } = params;
  const adTrackersPresent = adPixelVendors.length > 0;

  if (!enabled) {
    return {
      checked: false,
      adTrackersPresent,
      gpcEndpointUrl: gpcProbe.endpointUrl,
      gpcHttpStatus: gpcProbe.httpStatus,
      gpcWellKnownFound: false,
      gpcSupportDeclared: false,
      clientGpcListenerDetected: false,
      ccpaPrivacyChoicesLinkFound: false,
      optOutLinkLabel: null,
      optOutUrl: null,
      gpcOrOptOutRiskFound: false,
      evidence: [],
    };
  }

  let ccpaPrivacyChoicesLinkFound = false;
  let optOutLinkLabel: string | null = null;
  let optOutUrl: string | null = null;
  let clientGpcListenerDetected = false;
  const evidence: string[] = [];

  for (const { doc, finalUrl } of pages) {
    for (const s of doc.scripts) {
      if (CLIENT_GPC_SCRIPT_RE.test(s.inlineCode)) {
        clientGpcListenerDetected = true;
      }
    }

    for (const a of doc.anchors) {
      const combined = `${a.text} ${a.ariaLabel} ${a.title} ${a.href}`;
      if (CCPA_PRIVACY_CHOICES_RE.test(combined)) {
        ccpaPrivacyChoicesLinkFound = true;
        optOutLinkLabel = optOutLinkLabel ?? (a.text || a.ariaLabel || 'Your Privacy Choices');
        optOutUrl = optOutUrl ?? (a.resolvedHref || finalUrl);
      }
    }

    for (const ctrl of doc.controls) {
      const combined = `${ctrl.text} ${ctrl.ariaLabel} ${ctrl.className} ${ctrl.id}`;
      if (
        CCPA_PRIVACY_CHOICES_RE.test(combined) ||
        (/\boptanon-show-settings\b/i.test(combined) && /\bprivacy\s+choices|do\s+not\s+sell\b/i.test(combined))
      ) {
        ccpaPrivacyChoicesLinkFound = true;
        optOutLinkLabel = optOutLinkLabel ?? (ctrl.text || ctrl.ariaLabel || 'Your Privacy Choices');
        optOutUrl = optOutUrl ?? finalUrl;
      }
    }
  }

  if (gpcProbe.gpcSupportDeclared) {
    evidence.push(`/.well-known/gpc.json returned HTTP 200 with {"gpc": true} (${gpcProbe.endpointUrl})`);
  } else if (adTrackersPresent) {
    evidence.push(
      `/.well-known/gpc.json did not declare {"gpc": true} (HTTP ${gpcProbe.httpStatus ?? 'unreachable'}) while ad pixels [${adPixelVendors.join(', ')}] are present`,
    );
  }

  if (ccpaPrivacyChoicesLinkFound) {
    evidence.push(`Detected CCPA opt-out control "${optOutLinkLabel}" (${optOutUrl})`);
  } else if (adTrackersPresent) {
    evidence.push(
      `No "Your Privacy Choices" or "Do Not Sell or Share My Personal Information" link found while ad pixels [${adPixelVendors.join(', ')}] are present`,
    );
  }

  const missingOptOut = adTrackersPresent && !ccpaPrivacyChoicesLinkFound;
  const missingGpc = adTrackersPresent && !gpcProbe.gpcSupportDeclared && !clientGpcListenerDetected;

  return {
    checked: true,
    adTrackersPresent,
    gpcEndpointUrl: gpcProbe.endpointUrl,
    gpcHttpStatus: gpcProbe.httpStatus,
    gpcWellKnownFound: gpcProbe.wellKnownFound,
    gpcSupportDeclared: gpcProbe.gpcSupportDeclared,
    clientGpcListenerDetected,
    ccpaPrivacyChoicesLinkFound,
    optOutLinkLabel,
    optOutUrl,
    gpcOrOptOutRiskFound: missingOptOut || missingGpc,
    evidence,
  };
}
