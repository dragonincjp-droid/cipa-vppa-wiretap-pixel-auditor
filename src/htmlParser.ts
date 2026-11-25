import type {
  ParsedAnchor,
  ParsedCheckbox,
  ParsedControl,
  ParsedForm,
  ParsedHtmlDocument,
  ParsedIframeTag,
  ParsedScriptTag,
  ParsedVideoElement,
} from './types.js';

const NAMED_HTML_ENTITIES: Record<string, string> = {
  amp: '&',
  lt: '<',
  gt: '>',
  quot: '"',
  apos: "'",
  nbsp: ' ',
  euro: '€',
  pound: '£',
  copy: '©',
  reg: '®',
  sect: '§',
  ndash: '–',
  mdash: '—',
  laquo: '«',
  raquo: '»',
};

export function decodeHtmlEntities(input: string): string {
  if (!input || !input.includes('&')) return input;
  return input.replace(/&(#x[0-9a-fA-F]+|#\d+|[a-zA-Z0-9]+);/g, (full, entity: string) => {
    if (entity.startsWith('#x') || entity.startsWith('#X')) {
      const code = parseInt(entity.slice(2), 16);
      if (!Number.isNaN(code) && code > 0 && code <= 0x10ffff) {
        try {
          return String.fromCodePoint(code);
        } catch {
          return full;
        }
      }
      return full;
    }
    if (entity.startsWith('#')) {
      const code = parseInt(entity.slice(1), 10);
      if (!Number.isNaN(code) && code > 0 && code <= 0x10ffff) {
        try {
          return String.fromCodePoint(code);
        } catch {
          return full;
        }
      }
      return full;
    }
    return NAMED_HTML_ENTITIES[entity] ?? full;
  });
}

function getAttr(attrString: string, attrName: string): string {
  if (!attrString) return '';
  const escaped = attrName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const regex = new RegExp(
    `(?:^|\\s)${escaped}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>` + '`' + `]+))`,
    'i',
  );
  const match = regex.exec(attrString);
  if (!match) return '';
  const raw = match[1] ?? match[2] ?? match[3] ?? '';
  return decodeHtmlEntities(raw).trim();
}

function hasBooleanAttr(attrString: string, attrName: string): boolean {
  if (!attrString) return false;
  const escaped = attrName.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const re = new RegExp(
    `(?:^|\\s)${escaped}(?:\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s"'=<>` + '`' + `]+)))?(?=\\s|$|\\/)`,
    'i',
  );
  const match = re.exec(attrString);
  if (!match) return false;
  const explicitVal = (match[1] ?? match[2] ?? match[3] ?? '').trim().toLowerCase();
  if (explicitVal === 'false' || explicitVal === '0' || explicitVal === 'no') {
    return false;
  }
  return true;
}

function extractDataAttributesSummary(attrString: string): string {
  if (!attrString) return '';
  const matches: string[] = [];
  const re = /\b(data-[a-zA-Z0-9_-]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+)))?/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(attrString)) !== null) {
    const key = m[1].toLowerCase();
    const val = decodeHtmlEntities(m[2] ?? m[3] ?? m[4] ?? '').slice(0, 120);
    matches.push(val ? `${key}="${val}"` : key);
    if (matches.length >= 12) break;
  }
  return matches.join(' ');
}

function stripTagsPreserveAlt(htmlFragment: string): string {
  if (!htmlFragment) return '';
  const withImgAlt = htmlFragment.replace(/<img\b([^>]*)>/gi, (_m, attrs: string) => {
    const alt = getAttr(attrs, 'alt');
    return alt ? ` ${alt} ` : ' ';
  });
  const withoutTags = withImgAlt.replace(/<[^>]+>/g, ' ');
  return decodeHtmlEntities(withoutTags).replace(/\s+/g, ' ').trim();
}

function safeResolveUrl(rawHref: string, baseUrl: string): string {
  const trimmed = rawHref.trim();
  if (!trimmed) return '';
  if (/^(?:javascript|mailto|tel|data|about):/i.test(trimmed)) {
    return trimmed;
  }
  try {
    return new URL(trimmed, baseUrl).toString();
  } catch {
    return trimmed;
  }
}

function findRegionRanges(html: string, tagName: string): Array<[number, number]> {
  const ranges: Array<[number, number]> = [];
  const re = new RegExp(`<${tagName}\\b[^>]*>[\\s\\S]*?<\\/${tagName}>`, 'gi');
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    ranges.push([m.index, m.index + m[0].length]);
    if (ranges.length >= 25) break;
  }
  return ranges;
}

function isIndexInRanges(idx: number, ranges: Array<[number, number]>): boolean {
  for (const [start, end] of ranges) {
    if (idx >= start && idx <= end) return true;
  }
  return false;
}

const BLOCKED_SCRIPT_MIME_TYPES = new Set([
  'text/plain',
  'application/x-cookieconsent',
  'text/x-cookie-consent',
  'text/javascript-blocked',
  'javascript/blocked',
  'text/template',
]);

/**
 * Evaluates whether a `<script>` tag is blocked from firing prior to user opt-in consent
 * (e.g., OneTrust `type="text/plain" class="optanon-category-C0004"`, Cookiebot `data-cookieconsent`,
 * Usercentrics `data-usercentrics`, Complianz/Termly/Osano/custom consent gate, or inline consent callbacks).
 */
function classifyScriptGating(params: {
  src: string;
  dataSrc: string;
  type: string;
  className: string;
  attrs: string;
  inlineCode: string;
}): { isConsentGated: boolean; gatingMechanism: string | null } {
  const { src, dataSrc, type, className, attrs, inlineCode } = params;
  const lowerType = type.toLowerCase();
  const lowerClass = className.toLowerCase();
  const cookieConsentAttr = getAttr(attrs, 'data-cookieconsent').toLowerCase();
  const usercentricsAttr = getAttr(attrs, 'data-usercentrics');

  if (BLOCKED_SCRIPT_MIME_TYPES.has(lowerType)) {
    if (/optanon-category-[a-z0-9_-]+/i.test(className)) {
      return { isConsentGated: true, gatingMechanism: `type="${lowerType}" + OneTrust optanon-category` };
    }
    if (usercentricsAttr) {
      return { isConsentGated: true, gatingMechanism: `type="${lowerType}" + data-usercentrics` };
    }
    if (cookieConsentAttr && cookieConsentAttr !== 'ignore') {
      return { isConsentGated: true, gatingMechanism: `type="${lowerType}" + data-cookieconsent="${cookieConsentAttr}"` };
    }
    return { isConsentGated: true, gatingMechanism: `type="${lowerType}" script block` };
  }

  if (cookieConsentAttr && cookieConsentAttr !== 'ignore' && cookieConsentAttr !== 'necessary') {
    return { isConsentGated: true, gatingMechanism: `Cookiebot data-cookieconsent="${cookieConsentAttr}"` };
  }

  if (/\boptanon-category-(?!c0001\b)[a-z0-9_-]+/i.test(lowerClass)) {
    return { isConsentGated: true, gatingMechanism: `OneTrust class="${className}"` };
  }

  if (usercentricsAttr) {
    return { isConsentGated: true, gatingMechanism: `Usercentrics data-usercentrics="${usercentricsAttr}"` };
  }

  if (
    /\b(?:data-cmplz|cmplz-script|data-termly-category|data-consent-category|data-cookiecategory|data-cipa-consent-category|data-iub-purposes)\b/i.test(
      attrs,
    )
  ) {
    return { isConsentGated: true, gatingMechanism: 'CMP data-consent category attribute' };
  }

  if (!src && dataSrc) {
    return { isConsentGated: true, gatingMechanism: 'Deferred data-src without eager src' };
  }

  if (
    inlineCode &&
    /\b(?:OneTrust\.OnConsentChanged|OnetrustActiveGroups\.includes|CookiebotOnAccept|Cookiebot\.consent\.(?:marketing|statistics)|UC_UI\.areAllConsentsAccepted|window\.__cipaConsentGranted\s*===\s*true|cipaConsentAccepted)\b/.test(
      inlineCode,
    )
  ) {
    return { isConsentGated: true, gatingMechanism: 'Inline CMP consent-event listener gate' };
  }

  return { isConsentGated: false, gatingMechanism: null };
}

function classifyIframeGating(params: {
  src: string;
  dataSrc: string;
  className: string;
  attrs: string;
}): boolean {
  const { src, dataSrc, className, attrs } = params;
  const cleanSrc = src.trim().toLowerCase();
  const hasDeferredSrc = Boolean(dataSrc) && (!cleanSrc || cleanSrc === 'about:blank');

  if (hasDeferredSrc) return true;
  const cookieConsent = getAttr(attrs, 'data-cookieconsent').toLowerCase();
  if (cookieConsent && cookieConsent !== 'ignore' && cookieConsent !== 'necessary') {
    return true;
  }
  if (/\boptanon-category-(?!c0001\b)[a-z0-9_-]+/i.test(className)) {
    return true;
  }
  if (
    /\b(?:data-cookieblock-src|data-usercentrics|data-cmplz-target|data-cipa-consent-category)\b/i.test(
      attrs,
    )
  ) {
    return true;
  }
  return false;
}

const SENSITIVE_HEALTH_FIELD_RE =
  /\b(patient|symptom|symptoms|diagnosis|condition|medication|medications|prescription|insurance|member[-_ ]?id|group[-_ ]?number|provider|doctor|physician|clinician|therapist|treatment|telehealth|appointment|visit[-_ ]?(?:reason|type|date)|reason[-_ ]?for[-_ ]?visit|chief[-_ ]?complaint|medical[-_ ]?history|mental[-_ ]?health|dob|date[-_ ]?of[-_ ]?birth|health[-_ ]?concern)\b/i;

export function parseHtmlDocument(rawHtml: string, pageUrl: string): ParsedHtmlDocument {
  const html = rawHtml || '';

  // 1. Remove HTML comments first
  const uncommented = html.replace(/<!--[\s\S]*?-->/g, ' ');

  // 2. <html lang="..."> & <title>
  let htmlLang: string | null = null;
  const htmlTagMatch = /<html\b([^>]*)>/i.exec(uncommented);
  if (htmlTagMatch) {
    const rawLang = getAttr(htmlTagMatch[1], 'lang');
    if (rawLang) {
      htmlLang = rawLang.split(/[-_]/)[0].toLowerCase();
    }
  }

  let title: string | null = null;
  const titleMatch = /<title\b[^>]*>([\s\S]*?)<\/title>/i.exec(uncommented);
  if (titleMatch) {
    const cleanTitle = decodeHtmlEntities(titleMatch[1]).replace(/\s+/g, ' ').trim();
    title = cleanTitle || null;
  }

  // 3. Extract <script> tags (with full consent-gating metadata), URLs, inline scripts, and JSON-LD blocks
  const scripts: ParsedScriptTag[] = [];
  const scriptUrls: string[] = [];
  const inlineScripts: string[] = [];
  const jsonLdBlocks: unknown[] = [];

  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let scriptMatch: RegExpExecArray | null;
  while ((scriptMatch = scriptRe.exec(uncommented)) !== null) {
    const attrs = scriptMatch[1] || '';
    const body = (scriptMatch[2] || '').trim();
    const src = getAttr(attrs, 'src') || getAttr(attrs, 'data-lazy-src');
    const dataSrc =
      getAttr(attrs, 'data-src') ||
      getAttr(attrs, 'data-cookieblock-src');
    const type = getAttr(attrs, 'type').toLowerCase();
    const id = getAttr(attrs, 'id');
    const className = getAttr(attrs, 'class');
    const resolvedSrc = src ? safeResolveUrl(src, pageUrl) : '';
    const resolvedDataSrc = dataSrc ? safeResolveUrl(dataSrc, pageUrl) : '';

    if (type === 'application/ld+json') {
      if (body && jsonLdBlocks.length < 25) {
        try {
          jsonLdBlocks.push(JSON.parse(body));
        } catch {
          // Ignore invalid JSON-LD blocks
        }
      }
      continue;
    }

    const inlineSnippet = body.slice(0, 8_000);
    const gating = classifyScriptGating({
      src,
      dataSrc,
      type,
      className,
      attrs,
      inlineCode: inlineSnippet,
    });

    if (scripts.length < 200) {
      scripts.push({
        src,
        resolvedSrc,
        dataSrc,
        resolvedDataSrc,
        type,
        id,
        className,
        dataAttributes: extractDataAttributesSummary(attrs),
        rawAttrs: attrs.slice(0, 600),
        inlineCode: inlineSnippet,
        isConsentGated: gating.isConsentGated,
        gatingMechanism: gating.gatingMechanism,
      });
    }

    const effectiveUrl = resolvedSrc || resolvedDataSrc;
    if (effectiveUrl && scriptUrls.length < 200) {
      scriptUrls.push(effectiveUrl);
    }
    if (!src && !dataSrc && inlineSnippet && inlineScripts.length < 60) {
      inlineScripts.push(inlineSnippet);
    }
  }

  // 4. Extract <link> stylesheet/resource URLs
  const stylesheetUrls: string[] = [];
  const linkRe = /<link\b([^>]*)>/gi;
  let linkMatch: RegExpExecArray | null;
  while ((linkMatch = linkRe.exec(uncommented)) !== null) {
    const href = getAttr(linkMatch[1], 'href');
    if (href && stylesheetUrls.length < 100) {
      stylesheetUrls.push(safeResolveUrl(href, pageUrl));
    }
  }

  // 5. Strip <script>, <style>, and <noscript> for active DOM inspection
  const domHtml = uncommented
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, ' ')
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, ' ')
    .replace(/<noscript\b[^>]*>[\s\S]*?<\/noscript>/gi, ' ');

  // 6. Extract <iframe> elements (for embedded video players & chat frames)
  const iframes: ParsedIframeTag[] = [];
  const iframeRe = /<iframe\b([^>]*)>/gi;
  let iframeMatch: RegExpExecArray | null;
  while ((iframeMatch = iframeRe.exec(domHtml)) !== null) {
    if (iframes.length >= 60) break;
    const attrs = iframeMatch[1] || '';
    const src = getAttr(attrs, 'src') || getAttr(attrs, 'data-lazy-src');
    const dataSrc =
      getAttr(attrs, 'data-src') ||
      getAttr(attrs, 'data-cookieblock-src');
    const className = getAttr(attrs, 'class');
    iframes.push({
      src,
      resolvedSrc: src ? safeResolveUrl(src, pageUrl) : '',
      dataSrc,
      resolvedDataSrc: dataSrc ? safeResolveUrl(dataSrc, pageUrl) : '',
      title: getAttr(attrs, 'title').slice(0, 200),
      id: getAttr(attrs, 'id'),
      className,
      dataAttributes: extractDataAttributesSummary(attrs),
      rawAttrs: attrs.slice(0, 600),
      isConsentGated: classifyIframeGating({ src, dataSrc, className, attrs }),
    });
  }

  // 7. Extract HTML5 <video> elements (and nested <source src="...">), skipping silent ambient background loops
  const videos: ParsedVideoElement[] = [];
  const videoRe = /<video\b([^>]*)>([\s\S]*?)<\/video>/gi;
  let videoMatch: RegExpExecArray | null;
  while ((videoMatch = videoRe.exec(domHtml)) !== null) {
    if (videos.length >= 40) break;
    const attrs = videoMatch[1] || '';
    const inner = videoMatch[2] || '';
    const isDecorativeBackgroundLoop =
      hasBooleanAttr(attrs, 'autoplay') &&
      hasBooleanAttr(attrs, 'muted') &&
      hasBooleanAttr(attrs, 'loop') &&
      !hasBooleanAttr(attrs, 'controls');
    if (isDecorativeBackgroundLoop) {
      continue;
    }
    let src = getAttr(attrs, 'src') || getAttr(attrs, 'data-lazy-src');
    if (!src) {
      const srcTag = /<source\b([^>]*)>/i.exec(inner);
      if (srcTag) {
        src = getAttr(srcTag[1] || '', 'src') || getAttr(srcTag[1] || '', 'data-lazy-src');
      }
    }
    videos.push({
      src,
      resolvedSrc: src ? safeResolveUrl(src, pageUrl) : '',
      poster: getAttr(attrs, 'poster'),
      id: getAttr(attrs, 'id'),
      className: getAttr(attrs, 'class'),
      dataAttributes: extractDataAttributesSummary(attrs),
    });
  }

  // 8. Extract active <img> beacon URLs (outside <noscript>)
  const pixelImgUrls: string[] = [];
  const imgRe = /<img\b([^>]*)>/gi;
  let imgMatch: RegExpExecArray | null;
  while ((imgMatch = imgRe.exec(domHtml)) !== null) {
    if (pixelImgUrls.length >= 150) break;
    const src = getAttr(imgMatch[1] || '', 'src');
    if (src) {
      pixelImgUrls.push(safeResolveUrl(src, pageUrl));
    }
  }

  const footerRanges = findRegionRanges(domHtml, 'footer');
  const navRanges = [
    ...findRegionRanges(domHtml, 'nav'),
    ...findRegionRanges(domHtml, 'header'),
  ];

  // Build <label for="..."> map
  const labelByForId = new Map<string, string>();
  const labelRe = /<label\b([^>]*)>([\s\S]*?)<\/label>/gi;
  let lblMatch: RegExpExecArray | null;
  while ((lblMatch = labelRe.exec(domHtml)) !== null) {
    const forId = getAttr(lblMatch[1] || '', 'for');
    if (forId && !labelByForId.has(forId)) {
      labelByForId.set(forId, stripTagsPreserveAlt(lblMatch[2] || '').slice(0, 320));
    }
  }

  // 9. Extract <a ...>...</a> anchors
  const anchors: ParsedAnchor[] = [];
  const anchorRe = /<a\b([^>]*)>([\s\S]*?)<\/a>/gi;
  let anchorMatch: RegExpExecArray | null;
  while ((anchorMatch = anchorRe.exec(domHtml)) !== null) {
    if (anchors.length >= 500) break;
    const attrs = anchorMatch[1] || '';
    const inner = anchorMatch[2] || '';
    const href = getAttr(attrs, 'href');
    const resolvedHref = href ? safeResolveUrl(href, pageUrl) : '';
    const text = stripTagsPreserveAlt(inner).slice(0, 240);
    const ariaLabel = getAttr(attrs, 'aria-label').slice(0, 200);
    const anchorTitle = getAttr(attrs, 'title').slice(0, 200);
    const id = getAttr(attrs, 'id');
    const className = getAttr(attrs, 'class');

    anchors.push({
      href,
      resolvedHref,
      text,
      ariaLabel,
      title: anchorTitle,
      id,
      className,
      inFooter: isIndexInRanges(anchorMatch.index, footerRanges),
      inNav: isIndexInRanges(anchorMatch.index, navRanges),
    });
  }

  // 10. Extract interactive <button>, <input>, and checkbox controls
  const controls: ParsedControl[] = [];
  const checkboxes: ParsedCheckbox[] = [];

  const buttonRe = /<button\b([^>]*)>([\s\S]*?)<\/button>/gi;
  let btnMatch: RegExpExecArray | null;
  while ((btnMatch = buttonRe.exec(domHtml)) !== null) {
    if (controls.length >= 250) break;
    const attrs = btnMatch[1] || '';
    controls.push({
      tag: 'button',
      type: getAttr(attrs, 'type').toLowerCase() || 'submit',
      text: stripTagsPreserveAlt(btnMatch[2] || '').slice(0, 240),
      ariaLabel: getAttr(attrs, 'aria-label').slice(0, 200),
      id: getAttr(attrs, 'id'),
      className: getAttr(attrs, 'class'),
      name: getAttr(attrs, 'name'),
      dataAttributes: extractDataAttributesSummary(attrs),
    });
  }

  const inputTagRe = /<input\b([^>]*)>/gi;
  let inpMatch: RegExpExecArray | null;
  while ((inpMatch = inputTagRe.exec(domHtml)) !== null) {
    const attrs = inpMatch[1] || '';
    const inpType = (getAttr(attrs, 'type') || 'text').toLowerCase();

    if ((inpType === 'submit' || inpType === 'button') && controls.length < 300) {
      controls.push({
        tag: 'input',
        type: inpType,
        text: getAttr(attrs, 'value').slice(0, 240),
        ariaLabel: getAttr(attrs, 'aria-label').slice(0, 200),
        id: getAttr(attrs, 'id'),
        className: getAttr(attrs, 'class'),
        name: getAttr(attrs, 'name'),
        dataAttributes: extractDataAttributesSummary(attrs),
      });
    } else if (inpType === 'checkbox' && checkboxes.length < 100) {
      const id = getAttr(attrs, 'id');
      const name = getAttr(attrs, 'name');
      const className = getAttr(attrs, 'class');
      const value = getAttr(attrs, 'value');
      const ariaLabel = getAttr(attrs, 'aria-label');
      const checked =
        hasBooleanAttr(attrs, 'checked') ||
        hasBooleanAttr(attrs, 'defaultChecked') ||
        getAttr(attrs, 'aria-checked').toLowerCase() === 'true';
      const required =
        hasBooleanAttr(attrs, 'required') ||
        getAttr(attrs, 'aria-required').toLowerCase() === 'true';

      const explicitLabel = id ? labelByForId.get(id) ?? '' : '';
      const windowStart = Math.max(0, inpMatch.index - 140);
      const windowEnd = Math.min(domHtml.length, inpMatch.index + inpMatch[0].length + 340);
      const nearbyText = stripTagsPreserveAlt(domHtml.slice(windowStart, windowEnd)).slice(0, 360);
      const associatedText = `${explicitLabel} ${ariaLabel} ${nearbyText}`.replace(/\s+/g, ' ').trim();

      checkboxes.push({
        id,
        name,
        className,
        value,
        checked,
        required,
        associatedText,
      });
    }
  }

  const roleBtnRe =
    /<(?:div|span|label|summary)\b([^>]*\brole\s*=\s*["']button["'][^>]*)>([\s\S]*?)<\/(?:div|span|label|summary)>/gi;
  let roleMatch: RegExpExecArray | null;
  while ((roleMatch = roleBtnRe.exec(domHtml)) !== null) {
    if (controls.length >= 350) break;
    const attrs = roleMatch[1] || '';
    controls.push({
      tag: 'role-button',
      type: 'button',
      text: stripTagsPreserveAlt(roleMatch[2] || '').slice(0, 240),
      ariaLabel: getAttr(attrs, 'aria-label').slice(0, 200),
      id: getAttr(attrs, 'id'),
      className: getAttr(attrs, 'class'),
      name: getAttr(attrs, 'name'),
      dataAttributes: extractDataAttributesSummary(attrs),
    });
  }

  // 11. Extract <form> elements with sensitive health/appointment field detection
  const forms: ParsedForm[] = [];
  const formRe = /<form\b([^>]*)>([\s\S]*?)<\/form>/gi;
  let formMatch: RegExpExecArray | null;
  while ((formMatch = formRe.exec(domHtml)) !== null) {
    if (forms.length >= 50) break;
    const attrs = formMatch[1] || '';
    const inner = formMatch[2] || '';
    const action = getAttr(attrs, 'action');
    const resolvedAction = action ? safeResolveUrl(action, pageUrl) : pageUrl;
    const method = (getAttr(attrs, 'method') || 'get').toLowerCase();
    const id = getAttr(attrs, 'id');
    const className = getAttr(attrs, 'class');

    const inputNamesAndTypes: string[] = [];
    const sensitiveHealthFields: string[] = [];

    const fieldRe = /<(input|select|textarea)\b([^>]*)>/gi;
    let fm: RegExpExecArray | null;
    while ((fm = fieldRe.exec(inner)) !== null) {
      const tag = fm[1].toLowerCase();
      const fAttrs = fm[2] || '';
      const fType = (getAttr(fAttrs, 'type') || (tag === 'input' ? 'text' : tag)).toLowerCase();
      if (fType === 'hidden' || fType === 'submit' || fType === 'button') {
        continue;
      }
      const fName = getAttr(fAttrs, 'name');
      const fId = getAttr(fAttrs, 'id');
      const fPlaceholder = getAttr(fAttrs, 'placeholder');
      const fAria = getAttr(fAttrs, 'aria-label');
      const fLabel = fId ? labelByForId.get(fId) ?? '' : '';
      const combined = `${fName} ${fId} ${fPlaceholder} ${fAria} ${fLabel}`;

      const ident = fName || fId || fPlaceholder || fLabel || 'field';
      inputNamesAndTypes.push(`${ident.slice(0, 60)}:${fType}`);

      const sensitiveMatch = SENSITIVE_HEALTH_FIELD_RE.exec(combined);
      if (sensitiveMatch) {
        const token = `${ident.slice(0, 48)} (${sensitiveMatch[1].toLowerCase()})`;
        if (!sensitiveHealthFields.includes(token) && sensitiveHealthFields.length < 15) {
          sensitiveHealthFields.push(token);
        }
      }
    }

    const buttonTexts: string[] = [];
    const innerBtnRe = /<button\b([^>]*)>([\s\S]*?)<\/button>/gi;
    let ibm: RegExpExecArray | null;
    while ((ibm = innerBtnRe.exec(inner)) !== null) {
      const t = stripTagsPreserveAlt(ibm[2] || '') || getAttr(ibm[1] || '', 'aria-label');
      if (t) buttonTexts.push(t.slice(0, 160));
    }
    const innerSubRe = /<input\b([^>]*)>/gi;
    let ism: RegExpExecArray | null;
    while ((ism = innerSubRe.exec(inner)) !== null) {
      const tType = getAttr(ism[1] || '', 'type').toLowerCase();
      if (tType === 'submit' || tType === 'button') {
        const val = getAttr(ism[1] || '', 'value');
        if (val) buttonTexts.push(val.slice(0, 160));
      }
    }

    forms.push({
      action,
      resolvedAction,
      method,
      id,
      className,
      inputNamesAndTypes,
      sensitiveHealthFields,
      buttonTexts,
      textSnippet: stripTagsPreserveAlt(inner).slice(0, 500),
    });
  }

  // 12. Clean visible text (strip remaining SVG bodies, keep img[alt])
  const withoutSvg = domHtml.replace(/<svg\b[^>]*>[\s\S]*?<\/svg>/gi, ' ');
  const visibleText = stripTagsPreserveAlt(withoutSvg);

  return {
    url: pageUrl,
    title,
    htmlLang,
    rawHtml: html,
    visibleText,
    scripts,
    scriptUrls,
    inlineScripts,
    iframes,
    videos,
    pixelImgUrls,
    stylesheetUrls,
    jsonLdBlocks,
    anchors,
    controls,
    checkboxes,
    forms,
  };
}
