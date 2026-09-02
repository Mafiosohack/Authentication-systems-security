const fs = require("fs");
const {
  Document, Packer, Paragraph, TextRun, Table, TableRow, TableCell,
  AlignmentType, LevelFormat, TableOfContents, HeadingLevel, BorderStyle,
  WidthType, ShadingType, PageNumber, Header, Footer, PageBreak
} = require("docx");

const BLUE = "2E75B6", DARK = "1F3864", GREY = "595959", LIGHT = "D5E8F0",
      REDBG = "FCE4E4", GRNBG = "E2EFDA", CODEBG = "F2F2F2";
const CW = 9360; // content width, US Letter, 1" margins

const H1 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_1, children: [new TextRun(t)] });
const H2 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_2, children: [new TextRun(t)] });
const H3 = (t) => new Paragraph({ heading: HeadingLevel.HEADING_3, children: [new TextRun(t)] });
const P  = (t, o = {}) => new Paragraph({ spacing: { after: 120 }, children: [new TextRun({ text: t, ...o })] });
const bullet = (t) => new Paragraph({ numbering: { reference: "b", level: 0 }, spacing: { after: 60 }, children: textRuns(t) });

// allow **bold** inline
function textRuns(t) {
  const parts = t.split(/(\*\*[^*]+\*\*)/g).filter(Boolean);
  return parts.map(p => p.startsWith("**") && p.endsWith("**")
    ? new TextRun({ text: p.slice(2, -2), bold: true })
    : new TextRun(p));
}
function para(t, o = {}) { return new Paragraph({ spacing: { after: 120 }, children: textRuns(t), ...o }); }

function code(lines) {
  return new Table({
    width: { size: CW, type: WidthType.DXA }, columnWidths: [CW],
    rows: [new TableRow({ children: [new TableCell({
      width: { size: CW, type: WidthType.DXA },
      shading: { fill: CODEBG, type: ShadingType.CLEAR },
      borders: { top:{style:BorderStyle.SINGLE,size:1,color:"BBBBBB"}, bottom:{style:BorderStyle.SINGLE,size:1,color:"BBBBBB"},
                 left:{style:BorderStyle.SINGLE,size:1,color:"BBBBBB"}, right:{style:BorderStyle.SINGLE,size:1,color:"BBBBBB"} },
      margins: { top: 100, bottom: 100, left: 140, right: 140 },
      children: lines.map(l => new Paragraph({ spacing: { after: 0 },
        children: [new TextRun({ text: l || " ", font: "Consolas", size: 17 })] }))
    })] })]
  });
}

function callout(label, body, fill) {
  return new Table({
    width: { size: CW, type: WidthType.DXA }, columnWidths: [CW],
    rows: [new TableRow({ children: [new TableCell({
      width: { size: CW, type: WidthType.DXA },
      shading: { fill, type: ShadingType.CLEAR },
      borders: { left: { style: BorderStyle.SINGLE, size: 18, color: fill === REDBG ? "C00000" : (fill===GRNBG?"548235":BLUE) },
                 top:{style:BorderStyle.NONE}, bottom:{style:BorderStyle.NONE}, right:{style:BorderStyle.NONE} },
      margins: { top: 100, bottom: 100, left: 160, right: 140 },
      children: [ new Paragraph({ spacing: { after: 40 }, children: [new TextRun({ text: label, bold: true, size: 19 })] }),
                  ...(Array.isArray(body) ? body : [body]).map(b => new Paragraph({ spacing:{after:0}, children: textRuns(b) })) ]
    })] })]
  });
}

function tbl(headers, rows, widths) {
  const hcells = headers.map((h, i) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA },
    shading: { fill: DARK, type: ShadingType.CLEAR },
    margins: { top: 80, bottom: 80, left: 120, right: 120 },
    children: [new Paragraph({ children: [new TextRun({ text: h, bold: true, color: "FFFFFF", size: 19 })] })]
  }));
  const bord = { style: BorderStyle.SINGLE, size: 1, color: "CCCCCC" };
  const brd = { top: bord, bottom: bord, left: bord, right: bord };
  const dataRows = rows.map((r, ri) => new TableRow({ children: r.map((c, i) => new TableCell({
    width: { size: widths[i], type: WidthType.DXA }, borders: brd,
    shading: { fill: ri % 2 ? "FFFFFF" : "F2F6FB", type: ShadingType.CLEAR },
    margins: { top: 70, bottom: 70, left: 120, right: 120 },
    children: [new Paragraph({ children: textRuns(String(c)) })]
  })) }));
  return new Table({ width: { size: CW, type: WidthType.DXA }, columnWidths: widths,
    rows: [new TableRow({ tableHeader: true, children: hcells }), ...dataRows] });
}

const spacer = (n=120) => new Paragraph({ spacing: { after: n }, children: [new TextRun("")] });

// ---------------------------------------------------------------- title page
const titlePage = [
  new Paragraph({ spacing: { before: 1800, after: 0 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "Authentication Security Study Series", size: 26, color: GREY, bold: true })] }),
  new Paragraph({ spacing: { before: 80, after: 0 }, alignment: AlignmentType.CENTER,
    border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: BLUE, space: 8 } },
    children: [new TextRun({ text: "", size: 8 })] }),
  new Paragraph({ spacing: { before: 360, after: 0 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "SYSTEM 4", size: 60, bold: true, color: DARK })] }),
  new Paragraph({ spacing: { before: 120, after: 0 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "OAuth 2.0 & OpenID Connect", size: 40, bold: true, color: BLUE })] }),
  new Paragraph({ spacing: { before: 80, after: 0 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "Delegated Authorization: Vulnerabilities, Live Attacks, and Remediation", size: 24, color: GREY, italics: true })] }),
  new Paragraph({ spacing: { before: 720, after: 0 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "Methodology: vulnerable implementation \u2192 live attacks \u2192 hardened remediation", size: 20, color: GREY })] }),
  new Paragraph({ spacing: { before: 1400, after: 0 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "Standards basis: RFC 6749 \u00B7 RFC 6750 \u00B7 RFC 7636 \u00B7 RFC 9700 (Jan 2025) \u00B7 OpenID Connect Core 1.0", size: 18, color: GREY })] }),
  new Paragraph({ spacing: { before: 80, after: 0 }, alignment: AlignmentType.CENTER,
    children: [new TextRun({ text: "All attacks and mitigations in this report were executed and verified in a live three-server lab.", size: 18, color: GREY, italics: true })] }),
  new Paragraph({ children: [new PageBreak()] }),
];

// ---------------------------------------------------------------- TOC
const toc = [
  H1("Contents"),
  new TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-2" }),
  new Paragraph({ children: [new PageBreak()] }),
];

// ---------------------------------------------------------------- 1. Standards & scope
const sec1 = [
  H1("1. Standards and Scope"),
  para("OAuth 2.0 is a delegated **authorization** framework: it lets a client application obtain limited access to a resource on a user's behalf without handling the user's credentials. OpenID Connect (OIDC) layers **authentication** on top, returning a signed id_token that asserts who the user is. System 4 builds a minimal but complete instance of both \u2014 an Authorization Server, a client, and a resource server \u2014 then attacks and hardens it."),
  H2("1.1 Governing specifications"),
  bullet("**RFC 6749** (2012) \u2014 the OAuth 2.0 Authorization Framework core, plus **RFC 6750** for bearer-token usage."),
  bullet("**RFC 7636** \u2014 Proof Key for Code Exchange (PKCE)."),
  bullet("**RFC 9700** (January 2025) \u2014 Best Current Practice for OAuth 2.0 Security. This document updates the threat models of RFCs 6749/6750/6819, mandates exact-match redirect URIs and PKCE, and deprecates the implicit grant and the resource-owner password credentials grant. It is the remediation reference for the hardened build."),
  bullet("**OpenID Connect Core 1.0** \u2014 an OpenID Foundation specification (not an IETF RFC), defining the id_token and its required validation steps."),
  callout("Standards status note",
    "OAuth 2.1 (draft-ietf-oauth-v2-1, revision 15 as of March 2026) consolidates RFC 6749, RFC 9700, and PKCE into a single document, but it remains an IETF working draft and is not yet a published standard. This report treats it as forward guidance, not as a citable standard.", LIGHT),
  H2("1.2 Scope boundary with System 5"),
  para("OIDC id_tokens are JSON Web Tokens, which overlap with System 5 (JWT authentication). To avoid duplication, System 4 treats the id_token at the **validation-policy** level: whether the client checks the signature, pins the algorithm, and validates issuer, audience, and nonce. The deeper JWT cryptographic attack surface \u2014 algorithm-confusion (RS256\u2192HS256 key confusion), weak-secret brute force, and JWKS handling \u2014 is deferred to System 5. The id_token here is the **bridge** into that system, demonstrated in Vulnerability 5."),
];

// ---------------------------------------------------------------- 2. Architecture
const sec2 = [
  H1("2. Lab Architecture"),
  para("The lab runs three cooperating services plus a from-scratch primitive engine. Two client applications are registered at the Authorization Server to exercise both confidential- and public-client attack surfaces."),
  tbl(["Component", "Role", "Port"], [
    ["oauth_engine.py", "From-scratch primitives: code/token generation, PKCE (RFC 7636), hand-built JWT encode/verify, id_token construction", "library"],
    ["Authorization Server", "Issues authorization codes and tokens; hosts /authorize, /token, login and consent", "5000"],
    ["Client application", "Relying party; runs the redirect flow and consumes the id_token", "5001"],
    ["Resource server", "Protects /api/profile behind a bearer access token", "5002"],
  ], [3000, 4860, 1500]),
  spacer(60),
  H2("2.1 Registered clients"),
  tbl(["client_id", "Type", "Secret", "Used by"], [
    ["webapp", "Confidential", "Yes (HS256 id_token key)", "Vulns 2, 4, 5 (CSRF, replay, id_token)"],
    ["spa", "Public", "None", "Vulns 1, 3 (redirect_uri, PKCE)"],
  ], [2000, 1900, 2960, 2500]),
  spacer(60),
  para("The public client matters because it has no client secret to fall back on: for it, the redirect URI and PKCE are the only things protecting the authorization code. That is precisely where Vulnerabilities 1 and 3 bite hardest."),
  H2("2.2 Methodology"),
  para("Each vulnerability below follows the series methodology. A flaw is introduced in the vulnerable server (tagged in source with a VULN: comment), an attack script executes it against the running lab, and a hardened server implements the RFC 9700 control while a re-run of the same attack confirms the fix. The legitimate login flow was verified to still succeed against the hardened stack, ensuring the fixes harden rather than merely break the system."),
];

// ---------------------------------------------------------------- vuln template
function vuln(n, title, severity, desc, rootCause, attackLines, attackResult, remediationText, hardenedResult, rfc) {
  return [
    H2(`3.${n} Vulnerability ${n}: ${title}`),
    new Paragraph({ spacing: { after: 120 }, children: [
      new TextRun({ text: "Severity: ", bold: true }), new TextRun({ text: severity + "    " }),
      new TextRun({ text: "Reference: ", bold: true }), new TextRun({ text: rfc }),
    ]}),
    H3("Description"), para(desc),
    H3("Root cause"), para(rootCause),
    H3("Attack"),
    para("The attack script performs:"),
    code(attackLines),
    callout("Result against vulnerable server", attackResult, REDBG),
    H3("Remediation"), para(remediationText),
    callout("Result against hardened server", hardenedResult, GRNBG),
    spacer(80),
  ];
}

const sec3head = [ H1("3. Vulnerability Analysis"),
  para("Five vulnerabilities are analysed. Each was executed live; the result callouts below quote the actual script output.") ];

const v1 = vuln(1, "Redirect URI Manipulation", "Critical",
  "The authorization endpoint accepts any redirect_uri supplied in the request without comparing it to the value registered for the client. An attacker can therefore have the authorization code delivered to a server they control.",
  "Missing redirect_uri validation. The vulnerable /authorize reads redirect_uri from the query string and uses it directly in the 302 response, with no comparison against the registered value.",
  ["victim 'alice' is authenticated to the AS",
   "GET /authorize?client_id=spa&redirect_uri=http://localhost:6666/harvest&...",
   "  \u2192 AS issues a code and redirects it to the attacker URL",
   "attacker redeems the harvested code at /token (public client, no PKCE)",
   "attacker spends the access token at the resource server"],
  "STOLE alice's data via attacker redirect_uri: {'username': 'alice', 'email': 'alice@victim.com', 'note': 'SENSITIVE ACCOUNT DATA'}",
  "RFC 9700 (sec 2.1 / 4.1) requires exact string matching of redirect_uri against registration, with the sole exception of port numbers on localhost redirects for native apps. The hardened /authorize rejects any non-identical redirect_uri and does not redirect on this error. The token endpoint additionally requires the presented redirect_uri to equal the one bound to the code.",
  "AS refused hostile redirect_uri \u2014 no code issued.",
  "RFC 9700 \u00A72.1, \u00A74.1");

const v2 = vuln(2, "Cross-Site Request Forgery / Authorization Code Injection", "High",
  "The client does not generate or check a state value, so an authorization response is not bound to the user-agent that started the flow. An attacker can inject their own authorization code into a victim's session (login CSRF), silently logging the victim into the attacker's account.",
  "Missing state parameter. The vulnerable client's /login omits state entirely, and its /callback exchanges whatever code arrives with nothing to compare against.",
  ["attacker 'mallory' logs into the AS and obtains a code bound to mallory",
   "attacker does NOT redeem it",
   "victim's browser is induced to GET /callback?code=<mallory_code>",
   "client exchanges it and binds the victim's session to mallory"],
  "victim session fixated to attacker identity: {'identity': 'mallory'}  \u2014 the victim is now logged in as the attacker; anything they save lands in the attacker's account.",
  "RFC 6749 sec 10.12 and RFC 9700 sec 4.7 require an unguessable state value bound to the user-agent session and verified on return. The hardened client generates state, stores it server-side in the session, and rejects any callback whose state does not match.",
  "client rejected injected code \u2014 identity remained unset (state mismatch).",
  "RFC 6749 \u00A710.12, RFC 9700 \u00A74.7");

const v3 = vuln(3, "Authorization Code Not Bound to Client (No PKCE)", "High",
  "Without PKCE, an authorization code is not cryptographically bound to the client instance that requested it. If the code leaks through any channel, whoever holds it can redeem it.",
  "PKCE absent. The vulnerable /authorize neither requires nor stores a usable code_challenge, and /token never demands a code_verifier.",
  ["victim 'alice' completes a legitimate authorize to the registered redirect",
   "the issued code leaks to the attacker (channel is orthogonal)",
   "attacker POSTs /token with the code and NO code_verifier",
   "  \u2192 access_token issued"],
  "leaked code redeemed with no PKCE verifier \u2192 access_token issued.",
  "RFC 9700 (sec 2.1.1) mandates PKCE. The hardened AS requires a code_challenge for public clients at the authorization endpoint and verifies the S256 code_verifier at the token endpoint; the reference confidential client also adopts PKCE so the protection is universal. An attacker without the verifier cannot redeem a leaked code.",
  "no code issued \u2014 PKCE required at the authorization endpoint; a leaked code is unredeemable without the verifier.",
  "RFC 7636, RFC 9700 \u00A72.1.1");

const v4 = vuln(4, "Authorization Code Replay", "Medium",
  "An authorization code can be exchanged for tokens more than once. A code captured from logs, browser history, or a proxy can be replayed after the legitimate client has already consumed it.",
  "Codes are not marked used. The vulnerable /token issues tokens on every presentation of a valid code without invalidating it.",
  ["a code is issued for alice",
   "POST /token with the code  \u2192 access_token A",
   "POST /token with the SAME code  \u2192 access_token B"],
  "code replayed: two distinct access tokens minted from one code.",
  "RFC 6749 sec 4.1.2 requires codes to be single-use; RFC 9700 sec 4.5 adds that reuse should be treated as an attack signal. The hardened /token marks the code used on first exchange, rejects any reuse, and revokes tokens previously minted from that code.",
  "replay rejected \u2014 'code reuse detected; tokens revoked'.",
  "RFC 6749 \u00A74.1.2, RFC 9700 \u00A74.5");

const v5 = vuln(5, "id_token Accepted Without Validation", "Critical",
  "The client trusts the OIDC id_token without verifying it: no signature check, no algorithm pinning, and no issuer, audience, or nonce validation. Any party able to place an id_token in front of the client (a malicious or mixed-up authorization server, a MITM on a non-pinned channel, or a front-channel response) can forge an identity.",
  "Unverified decode. The vulnerable client base64url-decodes the id_token payload and trusts the sub claim directly, instead of cryptographically verifying the token.",
  ["forge F1: alg='none' unsigned token, sub='admin'",
   "forge F2: HS256 token signed with the WRONG key, sub='admin'",
   "feed each to the client's id_token handling"],
  "vulnerable client accepted forged id_token(s): ['alg=none', 'HS256/wrong-key'] \u2192 sub=admin.",
  "OpenID Connect Core 1.0 sec 3.1.3.7 requires verifying the signature, pinning the expected algorithm, and validating iss, aud, and nonce. The hardened client calls a strict verifier with all expectations pinned; both forgeries are rejected. This is the boundary into System 5, which takes the JWT cryptography deeper.",
  "both forgeries rejected (sub=None) under strict verification with pinned alg and validated iss/aud/nonce.",
  "OpenID Connect Core 1.0 \u00A73.1.3.7");

// ---------------------------------------------------------------- 4. Results
const sec4 = [
  H1("4. Results Summary"),
  para("All five attacks succeeded against the vulnerable stack and were blocked against the hardened stack, while the legitimate login flow continued to return the correct identity (alice)."),
  tbl(["#", "Vulnerability", "Vulnerable", "Hardened", "Control"], [
    ["1", "Redirect URI manipulation", "Account data stolen", "Blocked", "Exact-match redirect_uri"],
    ["2", "CSRF / code injection", "Session fixated", "Blocked", "state bound to session"],
    ["3", "No PKCE", "Leaked code redeemed", "Blocked", "PKCE required + verified"],
    ["4", "Code replay", "Two tokens, one code", "Blocked", "Single-use + revocation"],
    ["5", "id_token not validated", "Forgery accepted as admin", "Blocked", "Strict id_token verify"],
  ], [500, 3060, 2200, 1400, 2200]),
  spacer(60),
  callout("Verification basis",
    "Each row reflects a live execution. The vulnerable results are the actual outputs of the attack scripts against the servers on ports 5000\u20135002; the hardened results are the same scripts re-run after the RFC 9700 controls were applied, on the same ports.", LIGHT),
];

// ---------------------------------------------------------------- 5. Handoff
const sec5 = [
  H1("5. Residual Notes and Handoff"),
  H2("5.1 Deliberately deferred"),
  bullet("**Implicit grant** is not implemented. It returns tokens in the URL fragment, exposing them to browser history, referrers, and scripts; RFC 9700 and OAuth 2.1 deprecate it. It is noted here as deprecated rather than demonstrated."),
  bullet("**Deeper JWT attacks** (algorithm-confusion RS256\u2192HS256, weak-secret brute force, JWKS spoofing) belong to System 5. Vulnerability 5 establishes the validation-policy foundation they build on."),
  bullet("**Refresh-token rotation and sender-constraining (DPoP)** are out of scope for this system; RFC 9700 recommends both for long-lived sessions."),
  H2("5.2 Bridge to System 5"),
  para("The id_token in Vulnerability 5 is a JWT. System 5 takes the same artifact and attacks the token itself rather than the policy around it: forging signatures via algorithm confusion, exploiting the 'none' algorithm against libraries that do not pin alg, and brute-forcing weak HMAC secrets. The strict verifier built here (pinned algorithm, signature check, claim validation) is the defensive baseline System 5 will extend."),
  H1("6. References"),
  bullet("RFC 6749 \u2014 The OAuth 2.0 Authorization Framework (2012)."),
  bullet("RFC 6750 \u2014 OAuth 2.0 Bearer Token Usage."),
  bullet("RFC 7636 \u2014 Proof Key for Code Exchange by OAuth Public Clients."),
  bullet("RFC 9700 \u2014 Best Current Practice for OAuth 2.0 Security (January 2025)."),
  bullet("OpenID Connect Core 1.0 \u2014 OpenID Foundation."),
  bullet("draft-ietf-oauth-v2-1-15 \u2014 The OAuth 2.1 Authorization Framework (work in progress, March 2026)."),
];

const doc = new Document({
  creator: "Authentication Security Study Series",
  title: "System 4 \u2014 OAuth 2.0 & OpenID Connect",
  styles: {
    default: { document: { run: { font: "Arial", size: 22, color: "222222" } } },
    paragraphStyles: [
      { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 30, bold: true, color: DARK, font: "Arial" },
        paragraph: { spacing: { before: 300, after: 160 }, outlineLevel: 0,
          border: { bottom: { style: BorderStyle.SINGLE, size: 6, color: BLUE, space: 4 } } } },
      { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 25, bold: true, color: BLUE, font: "Arial" },
        paragraph: { spacing: { before: 220, after: 120 }, outlineLevel: 1 } },
      { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
        run: { size: 22, bold: true, color: "333333", font: "Arial" },
        paragraph: { spacing: { before: 140, after: 80 }, outlineLevel: 2 } },
    ],
  },
  numbering: { config: [
    { reference: "b", levels: [{ level: 0, format: LevelFormat.BULLET, text: "\u2022", alignment: AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 540, hanging: 280 } } } }] },
  ] },
  sections: [{
    properties: { page: { size: { width: 12240, height: 15840 },
      margin: { top: 1440, right: 1440, bottom: 1440, left: 1440 } } },
    headers: { default: new Header({ children: [ new Paragraph({
      alignment: AlignmentType.RIGHT, spacing: { after: 0 },
      border: { bottom: { style: BorderStyle.SINGLE, size: 4, color: "CCCCCC", space: 2 } },
      children: [new TextRun({ text: "Authentication Security Study Series \u2014 System 4", size: 16, color: GREY })] }) ] }) },
    footers: { default: new Footer({ children: [ new Paragraph({
      alignment: AlignmentType.CENTER, spacing: { before: 0 },
      children: [ new TextRun({ text: "OAuth 2.0 & OIDC  \u00B7  Page ", size: 16, color: GREY }),
                  new TextRun({ children: [PageNumber.CURRENT], size: 16, color: GREY }) ] }) ] }) },
    children: [
      ...titlePage, ...toc, ...sec1, ...sec2,
      ...sec3head, ...v1, ...v2, ...v3, ...v4, ...v5,
      ...sec4, ...sec5,
    ],
  }],
});

Packer.toBuffer(doc).then(buf => {
  fs.writeFileSync("/home/claude/system4_oauth/System4_OAuth_OIDC_Report.docx", buf);
  console.log("report written:", buf.length, "bytes");
});
