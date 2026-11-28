import { bodyAfterParams, findUnits, type Unit } from '../access.js';
import { AUTH_CHECK_RE, detectAuth } from '../detect.js';
import type { ProjectContext, SourceFile } from '../project.js';
import { matchBracket, matcherCovers, matcherToRegExp } from '../routes.js';
import type { Check, CheckOutput, Location } from '../types.js';
import { lineTextAt } from '../util.js';
import { appCode, clientCode, emptyOutput, isRouteLike, notApplicable, serverCode, where } from './common.js';
import { MIDDLEWARE_BLOCKS, matcherEntries } from './costs.js';

/*
 * Access control: can one person reach or change data that isn't theirs?
 *
 * Everything here is pattern-based, so each finding is worded as "check this". The rules follow
 * the official guidance they cite (Next.js data security guide, Supabase RLS docs, OWASP IDOR and
 * mass assignment cheat sheets) and accept the usual ways apps do the check correctly:
 * a scoped query, fetch-then-compare, a policy helper, an admin gate, or a signed-in wrapper.
 */

const MAX_PER_ID = 5;

// ---------- who is calling ----------

/** Sign-in helpers beyond the shared AUTH_CHECK_RE (getCurrentUser(), requireOrgMember(), ...). */
const AUTH_EXTRA =
  /\b(?:get|require|ensure|assert|check|verify|validate|fetch|load|must)(?:Current|Signed[iI]n|LoggedIn|Authed)?(?:User|Session|Auth|Viewer|Member|Account|Me)\w*\s*\(|\bgetClaims\s*\(|\bauthenticate\w*\s*\(|\bauth\.protect\s*\(/;
const PY_AUTH =
  /(?:Depends|Security)\(\s*[\w.]*(?:user|auth|current|session|token|login|verify|jwt|principal|account|member|admin|claims)\w*|\bcurrent_user\b|\bget_jwt_identity\s*\(|\bverify_jwt_in_request\s*\(|\brequest\.user\b|\bg\.user\b|\bsession\[\s*["']user/i;

/** Function names defined in `shared` that this unit calls and that check who is signed in. */
/** The source of one helper defined at `at` in `code`, cut at its real end (not running into the next function). */
function helperBody(code: string, at: number, python: boolean): string {
  if (python) {
    const indent = /^[ \t]*/.exec(code.slice(code.lastIndexOf('\n', at) + 1))![0].length;
    const lines = code.slice(at).split('\n');
    let end = lines[0]!.length;
    for (const line of lines.slice(1)) {
      if (line.trim() && /^[ \t]*/.exec(line)![0].length <= indent) break;
      end += line.length + 1;
    }
    return code.slice(at, at + end);
  }
  const paren = code.indexOf('(', at);
  const body = paren === -1 ? null : bodyAfterParams(code, paren);
  return body ? code.slice(at, body.end) : '';
}

/** The helpers defined next to this unit (same file) that it calls. */
function calledHelpers(u: Unit): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  for (const m of u.text.matchAll(/\b([A-Za-z_$][\w$]*)\s*\(/g)) {
    const name = m[1]!;
    if (seen.has(name)) continue;
    seen.add(name);
    const def = new RegExp(`(?:function\\s+|(?:const|let|var)\\s+|def\\s+)${name.replace(/\$/g, '\\$')}\\b`).exec(
      u.shared,
    );
    if (def) out.push(helperBody(u.shared, def.index, u.kind === 'python'));
  }
  return out;
}

function callsAuthHelper(u: Unit): boolean {
  return calledHelpers(u).some((body) => AUTH_CHECK_RE.test(body) || AUTH_EXTRA.test(body) || PY_AUTH.test(body));
}

function signsInCaller(u: Unit): boolean {
  if (u.authOutside) return true;
  if (u.kind === 'python') return PY_AUTH.test(u.text) || callsAuthHelper(u);
  return (
    AUTH_CHECK_RE.test(u.text) || AUTH_EXTRA.test(u.text) || AUTH_CHECK_RE.test(u.reachedCode) || callsAuthHelper(u)
  );
}

// ---------- where a value comes from ----------

type Origin = 'request' | 'session' | 'unknown';

const SESSION_SRC =
  /\b(?:session|getServerSession|getSession|auth|getAuth|currentUser|current_user|getCurrentUser|get_current_user|getUser|getClaims|claims|viewer|locals\.user|ctx\.user|ctx\.session|ctx\.auth|ctx\.userId|req\.user|req\.auth|request\.user|request\.auth|g\.user|get_jwt_identity)\b|\buser\??\.(?:id|uid|sub|userId|pk)\b|\bme\??\.id\b/;
const REQUEST_SRC =
  /\b(?:params|searchParams|query|body|formData|input|args|parsedInput|req\.(?:params|query|body|json|formData)|request\.(?:args|form|json|get_json|GET|POST|data|query_params|path_params|values|files|formData|nextUrl)|nextUrl|c\.req|event\.(?:params|body|queryStringParameters|pathParameters)|getRouterParam|getQuery|readBody)\b/;
/** Parameters that a framework fills in itself, not the caller. */
const INJECTED_PARAM =
  /^(?:request|req|res|response|self|cls|db|session|current_user|user|me|background_tasks|settings|ctx|context|next|c|event)$/;

function escapeRe(s: string): string {
  return s.replace(/[$]/g, '\\$');
}

function paramNames(u: Unit): string[] {
  if (!u.paramsFromCaller) return [];
  if (u.kind === 'trpc') return ['input'];
  if (u.kind === 'python') {
    return u.params
      .split(',')
      .filter((p) => !/(?:Depends|Security)\(/.test(p))
      .map((p) => /^\s*\**\s*(\w+)/.exec(p)?.[1] ?? '')
      .filter((n) => n && !INJECTED_PARAM.test(n));
  }
  // Every identifier in a JS parameter list (destructured names included); type names never match a lookup value.
  return [...u.params.matchAll(/([A-Za-z_$][\w$]*)\s*(?=[,:=})?]|$)/g)].map((m) => m[1]!);
}

/** The right-hand side that defines `name` inside the function, or null. */
function definitionOf(name: string, u: Unit): string | null {
  const n = escapeRe(name);
  if (u.kind === 'python') {
    return new RegExp(`^[ \\t]*${n}\\s*(?::[^=\\n]+)?=(?!=)\\s*(.+)$`, 'm').exec(u.text)?.[1] ?? null;
  }
  const direct = new RegExp(`(?:const|let|var)\\s+${n}\\s*(?::[^=;]+)?=\\s*([^;\\n]+)`).exec(u.text);
  if (direct) return direct[1]!;
  for (const m of u.text.matchAll(/(?:const|let|var)\s*\{([^{}]*)\}\s*(?::[^=;]+)?=\s*([^;\n]+)/g)) {
    if (new RegExp(`(?:^|[,{\\s])${n}\\s*(?:[,=}]|$)|:\\s*${n}\\b`).test(m[1]!)) return m[2]!;
  }
  return null;
}

/** Does this value come from the request, from the signed-in session, or can't we tell? */
export function originOf(expr: string, u: Unit, depth = 0): Origin {
  const e = expr
    .trim()
    .replace(/^await\s+/, '')
    .replace(/^(?:Number|parseInt|parseFloat|String|BigInt|int|str|uuid\.UUID|UUID)\s*\(\s*/, '')
    .replace(/\s+as\s+[\w<>[\]|\s]+$/, '')
    .replace(/[!)\s]+$/, '');
  if (!e) return 'unknown';
  if (SESSION_SRC.test(e)) return 'session';
  if (REQUEST_SRC.test(e)) return 'request';
  const id = /^([A-Za-z_$][\w$]*)$/.exec(e)?.[1] ?? /^\(?\s*([A-Za-z_$][\w$]*)/.exec(e)?.[1];
  if (!id || depth > 2) return 'unknown';
  const rhs = definitionOf(id, u);
  if (rhs !== null) return originOf(rhs, u, depth + 1);
  if (paramNames(u).includes(id)) return 'request';
  return 'unknown';
}

// ---------- ownership evidence ----------

const OWNER_FIELD =
  /\b(?:user|owner|author|creator|created_?by|tenant|org|organi[sz]ation|account|team|workspace|member|profile|customer|seller|buyer)_?(?:id|Id|ID|uid)\b|\bcreated_?[bB]y\b|\buid\b/g;
const OWNER_RELATION =
  /\b(?:user|owner|author|creator|tenant|organi[sz]ation|org|account|team|workspace|members?)\s*:\s*\{/;
const PY_OWNER_KW =
  /\b(?:owner|user|author|created_by|creator|account|tenant|organization|org|team|customer)(?:_id)?\s*(?:=(?!=)|==)\s*([^,)\n]+)/g;

/** A filter in the query itself that limits it to the caller's records (and isn't taken from the request). */
function scopedQuery(query: string, u: Unit): boolean {
  if (OWNER_RELATION.test(query)) return true;
  for (const m of query.matchAll(OWNER_FIELD)) {
    const rest = query.slice(m.index + m[0].length);
    const v = /^\s*["'`]?\s*\]?\s*(?:,|:|===?|==|=)\s*([^,})\n]+)/.exec(rest);
    // No separator after it: only a shorthand key ({ id, userId }) counts. `body.userId` is a value, not a filter.
    if (!v && !/[{,]\s*$/.test(query.slice(0, m.index))) continue;
    if (originOf(v ? v[1]! : m[0], u) !== 'request') return true;
  }
  if (u.kind === 'python') {
    for (const m of query.matchAll(PY_OWNER_KW)) {
      // "user=Depends(get_current_user)" is a parameter that receives the user, not a filter.
      if (/^\s*(?:Depends|Security)\s*\(/.test(m[1]!)) continue;
      if (originOf(m[1]!, u) !== 'request') return true;
    }
  }
  return false;
}

const OWNER_KEY =
  '(?:user|owner|author|creator|created_?by|tenant|org|organi[sz]ation|account|team|workspace|profile|customer|seller)_?(?:id|Id|ID|uid)';
/** Fetch-then-compare: `if (note.userId !== session.user.id)` or `if note.owner_id != current_user.id`. */
const OWNER_COMPARE = new RegExp(
  [
    `\\.${OWNER_KEY}\\b\\s*(?:!==?|===?|!=|==)`,
    `(?:!==?|===?|!=|==)\\s*[\\w$.?\\[\\]'"]*\\.${OWNER_KEY}\\b`,
    '\\b(?:session|user|currentUser|current_user|claims|viewer|me)\\??\\.(?:id|uid|sub|userId|pk)\\s*(?:!==?|===?|!=|==)',
    '(?:!==?|===?|!=|==)\\s*(?:[\\w$]+\\??\\.)*(?:user|currentUser|current_user|claims|viewer|me)\\??\\.(?:id|uid|sub|userId|pk)\\b',
    '\\.uid\\s*(?:!==?|===?|!=|==)',
    '\\.(?:owner|user|author)\\s*(?:!=|==)\\s*(?:request\\.user|current_user|user)\\b',
    '\\b(?:request\\.user|current_user)\\.\\w+\\.(?:get|filter|all)\\s*\\(',
  ].join('|'),
);
/** Policy helpers (CASL, Casbin, hand-written ones). */
const POLICY_HELPER =
  /\b(?:authori[sz]e\w*|can|cannot|ability\.can|checkPermission\w*|hasPermission\w*|checkAccess|hasAccess|canAccess|canEdit|canDelete|canView|canUpdate|isOwner|isMember|has_perm|has_object_permission|check_object_permissions|(?:assert|ensure|require|check|verify|enforce)\w*(?:Owner|Access|Permission|Member|Membership|Can)\w*|(?:assert|ensure|require|check|verify)_\w*(?:owner|access|permission|member)\w*)\s*\(/;
/** Admin-only code may legitimately touch anyone's records. */
const ADMIN_GATE =
  /\brole\s*(?:!==?|===?|!=|==)\s*["'`](?:admin|superadmin|super_admin|owner|staff)["'`]|["'`](?:admin|superadmin)["'`]\s*(?:!==?|===?|!=|==)\s*[\w$.?]*\brole\b|\bisAdmin\b|\bis_admin\b|\bis_staff\b|\bis_superuser\b|\b(?:require|assert|ensure|check|verify)_?Admin\w*|\bisSuperAdmin\b|\bhasRole\s*\(|\bhas_role\s*\(|\badminProcedure\b|\bIsAdminUser\b|\bstaff_member_required\b|\bhas\(\s*\{\s*role/;
function checksOwnership(u: Unit): boolean {
  return u.adminOnly || OWNER_COMPARE.test(u.text) || POLICY_HELPER.test(u.text) || ADMIN_GATE.test(u.text);
}

// ---------- database lookups by id ----------

interface Lookup {
  index: number;
  id: string;
  model: string;
  mutation: boolean;
  query: string;
  supabase?: boolean;
}

/** Models that are usually public, so reading one by id is normal. */
const PUBLIC_MODEL =
  /^(?:products?|posts?|articles?|blogs?|blogPosts?|pages?|categor(?:y|ies)|tags?|plans?|prices?|pricing|events?|listings?|courses?|lessons?|faqs?|reviews?|testimonials?|recipes?|jobs?|users?|profiles?|authors?|tools?|templates?|items?)$/i;
const NOT_A_MODEL =
  /^(?:stripe|cache|map|redis|kv|cookies|cookieStore|headers|store|storage|bucket|params|searchParams|url|formData|set|hash|crypto|hmac|resend|axios|api|http|fetch|localStorage|sessionStorage|queryClient|this|Object|Reflect)$/;

function statementAround(text: string, index: number): string {
  const before = text.lastIndexOf(';', index);
  const start = Math.max(before + 1, index - 600, 0);
  let end = text.indexOf(';', index);
  if (end === -1 || end > index + 600) end = Math.min(text.length, index + 600);
  return text.slice(start, end);
}

/** From `index` to the end of its statement (or 600 characters). */
function statementAfter(text: string, index: number): string {
  let end = text.indexOf(';', index);
  if (end === -1 || end > index + 600) end = Math.min(text.length, index + 600);
  return text.slice(index, end);
}

const ORM_CALL =
  /\.(findUnique(?:OrThrow)?|findFirst(?:OrThrow)?|update|delete|upsert|destroy|findOne|findOneAndUpdate|findOneAndDelete|findOneAndRemove|updateOne|deleteOne)\s*\(/g;
const READ_METHODS = /^(?:findUnique|findUniqueOrThrow|findFirst|findFirstOrThrow|findOne)$/;
const BY_ID_CALL = /\b([A-Z][\w$]*)\.(findById|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findByPk)\s*\(/g;
const DRIZZLE_EQ = /\beq\(\s*([\w$]+)\.(?:id|_id)\s*,\s*([^)]+)\)/g;
const SUPABASE_FROM = /\.from\(\s*["'`]([\w.-]+)["'`]\s*\)/g;
const FIREBASE_DOC = /\.collection\(\s*["'`]([\w-]+)["'`]\s*\)\s*\.doc\(\s*([^)]+)\)/g;

/** The value of the `id` key in an object literal, or null. */
function idValue(obj: string): string | null {
  const explicit = /(?:^|[{,\s])(?:_id|id)\s*:\s*([^,}\n]+)/.exec(obj);
  if (explicit) return explicit[1]!;
  if (/[{,]\s*(?:_id|id)\s*[,}]/.test(obj)) return 'id';
  return null;
}

function jsLookups(u: Unit, firebaseAdmin: boolean): Lookup[] {
  const t = u.text;
  const out: Lookup[] = [];
  for (const m of t.matchAll(ORM_CALL)) {
    const receiver = /([\w$]+)\s*\??\.?\s*$/.exec(t.slice(Math.max(0, m.index - 60), m.index))?.[1] ?? '';
    if (!receiver || NOT_A_MODEL.test(receiver)) continue;
    // Supabase's builder (.from("x").update(...)) is read separately.
    if (/\)\s*$/.test(t.slice(Math.max(0, m.index - 2), m.index))) continue;
    const open = m.index + m[0].length - 1;
    const close = matchBracket(t, open);
    if (close === -1) continue;
    let arg = t.slice(open, close + 1);
    const whereAt = /\bwhere\s*:\s*\{/.exec(arg);
    if (whereAt) {
      const brace = whereAt.index + whereAt[0].length - 1;
      const end = matchBracket(arg, brace);
      if (end !== -1) arg = arg.slice(brace, end + 1);
    }
    const id = idValue(arg);
    if (id === null) continue;
    out.push({ index: m.index, id, model: receiver, mutation: !READ_METHODS.test(m[1]!), query: arg });
  }
  for (const m of t.matchAll(BY_ID_CALL)) {
    const open = m.index + m[0].length - 1;
    const close = matchBracket(t, open);
    if (close === -1) continue;
    const first = /^\(\s*([^,)]+)/.exec(t.slice(open, close + 1))?.[1];
    if (!first) continue;
    out.push({ index: m.index, id: first, model: m[1]!, mutation: !/^find(?:ById|ByPk)$/.test(m[2]!), query: '' });
  }
  for (const m of t.matchAll(DRIZZLE_EQ)) {
    const stmt = statementAround(t, m.index);
    out.push({
      index: m.index,
      id: m[2]!,
      model: m[1]!,
      mutation: /\.(?:update|delete)\s*\(\s*[\w$.]+\s*\)/.test(stmt),
      query: stmt,
    });
  }
  for (const m of t.matchAll(SUPABASE_FROM)) {
    const stmt = statementAfter(t, m.index);
    const eq = /\.(?:eq|match)\(\s*["'`]id["'`]\s*,\s*([^)]+)\)/.exec(stmt);
    if (!eq) continue;
    out.push({
      index: m.index,
      id: eq[1]!,
      model: m[1]!,
      mutation: /\.(?:update|delete|upsert)\s*\(/.test(stmt),
      query: stmt,
      supabase: true,
    });
  }
  if (firebaseAdmin) {
    for (const m of t.matchAll(FIREBASE_DOC)) {
      const stmt = statementAround(t, m.index);
      out.push({
        index: m.index,
        id: m[2]!,
        model: m[1]!,
        mutation: /\.(?:update|delete|set)\s*\(/.test(stmt),
        query: '',
      });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

function pyLookups(u: Unit): Lookup[] {
  const t = u.text;
  const out: Lookup[] = [];
  const lineAt = (i: number) => lineTextAt(t, i);
  const mutation = (i: number) =>
    /^(?:PUT|PATCH|DELETE)$/.test(u.method) ||
    /\.delete\s*\(|\.update\s*\(|\.commit\s*\(|\.save\s*\(/.test(lineAt(i)) ||
    /\.delete\s*\(|\.commit\s*\(|\.save\s*\(/.test(t);
  for (const m of t.matchAll(
    /\b(?:db|session|self\.db|self\.session|db\.session|async_session)\.get\(\s*([\w.]+)\s*,\s*([^)]+)\)/g,
  ))
    out.push({ index: m.index, id: m[2]!, model: m[1]!.split('.').pop()!, mutation: mutation(m.index), query: '' });
  for (const m of t.matchAll(/\b([A-Z]\w*)\.query\.(?:get|get_or_404)\(\s*([^)]+)\)/g))
    out.push({ index: m.index, id: m[2]!, model: m[1]!, mutation: mutation(m.index), query: '' });
  for (const m of t.matchAll(/\bget_object_or_404\(\s*([\w.]+)\s*,([^)]*)\)/g)) {
    const id = /\b(?:pk|id)\s*=\s*([^,)]+)/.exec(m[2]!)?.[1];
    if (id) out.push({ index: m.index, id, model: m[1]!.split('.').pop()!, mutation: mutation(m.index), query: m[2]! });
  }
  for (const m of t.matchAll(/\b([A-Z]\w*)\.objects\.(?:get|filter)\(([^)]*)\)/g)) {
    const id = /\b(?:pk|id)\s*=\s*([^,)]+)/.exec(m[2]!)?.[1];
    if (id) out.push({ index: m.index, id, model: m[1]!, mutation: mutation(m.index), query: lineAt(m.index) });
  }
  for (const m of t.matchAll(/\.(?:filter|where)\(\s*([A-Z]\w*)\.id\s*==\s*([^,)]+)/g))
    out.push({
      index: m.index,
      id: m[2]!,
      model: m[1]!,
      mutation: mutation(m.index),
      query: statementAround(t, m.index),
    });
  for (const m of t.matchAll(/\.filter_by\(([^)]*)\)/g)) {
    const id = /\bid\s*=\s*([^,)]+)/.exec(m[1]!)?.[1];
    if (id) out.push({ index: m.index, id, model: '', mutation: mutation(m.index), query: m[1]! });
  }
  return out.sort((a, b) => a.index - b.index);
}

// ---------- writes ----------

const JS_WRITE = [
  /\b(?:prisma|db|tx|ctx\.db|ctx\.prisma|database)\s*\.\s*[\w$]+\s*\.\s*(?:create|createMany|createManyAndReturn|update|updateMany|upsert|delete|deleteMany)\s*\(/,
  /\b(?:db|tx|database)\s*\.\s*(?:insert|update|delete)\s*\(\s*[\w$.]+\s*\)/,
  /\b(?!(?:Object|Array|Promise|Response|NextResponse|Error|Map|Set|URL|JSON|Math|Reflect|Symbol|Buffer|Date|String|Number|Intl|React)\.)[A-Z][\w$]*\.(?:create|insertMany|updateOne|updateMany|deleteOne|deleteMany|findByIdAndUpdate|findByIdAndDelete|findByIdAndRemove|findOneAndUpdate|findOneAndDelete|findOneAndRemove|replaceOne|bulkCreate|destroy)\s*\(/,
  /\bsql\s*`\s*(?:insert|update|delete)\b/i,
  /\.(?:query|execute)\s*\(\s*["'`]\s*(?:insert|update|delete)\b/i,
  /\.collection\(\s*["'`][^"'`]+["'`]\s*\)\s*\.(?:insertOne|insertMany|updateOne|updateMany|deleteOne|deleteMany|replaceOne|findOneAndUpdate|findOneAndDelete)\s*\(/,
];
const SUPABASE_WRITE = /\.from\(\s*["'`][\w.-]+["'`]\s*\)\s*\.(?:insert|update|upsert|delete)\s*\(/;
const FIREBASE_ADMIN_WRITE = /\.(?:doc|collection)\([^)]*\)\s*\.(?:set|update|delete|add)\s*\(/;
const PY_WRITE =
  /\b(?:db|session|self\.db|db\.session)\.(?:add|delete|merge)\s*\(|\.commit\s*\(\s*\)|\.objects\.(?:create|update_or_create|get_or_create|bulk_create)\s*\(|\.save\s*\(\s*\)|\.delete\s*\(\s*\)|\.(?:insert_one|insert_many|update_one|update_many|delete_one|delete_many|replace_one)\s*\(|\.table\(\s*["'][^"']+["']\s*\)\.(?:insert|update|upsert|delete)\s*\(/;

/** A Supabase client that skips Row Level Security (the secret / service_role key). */
const SERVICE_ROLE =
  /SERVICE_ROLE|service_role|SUPABASE_SECRET_KEY|\bsupabaseAdmin\b|\bcreateAdminClient\b|\bcreateServiceClient\b|\bcreateServiceRoleClient\b/;

interface Env {
  firebaseAdmin: boolean;
}

function usesServiceRole(u: Unit): boolean {
  return SERVICE_ROLE.test(u.text) || SERVICE_ROLE.test(u.shared) || SERVICE_ROLE.test(u.reachedCode);
}

/** Does this unit change data? Supabase writes through the signed-in user's client are left to RLS. */
function writes(u: Unit, env: Env): boolean {
  const code = `${u.text}\n${u.reachedCode}`;
  if (u.kind === 'python') return PY_WRITE.test(u.text);
  if (JS_WRITE.some((re) => re.test(code))) return true;
  if (SUPABASE_WRITE.test(code) && usesServiceRole(u)) return true;
  return env.firebaseAdmin && FIREBASE_ADMIN_WRITE.test(code);
}

// ---------- endpoints that are meant to be public ----------

/** Sign-in flows, webhooks and public forms: they run before there is a user, or prove who is calling another way. */
/**
 * Function names of flows that run before there is a user (or that are public by nature). The whole name has to be
 * that flow, optionally with a verb in front ("handleSignIn", "submitContactForm"): deleteContact or updatePassword
 * change existing data and are not exempt.
 */
const PUBLIC_FLOW_NAME = new RegExp(
  '^(?:handle|submit|send|process|on|do)?_?' +
    '(?:(?:log_?in|sign_?in|sign_?up|register|log_?out|sign_?out|oauth|magic_?link|otp|webhook)\\w*' +
    '|(?:forgot|reset|request)_?password(?:_?reset)?|request_?password_?reset|verify_?(?:email|otp|code|token)?|confirm_?email' +
    '|(?:auth_?)?callback|(?:un)?subscribe|(?:join_?)?(?:waitlist|newsletter)|contact|feedback|health_?check|cron)' +
    '(?:_?(?:form|action|handler|request|route))?$',
  'i',
);
/** URL segments of webhooks, sign-in flows and cron jobs. */
const PUBLIC_FLOW_PATH =
  /(?:^|[/_.\-[])(?:webhooks?|hooks|cron|callback|oauth|auth|login|logout|signin|sign-in|signup|sign-up|register|inngest|qstash|health|contact|newsletter|subscribe|waitlist)(?=$|[/_.\-\]])/i;
const SIGNED_REQUEST =
  /constructEvent|webhooks?\.(?:verify|unwrap|constructEvent)|verifySignature|verifyWebhook|validateWebhook|\bsvix\b|new\s+Webhook\s*\(|createHmac|timingSafeEqual|x-hub-signature|stripe-signature|CRON_SECRET|new\s+Receiver\s*\(|verify_webhook|compare_digest/i;

function meantToBePublic(u: Unit): boolean {
  if (PUBLIC_FLOW_NAME.test(u.name) && u.kind !== 'route') return true;
  if (PUBLIC_FLOW_PATH.test(u.urlPath ?? '')) return true;
  // A Next.js route file is one URL, so its path is the URL. Files holding many routes are judged route by route.
  if (u.kind === 'route' && PUBLIC_FLOW_PATH.test(u.file.path)) return true;
  // A signature check this handler actually runs (not one somewhere else in the file).
  return [u.text, u.reachedCode, ...calledHelpers(u)].some((code) => SIGNED_REQUEST.test(code));
}

// ---------- middleware ----------

function isMiddlewareFile(f: SourceFile): boolean {
  return /(^|\/)(?:src\/)?(middleware|proxy)\.(t|j)s$/.test(f.path);
}

/** A blocking middleware runs on this URL path. */
function middlewareCovers(ctx: ProjectContext, urlPath: string | null): boolean {
  return ctx.files.some((f) => {
    if (!isMiddlewareFile(f)) return false;
    const code = ctx.codeOf(f);
    return MIDDLEWARE_BLOCKS.test(code) && matcherCovers(matcherEntries(code), urlPath) !== false;
  });
}

/** A blocking middleware runs on every page (so on the pages that Server Actions post to). */
function middlewareCoversPages(ctx: ProjectContext): boolean {
  return ctx.files.some((f) => {
    if (!isMiddlewareFile(f)) return false;
    const code = ctx.codeOf(f);
    if (!MIDDLEWARE_BLOCKS.test(code)) return false;
    // Protection limited to some routes ("if (isProtectedRoute(req)) auth.protect()") doesn't cover every page.
    if (/createRouteMatcher|isProtectedRoute/.test(code) && !/isPublicRoute/.test(code)) return false;
    const entries = matcherEntries(code);
    if (entries === null) return true;
    // The matcher has to run on ordinary pages, not just /api or /dashboard.
    const pages = ['/', '/settings', '/account/profile'];
    return pages.every((p) => entries.some((e) => matcherToRegExp(e)?.test(p)));
  });
}

// ---------- the other rules ----------

const META_KEYS =
  'role|roles|is_?admin|isAdmin|admin|plan|tier|subscription\\w*|credits|permissions?|is_?pro|isPro|premium|isPremium|is_?paid|isPaid|access_?level|accessLevel';
const META_READ = new RegExp(
  `\\b(user_metadata|unsafeMetadata|unsafe_metadata|raw_user_meta_data)\\s*(?:\\?\\.|\\.)\\s*(${META_KEYS})\\b|\\b(user_metadata|unsafeMetadata|unsafe_metadata|raw_user_meta_data)\\s*(?:\\?\\.)?\\s*(?:\\[\\s*|\\.get\\(\\s*)["'\`](${META_KEYS})["'\`]`,
);
const SQL_META = /user_meta_?data|raw_user_meta_data/i;
const SQL_META_KEY = new RegExp(`(?:user_meta_?data|raw_user_meta_data)['"]?\\s*->>?\\s*'(${META_KEYS})'`, 'i');

const CLIENT_ADMIN =
  /\b(?:role|userRole|user_role)\s*(?:!==?|===?)\s*["'`](?:admin|superadmin|super_admin)["'`]|["'`](?:admin|superadmin)["'`]\s*(?:!==?|===?)\s*[\w$.?]*\brole\b|\.email\s*(?:!==?|===?)\s*["'`][^"'`\s@]+@[^"'`\s]+["'`]|\b(?:ADMIN_EMAILS?|ADMIN_EMAIL_LIST|NEXT_PUBLIC_ADMIN\w*|VITE_ADMIN\w*|EXPO_PUBLIC_ADMIN\w*)\b|\.includes\(\s*[\w$.?]*\.email\s*\)/;
const SERVER_ADMIN_SQL = /\b(?:is_)?admins?\b|\broles?\b|app_metadata/i;
const RULES_ADMIN = /request\.auth\.token\.(?:admin|role)|auth\.token\.(?:admin|role)/;

/** Raw request bodies passed whole into a database write. */
const JS_BODY_VAR =
  /(?:const|let|var)\s+([\w$]+)\s*(?::[^=;]+)?=\s*(?:await\s+)?(?:(?:req|request|c\.req|ctx\.request|event)\s*\.\s*(?:json\s*\(\s*\)|body\b(?!\s*[.[])|formData\s*\(\s*\))|Object\.fromEntries\(\s*(?:await\s+)?[\w$.]*(?:formData|form)\b[^)]*\))/g;
const NOT_A_RECORD =
  /^(?:Response|NextResponse|URL|Error|Request|Headers|Blob|FormData|URLSearchParams|Map|Set|Date|Uint8Array|TextEncoder|TextDecoder|WeakMap|Promise|RegExp)$/;
const PY_BODY_VAR = /^[ \t]*(\w+)\s*=\s*request\.(?:json|get_json\(\s*\)|data|form|POST)\b/gm;

const SCHEMA_SENSITIVE =
  /\b(role|is_?admin|isAdmin|is_staff|is_superuser|credits|balance|plan|tier|is_?verified|emailVerified|stripe\w*|subscription\w*|price|amount)\b/;

function fileOnce(items: { file: SourceFile; index: number }[]): { file: SourceFile; index: number }[] {
  const seen = new Set<string>();
  return items.filter((i) => !seen.has(i.file.path) && seen.add(i.file.path));
}

// ---------- the check ----------

export const accessCheck: Check = {
  id: 'access',
  name: 'Access control',
  weight: 3,
  ids: [
    'server-action-no-auth',
    'api-write-no-auth',
    'missing-ownership-check',
    'user-metadata-role',
    'mass-assignment',
    'client-only-admin-check',
    'jwt-not-verified',
    'jwt-none-algorithm',
    'supabase-getsession-server',
    'test-other-users-data',
    'server-actions-middleware-only',
  ],
  run(ctx) {
    const server = serverCode(ctx);
    const client = clientCode(ctx);
    const sqlFiles = ctx.files.filter((f) => f.path.endsWith('.sql') && !/(^|\/)(?:seed|tests?)\b/.test(f.path));
    const projectPythonAuth =
      ctx.files.some((f) => f.path.endsWith('.py') && /LoginRequiredMiddleware/.test(ctx.codeOf(f))) ||
      ctx.files.some((f) => f.path.endsWith('.py') && /include_router\([^)]*dependencies\s*=/s.test(ctx.codeOf(f)));
    const units = findUnits(ctx, server, (f) => isRouteLike(f) || f.path.endsWith('.py'), projectPythonAuth);
    const authLib = detectAuth(ctx);
    const hasAccounts =
      authLib !== null ||
      ctx.findCode(AUTH_CHECK_RE, server, 1).length > 0 ||
      ctx.files.some((f) => server(f) && f.path.endsWith('.py') && PY_AUTH.test(ctx.codeOf(f)));
    const usesSupabase = ctx.usesAny(['@supabase/supabase-js', '@supabase/ssr', 'supabase']);
    const usesClerk = ctx.uses('@clerk/');

    const usesTokens = ctx.usesAny(['jsonwebtoken', 'jose', 'jwt-decode', 'pyjwt', 'python-jose']);
    if (!units.length && !sqlFiles.length && !hasAccounts && !usesSupabase && !usesClerk && !usesTokens)
      return notApplicable('No API routes, Server Actions or user accounts found');

    const out: CheckOutput = emptyOutput();
    const env: Env = { firebaseAdmin: ctx.uses('firebase-admin') };
    const loc = (u: Unit, index?: number): Location => ({
      file: u.file.path,
      line: index === undefined ? u.line : ctx.lineOf(u.file, u.start + index),
    });
    const label = (u: Unit): string =>
      u.kind === 'action'
        ? `Server Action ${u.name}`
        : u.kind === 'trpc'
          ? `tRPC procedure ${u.name}`
          : u.kind === 'python'
            ? `${u.name} (${u.method === 'ANY' ? '' : `${u.method} `}${u.urlPath ?? u.file.path})`.replace('( ', '(')
            : `${u.method === 'ANY' ? '' : `${u.method} `}${u.urlPath ?? u.file.path}`;

    // 1. Server Actions that change data without asking who is calling.
    const actions = units.filter((u) => u.kind === 'action');
    const openActions = hasAccounts
      ? actions.filter((u) => writes(u, env) && !signsInCaller(u) && !meantToBePublic(u))
      : [];
    const middlewareOnly = openActions.length > 0 && middlewareCoversPages(ctx);
    if (middlewareOnly) {
      out.manual.push({
        id: 'server-actions-middleware-only',
        title: `Check that your Server Actions are protected by more than middleware (${openActions.length} rely on it)`,
        how:
          `${openActions
            .map((u) => u.name)
            .slice(0, 5)
            .join(
              ', ',
            )} change data and only your middleware checks sign-in. Next.js recommends checking inside each action, ` +
          'because every action can be called with a direct POST request and middleware matchers are easy to get wrong (CVE-2025-29927 bypassed middleware on self-hosted apps).',
      });
    } else {
      const byFile = new Map<string, Unit[]>();
      for (const u of openActions) byFile.set(u.file.path, [...(byFile.get(u.file.path) ?? []), u]);
      for (const group of [...byFile.values()].slice(0, MAX_PER_ID)) {
        const first = group[0]!;
        const names = group.map((u) => u.name);
        const list =
          names.length > 1
            ? `${names.slice(0, 4).join(', ')}${names.length > 4 ? ` and ${names.length - 4} more` : ''}`
            : names[0]!;
        out.findings.push({
          id: 'server-action-no-auth',
          severity: 'warning',
          title: `${names.length > 1 ? `${names.length} Server Actions change` : 'A Server Action changes'} data without checking who is calling (${list})`,
          why:
            'Every exported Server Action is a public endpoint: anyone can call it with a direct POST request, even if the page that uses it is behind a login. ' +
            'We found no sign-in check inside it (such as auth(), getUser() or getServerSession()). If it is meant to be public, like a contact form, you can ignore this.',
          location: loc(first),
          fixPrompt:
            `In ${first.file.path}, the Server Action${names.length > 1 ? 's' : ''} ${list} change data in my database but never check who is calling. ` +
            'Next.js says every Server Action can be called directly with a POST request, so a check on the page does not protect it. For each action:\n' +
            `1. At the top, get the signed-in user with the auth system my app already uses${authLib ? ` (${authLib})` : ''}, and throw or return an error if there is none.\n` +
            '2. When the action changes an existing record, make sure that record belongs to this user (filter the query by the user id from the session, never from the arguments).\n' +
            '3. Never take the user id, role or price from the action arguments; read them from the session or the database.\n' +
            'Leave genuinely public actions (sign-in, sign-up, contact form) as they are and tell me which ones you left.',
        });
      }
    }
    // Only when the app has accounts: without them nothing was checked, so there is nothing to claim.
    if (hasAccounts && actions.some((u) => writes(u, env)) && !openActions.length)
      out.passed.push('Server Actions check who is calling');

    // 2. API routes that change data without asking who is calling.
    const apiUnits = units.filter((u) => u.kind !== 'action');
    const writeUnits = apiUnits.filter((u) => u.method !== 'GET' && u.method !== 'HEAD' && writes(u, env));
    const openRoutes = hasAccounts
      ? writeUnits.filter(
          (u) => !signsInCaller(u) && !meantToBePublic(u) && !(u.kind === 'route' && middlewareCovers(ctx, u.urlPath)),
        )
      : [];
    for (const u of openRoutes.slice(0, MAX_PER_ID)) {
      out.findings.push({
        id: 'api-write-no-auth',
        severity: 'warning',
        title: `Endpoint changes data without checking who is calling (${label(u)})`,
        why:
          'Your app has user accounts, but this endpoint writes to the database without a sign-in check, so anyone who finds the URL can call it. ' +
          "We looked in the handler, the helpers it imports and its middleware. If it is meant to be public, or something we couldn't see protects it, you can ignore this.",
        location: loc(u),
        fixPrompt:
          `The ${label(u)} handler in ${where(loc(u))} changes data in my database but doesn't check who is calling. Please:\n` +
          `1. Reject callers who aren't signed in (HTTP 401) using the auth system my app already uses${authLib ? ` (${authLib})` : ''}, and use the result of the check, not just call it.\n` +
          '2. If it changes an existing record, only allow it when the record belongs to the signed-in user (filter by the user id from the session).\n' +
          '3. Take the user id from the session, never from the request body or URL.\n' +
          'If this endpoint is meant to be public (a webhook, a contact form), tell me how it is protected instead (a signature check, a rate limit) and leave it.',
      });
    }
    if (hasAccounts && writeUnits.length && !openRoutes.length)
      out.passed.push('Endpoints that change data check who is calling');

    // 3. Records looked up by an id from the request, with nothing tying them to the caller.
    let lookupsSeen = 0;
    const unscoped: { u: Unit; l: Lookup }[] = [];
    for (const u of units) {
      if (!signsInCaller(u) && !(u.kind === 'route' && middlewareCovers(ctx, u.urlPath))) continue; // reported above when it writes
      const lookups = u.kind === 'python' ? pyLookups(u) : jsLookups(u, env.firebaseAdmin);
      for (const l of lookups) {
        if (l.supabase && !usesServiceRole(u)) continue; // the user's own client: Row Level Security decides
        if (originOf(l.id, u) !== 'request') continue;
        lookupsSeen++;
        if (!l.mutation && PUBLIC_MODEL.test(l.model)) continue;
        // The query is scoped, ownership is compared, or the handler ties the work to the caller somewhere else:
        // an earlier scoped lookup of the same record, or a helper called with the caller's id
        // (deleteDocument({ id, userId: ctx.user.id })), which usually means the check happens there.
        if (scopedQuery(l.query, u) || checksOwnership(u) || scopedQuery(u.text, u)) continue;
        unscoped.push({ u, l });
        break; // one per handler
      }
    }
    for (const { u, l } of unscoped.slice(0, MAX_PER_ID)) {
      const what = l.model ? `a ${l.model.replace(/s$/, '')} record` : 'a record';
      out.findings.push({
        id: 'missing-ownership-check',
        severity: 'warning',
        title: `${l.mutation ? 'Changes' : 'Loads'} ${what} by an id from the request without checking who owns it (${label(u)})`,
        why:
          'This handler checks that someone is signed in, but not that the record is theirs. A signed-in user can change the id in the URL or request and ' +
          `${l.mutation ? 'edit or delete' : 'read'} other people's data (an "IDOR", the most common access-control bug). ` +
          'We looked for an owner filter in the query (like userId: session.user.id), an owner comparison after loading it, a permission helper or an admin check, and found none. ' +
          'If this record is meant to be shared, or your database rules (RLS) already limit it, you can ignore this.',
        location: loc(u, l.index),
        fixPrompt:
          `In ${where(loc(u, l.index))}, ${label(u)} ${l.mutation ? 'changes' : 'loads'} ${what} using an id from the request, but never checks that it belongs to the signed-in user, ` +
          `so one user could ${l.mutation ? 'change or delete' : 'read'} another user's data by changing the id. Please:\n` +
          "1. Add the owner to the query itself (for example where: { id, userId: session.user.id }), or load the record and return 404 when its owner isn't the signed-in user.\n" +
          '2. Take the user id from the session, never from the request.\n' +
          '3. Check the other handlers that load records by id in the same way and fix them too.\n' +
          'If this record is genuinely meant to be visible to every signed-in user, explain that to me instead of changing it.',
      });
    }
    if (lookupsSeen && !unscoped.length)
      out.passed.push('Records looked up by id are checked against the signed-in user');

    // 4. Roles and plans read from metadata the user can edit.
    const metaFindings: { file: SourceFile; index: number; key: string; sql: boolean }[] = [];
    for (const f of sqlFiles) {
      const sql = ctx.codeOf(f);
      let pos = 0;
      for (const stmt of sql.split(';')) {
        const at = pos;
        pos += stmt.length + 1;
        const hit = SQL_META.exec(stmt);
        if (!hit) continue;
        const key = SQL_META_KEY.exec(stmt)?.[1];
        if (!/create\s+policy/i.test(stmt) && !key) continue; // copying full_name into profiles is the normal template
        metaFindings.push({ file: f, index: at + hit.index, key: key ?? 'user_metadata', sql: true });
        break;
      }
    }
    for (const m of ctx.findCode(META_READ, appCode)) {
      if (metaFindings.some((x) => x.file.path === m.file.path)) continue;
      metaFindings.push({ file: m.file, index: m.index, key: m.match[2] ?? m.match[4] ?? 'role', sql: false });
    }
    for (const mf of metaFindings.slice(0, MAX_PER_ID)) {
      const l = { file: mf.file.path, line: ctx.lineOf(mf.file, mf.index) };
      const clerk = /unsafe_?[mM]etadata/.test(lineTextAt(mf.file.content, mf.index));
      const inBrowser = !mf.sql && ctx.isClient(mf.file);
      const field = clerk ? 'unsafeMetadata' : 'user_metadata';
      out.findings.push({
        id: 'user-metadata-role',
        severity: inBrowser ? 'warning' : 'critical',
        title: mf.sql
          ? `A database rule trusts user_metadata, which every user can edit (${mf.file.path})`
          : `"${mf.key}" is read from ${field}, which every user can edit`,
        why:
          (clerk
            ? "Clerk's unsafeMetadata can be changed from the browser by the user themselves. "
            : 'Supabase lets any signed-in user change their own user_metadata with a single call (supabase.auth.updateUser). ') +
          `So anyone can give themselves ${mf.key === 'user_metadata' ? 'whatever this rule checks' : `a different "${mf.key}"`}, for example make themselves an admin or a paying customer.` +
          (inBrowser
            ? ' Here it is only read in the browser, which is fine for display, but make sure nothing on the server or in your database rules trusts it.'
            : ''),
        location: l,
        fixPrompt:
          `In ${where(l)} my app reads "${mf.key}" from ${field}, which users can edit themselves. ` +
          (clerk
            ? 'Please move roles and plans to Clerk publicMetadata or privateMetadata (only my server can change those), set them from my backend, and check them on the server with auth().sessionClaims. '
            : 'Please move roles, plans and similar fields to app_metadata (only my server can change it, via the service role key) or to a table that users cannot write to, ' +
              "and update every RLS policy and server check that reads user_metadata to use auth.jwt() -> 'app_metadata' or that table instead. ") +
          'Also check my sign-up code: users must not be able to choose their own role when they register.',
      });
    }
    if (!metaFindings.length && (usesSupabase || usesClerk))
      out.passed.push('Roles and plans are not read from metadata users can edit');

    // 5. Whole request bodies written to the database (mass assignment).
    const massHits: { file: SourceFile; index: number }[] = [];
    for (const f of ctx.files) {
      if (!server(f)) continue;
      const code = ctx.codeOf(f);
      if (f.path.endsWith('.py')) {
        const vars = [...code.matchAll(PY_BODY_VAR)].map((m) => m[1]!);
        const raw = ['request\\.(?:json|get_json\\(\\s*\\)|data|form|POST)\\b', ...vars.map((v) => `\\b${v}\\b`)].join(
          '|',
        );
        const sink = new RegExp(
          `\\b(?:[A-Z]\\w*|\\.objects\\.create|\\.objects\\.update_or_create|\\.update)\\(\\s*\\*\\*\\s*(?:${raw})`,
        );
        const m = sink.exec(code);
        if (m) massHits.push({ file: f, index: m.index });
        const drf = /class\s+\w+\s*\([^)]*Model(?:Serializer|Form)[^)]*\)\s*:[\s\S]*?(?=^class\s|(?![\s\S]))/gm;
        for (const c of code.matchAll(drf)) {
          const all = /fields\s*=\s*["']__all__["']/.exec(c[0]);
          if (all && !/read_only_fields/.test(c[0])) massHits.push({ file: f, index: c.index + all.index });
        }
        continue;
      }
      if (!/\.[cm]?[jt]sx?$/.test(f.path)) continue;
      const vars = [...code.matchAll(JS_BODY_VAR)].map((m) => m[1]!);
      // Server Action parameters arrive straight from the caller, whatever their TypeScript type says.
      // (A parameter typed as a string or number can't carry extra fields.)
      for (const u of units) {
        if (u.kind !== 'action' || u.file !== f) continue;
        const primitive = (n: string) =>
          new RegExp(`\\b${escapeRe(n)}\\??\\s*:\\s*(?:string|number|boolean|bigint|Date)\\b`).test(u.params);
        vars.push(...paramNames(u).filter((n) => !primitive(n)));
      }
      const names = [...new Set(vars)]
        .filter((v) => v.length > 1 && !/^(?:req|res|request|ctx|session|user)$/.test(v))
        .map(escapeRe);
      const raw = [
        '(?:req|request)\\.body\\b(?!\\s*[.[])',
        '(?:await\\s+)?(?:req|request|c\\.req)\\.json\\(\\s*\\)',
        'Object\\.fromEntries\\([^)]*\\)',
        ...names.map((n) => `${n}\\b(?!\\s*[.[(])`),
      ].join('|');
      const sinks = [
        new RegExp(`\\bdata\\s*:\\s*(?:\\{\\s*\\.\\.\\.\\s*)?(?:${raw})\\s*(?=[,}\\n])`, 'g'),
        new RegExp(
          `([\\w$]+)\\s*\\.\\s*(?:create|insertMany|findByIdAndUpdate|findOneAndUpdate|updateOne|updateMany|update|upsert|bulkCreate)\\s*\\(\\s*(?:[^,()]+,\\s*)?(?:\\{\\s*\\.\\.\\.\\s*)?(?:${raw})\\s*[,)}]`,
          'g',
        ),
        new RegExp(`\\bnew\\s+([A-Z][\\w$]*)\\s*\\(\\s*(?:\\{\\s*\\.\\.\\.\\s*)?(?:${raw})\\s*[,)}]`, 'g'),
        // Query builders: db.update(users).set(body), db.insert(t).values(body), supabase.from("t").insert(body)
        new RegExp(
          `\\)\\s*\\.\\s*(?:set|values|insert|update|upsert)\\s*\\(\\s*(?:\\{\\s*\\.\\.\\.\\s*)?(?:${raw})\\s*[,)}]`,
          'g',
        ),
      ];
      for (const [i, re] of sinks.entries()) {
        for (const m of code.matchAll(re)) {
          if (
            i === 0 &&
            !/\.(?:create|createMany|update|updateMany|upsert)\s*\(\s*\{[^;]*$/.test(
              code.slice(Math.max(0, m.index - 400), m.index),
            )
          )
            continue;
          if (
            i === 1 &&
            /^(?:hash|hmac|crypto|digest|sha\w*|md5|cipher|decipher|params|searchParams|headers|map|cache|set|formData|url|state|form)$/i.test(
              m[1]!,
            )
          )
            continue;
          if (i === 2 && NOT_A_RECORD.test(m[1]!)) continue;
          if (
            i === 3 &&
            /create(?:Hash|Hmac|Cipheriv|Decipheriv|Sign|Verify)\s*\([^;]*$/.test(
              code.slice(Math.max(0, m.index - 200), m.index),
            )
          )
            continue;
          massHits.push({ file: f, index: m.index });
        }
      }
    }
    const sensitiveSchema = ctx.files.find(
      (f) =>
        /(?:schema\.prisma|models\.py|schema\.[jt]s|models?\/[\w-]+\.[jt]s)$/.test(f.path) &&
        SCHEMA_SENSITIVE.test(f.content),
    );
    const sensitiveField = sensitiveSchema ? SCHEMA_SENSITIVE.exec(sensitiveSchema.content)![1] : null;
    for (const h of fileOnce(massHits.sort((a, b) => a.index - b.index)).slice(0, MAX_PER_ID)) {
      const l = { file: h.file.path, line: ctx.lineOf(h.file, h.index) };
      const drf = /__all__/.test(lineTextAt(h.file.content, h.index));
      out.findings.push({
        id: 'mass-assignment',
        severity: 'warning',
        title: drf
          ? `A serializer or form accepts every field of the model (${h.file.path})`
          : `The whole request is saved to the database as-is (${h.file.path})`,
        why:
          'When every field the caller sends is written to the database, a user can add extra fields of their own, such as ' +
          `${sensitiveField ? `"${sensitiveField}" (your schema has it)` : '"role", "isAdmin", "credits" or "userId"'}, and change things they should not be able to. ` +
          'Only the fields a user is allowed to change should be copied over.',
        location: l,
        fixPrompt:
          `In ${where(l)} my app ${drf ? 'uses fields = "__all__"' : 'passes the whole request body (or form data) straight into a database write'}. ` +
          'Please replace it with an explicit list of the fields users are allowed to set (for example with a zod schema or by picking fields one by one), ' +
          'and make sure fields like role, isAdmin, plan, credits, price and the owner id are never taken from the request. ' +
          'The owner id should come from the signed-in session. Check my other create and update handlers for the same problem.',
      });
    }
    if (!massHits.length && (writeUnits.length || actions.some((u) => writes(u, env))))
      out.passed.push('Request bodies are not saved to the database as-is');

    // 6. Admin checks that only happen in the browser.
    const clientAdmin = ctx.findCode(CLIENT_ADMIN, client);
    if (clientAdmin.length) {
      const serverAdmin =
        ctx.findCode(ADMIN_GATE, server, 1).length > 0 ||
        ctx.findCode(CLIENT_ADMIN, server, 1).length > 0 ||
        sqlFiles.some(
          (f) =>
            /create\s+policy|create\s+(?:or\s+replace\s+)?function/i.test(f.content) &&
            SERVER_ADMIN_SQL.test(ctx.codeOf(f)),
        ) ||
        ctx.files.some(
          (f) => /(?:firestore|storage)\.rules$|database\.rules\.json$/.test(f.path) && RULES_ADMIN.test(f.content),
        );
      if (!serverAdmin) {
        const first = clientAdmin[0]!;
        const l = { file: first.file.path, line: first.line };
        out.findings.push({
          id: 'client-only-admin-check',
          severity: 'warning',
          title: `Admin access is only checked in the browser (${first.file.path})`,
          why:
            'Code in the browser can be changed by anyone using it, so a check like role === "admin" or a list of admin emails there only hides buttons. ' +
            'We found no matching admin check on your server or in your database rules, so the data behind those screens may be open to every user. ' +
            'If your admin data is protected by rules set up in your database dashboard, you can ignore this.',
          location: l,
          fixPrompt:
            `In ${where(l)} my app decides who is an admin in browser code. Please make sure every admin action and every admin data query is also checked on the server ` +
            '(in the API route, Server Action, Edge Function or database policy), using a role stored where users cannot change it ' +
            '(a database table they cannot write to, Supabase app_metadata, or Clerk publicMetadata). Keep the browser check only for showing or hiding the UI.',
        });
      }
    }

    // 7. Tokens decoded but never verified.
    for (const f of ctx.files) {
      if (!server(f)) continue;
      const code = ctx.codeOf(f);
      const none = /algorithms?\s*[:=]\s*(?:\[[^\]]*["']none["']|["']none["'])/i.exec(code);
      if (none && /jwt|jose|token/i.test(code)) {
        const l = { file: f.path, line: ctx.lineOf(f, none.index) };
        out.findings.push({
          id: 'jwt-none-algorithm',
          severity: 'critical',
          title: `Tokens with no signature ("none" algorithm) are accepted (${f.path})`,
          why: 'With the "none" algorithm a token needs no signature at all, so anyone can write their own token and sign in as any user, including an admin.',
          location: l,
          fixPrompt: `In ${where(l)} my JWT code allows the "none" algorithm. Please remove it and only allow the one algorithm my tokens are actually signed with (for example HS256 or RS256), and reject every other token.`,
        });
        continue;
      }
      let decode: RegExpExecArray | null = null;
      if (f.path.endsWith('.py')) {
        if (/^\s*(?:import\s+jwt|from\s+jwt\s+import|from\s+jose\s+import)/m.test(code))
          decode = /["']verify_signature["']\s*:\s*False|\bget_unverified_claims\s*\(/.exec(code);
      } else {
        const jwtName =
          /import\s+(?:\*\s+as\s+)?([\w$]+)\s+from\s+["']jsonwebtoken["']|(?:const|let|var)\s+([\w$]+)\s*=\s*require\(\s*["']jsonwebtoken["']\s*\)/.exec(
            code,
          );
        const named = /import\s*\{[^}]*\bdecode\b[^}]*\}\s*from\s*["']jsonwebtoken["']/.test(code);
        const verified = /\.verify\s*\(|\bverify\s*\(|\bjwtVerify\s*\(|\bverifyToken\s*\(|\bverifyIdToken\s*\(/.test(
          code,
        );
        if (!verified) {
          const name = jwtName?.[1] ?? jwtName?.[2];
          decode =
            (name ? new RegExp(`\\b${escapeRe(name)}\\.decode\\s*\\(`).exec(code) : null) ??
            (named ? /\bdecode\s*\(/.exec(code) : null) ??
            // jwt-decode and hand-rolled decoding are browser tools; only count them in request handlers.
            (isRouteLike(f)
              ? (/\bdecodeJwt\s*\(|\bjwtDecode\s*\(|\bjwt_decode\s*\(/.exec(code) ??
                /JSON\.parse\(\s*(?:atob|Buffer\.from)\s*\(\s*[\w$.?]+\.split\(\s*["']\.["']\s*\)\s*\[\s*1\s*\]/.exec(
                  code,
                ))
              : /\bdecodeJwt\s*\(/.exec(code));
        }
      }
      if (!decode) continue;
      const l = { file: f.path, line: ctx.lineOf(f, decode.index) };
      out.findings.push({
        id: 'jwt-not-verified',
        severity: 'warning',
        title: `A login token is read without checking its signature (${f.path})`,
        why:
          'Decoding a token only reads what is written in it; anyone can write a token that says they are another user. ' +
          'Only a verified token proves who is calling. If this code only reads the expiry time for display, you can ignore this.',
        location: l,
        fixPrompt:
          `In ${where(l)} my server decodes a JWT without verifying its signature. Please verify it instead (jwt.verify from jsonwebtoken, jwtVerify from jose, or jwt.decode with the key and algorithms in PyJWT), ` +
          'with my secret or public key and the one algorithm I use, and reject the request when verification fails. Then use only the verified result for the user id.',
      });
    }
    if (!out.findings.some((f) => f.id.startsWith('jwt-')) && usesTokens)
      out.passed.push('Login tokens are verified, not just decoded');

    // 8. Supabase getSession() trusted on the server.
    if (usesSupabase) {
      const hits = ctx
        .findCode(/\.auth\.getSession\s*\(/, (f) => server(f) && /\.[cm]?[jt]sx?$/.test(f.path))
        .filter((m) => !/\.auth\.(?:getUser|getClaims)\s*\(/.test(ctx.codeOf(m.file)));
      for (const m of fileOnce(hits.map((h) => ({ file: h.file, index: h.index }))).slice(0, MAX_PER_ID)) {
        const l = { file: m.file.path, line: ctx.lineOf(m.file, m.index) };
        out.findings.push({
          id: 'supabase-getsession-server',
          severity: 'warning',
          title: `Server code trusts supabase.auth.getSession() (${m.file.path})`,
          why:
            'On the server, getSession() reads the login cookie without checking it with Supabase, so a forged or edited cookie is accepted. ' +
            "Supabase's own docs say never to trust it in server code; use getClaims() or getUser(), which verify the token.",
          location: l,
          fixPrompt:
            `In ${where(l)} my server code uses supabase.auth.getSession() to find out who is signed in. Please switch it to supabase.auth.getClaims() ` +
            '(or getUser()), which verifies the token, and use that result for any sign-in check or user id. Keep getSession() only where I just need to pass the access token along.',
        });
      }
    }

    // 9. What only a real test can show.
    if (hasAccounts || usesSupabase || units.length) {
      out.manual.push({
        id: 'test-other-users-data',
        title: "Try to open another user's data",
        how:
          "Create two test accounts. Signed in as the second one, open, edit and delete the first one's records by changing the id in the URL or in the request " +
          '(your browser\'s network tab shows it). Every attempt should fail with "not found" or "forbidden". Also try your admin pages and API while signed in as a normal user.',
      });
    }

    return out;
  },
};
