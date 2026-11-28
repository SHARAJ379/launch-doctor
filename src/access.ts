import type { ProjectContext, SourceFile } from './project.js';
import { evidenceOf, handlersOf, matchBracket, reach } from './routes.js';

/**
 * The places where a request from the outside world runs code: Next.js Server Actions and route
 * handlers, Express-style routes, tRPC procedures, and FastAPI / Flask / Django views.
 * The access-control check looks at each one separately.
 */
export type UnitKind = 'action' | 'route' | 'express' | 'trpc' | 'python';

export interface Unit {
  kind: UnitKind;
  file: SourceFile;
  /** Function name, or the procedure key for tRPC. Empty when it has none. */
  name: string;
  /** Upper-case HTTP method; 'ANY' when it can't be told (Django views, Pages Router default exports). */
  method: string;
  /** URL path when known ("/api/notes/:id"). */
  urlPath: string | null;
  /** The parameter list, without the parentheses. */
  params: string;
  /** Source text of the whole function (comments blanked out). */
  text: string;
  /** Index of `text` in the file. */
  start: number;
  line: number;
  /** True when the parameters come straight from the caller (Server Action arguments, tRPC input, Python view arguments). */
  paramsFromCaller: boolean;
  /** A sign-in check that sits outside the body: a wrapper, route middleware, a protected procedure, a decorator. */
  authOutside: boolean;
  /** Only admins can reach it (an admin wrapper, middleware, procedure or dependency), so it may touch anyone's records. */
  adminOnly: boolean;
  /** Code of local modules this function reaches through imports. */
  reachedCode: string;
  /** Code of the same file outside every unit (helpers defined next to it). */
  shared: string;
}

const isPython = (f: SourceFile): boolean => f.path.endsWith('.py');
const isScript = (f: SourceFile): boolean => /\.[cm]?[jt]sx?$/.test(f.path);

// ---------- JavaScript / TypeScript ----------

/** A whole file of Server Actions: "use server" is its first statement. */
export const FILE_USE_SERVER = /^\s*(?:["']use strict["'];?\s*)?["']use server["']/;

function skipString(code: string, i: number): number {
  const q = code[i]!;
  let j = i + 1;
  while (j < code.length) {
    if (code[j] === '\\') j += 2;
    else if (code[j] === q) return j + 1;
    else j++;
  }
  return code.length;
}

/** Where an expression-bodied arrow function ends. */
function expressionEnd(code: string, from: number): number {
  let depth = 0;
  for (let i = from; i < code.length; i++) {
    const ch = code[i]!;
    if (ch === '"' || ch === "'" || ch === '`') {
      i = skipString(code, i) - 1;
    } else if (ch === '(' || ch === '[' || ch === '{') depth++;
    else if (ch === ')' || ch === ']' || ch === '}') {
      if (depth === 0) return i;
      depth--;
    } else if (depth === 0 && (ch === ';' || ch === ',')) return i;
    else if (
      depth === 0 &&
      ch === '\n' &&
      /^\s*(?:export|const|let|var|function|async|import|class)\b/.test(code.slice(i + 1, i + 40))
    )
      return i;
  }
  return code.length;
}

/**
 * The body of a function whose parameter list opens at `paren`: skips a return type annotation
 * (`: Promise<{ ok: boolean }>`) and an arrow. Returns [start, end) of the body, or null.
 */
export function bodyAfterParams(code: string, paren: number): { start: number; end: number } | null {
  const close = matchBracket(code, paren);
  if (close === -1) return null;
  let angle = 0;
  let prev = ')';
  for (let i = close + 1; i < code.length; i++) {
    const ch = code[i]!;
    if (/\s/.test(ch)) continue;
    if (ch === '"' || ch === "'" || ch === '`') {
      i = skipString(code, i) - 1;
      prev = 'x';
      continue;
    }
    if (ch === '=' && code[i + 1] === '>') {
      if (angle > 0) {
        // a function type inside generics: Promise<() => void>
        i++;
        prev = '>';
        continue;
      }
      let j = i + 2;
      while (j < code.length && /\s/.test(code[j]!)) j++;
      if (code[j] === '{') {
        const end = matchBracket(code, j);
        return end === -1 ? null : { start: j, end: end + 1 };
      }
      return { start: j, end: expressionEnd(code, j) };
    }
    if (ch === '<') angle++;
    else if (ch === '>') angle = Math.max(0, angle - 1);
    else if (ch === '(') {
      const end = matchBracket(code, i);
      if (end === -1) return null;
      i = end;
      prev = ')';
      continue;
    } else if (ch === '{') {
      const end = matchBracket(code, i);
      if (end === -1) return null;
      // An object type in the annotation (": { ok: boolean }") rather than the body.
      if (angle > 0 || /[:|&,<(]/.test(prev)) {
        i = end;
        prev = '}';
        continue;
      }
      return { start: i, end: end + 1 };
    } else if (ch === ';') return null;
    prev = ch;
  }
  return null;
}

function unitFrom(
  ctx: ProjectContext,
  file: SourceFile,
  code: string,
  start: number,
  paren: number,
  fields: Pick<Unit, 'kind' | 'name' | 'method' | 'urlPath' | 'paramsFromCaller' | 'authOutside' | 'adminOnly'>,
): Unit | null {
  const close = matchBracket(code, paren);
  const body = bodyAfterParams(code, paren);
  if (close === -1 || !body) return null;
  const text = code.slice(start, body.end);
  const reached = reach(ctx, file, text);
  return {
    ...fields,
    file,
    params: code.slice(paren + 1, close),
    text,
    start,
    line: ctx.lineOf(file, start),
    reachedCode: reached.files.map((f) => ctx.codeOf(f)).join('\n'),
    shared: '',
  };
}

const EXPORTED_ASYNC_FN = /export\s+(?:default\s+)?async\s+function\s*(\w*)\s*(?:<[^>()]*>)?\s*\(/g;
const EXPORTED_ASYNC_ARROW = /export\s+const\s+(\w+)\s*(?::[^=;]+)?=\s*async\s*(?:function\s*\w*\s*)?\(/g;
const INLINE_ACTION = /(?:async\s+function\s+(\w+)\s*\(|(?:const|let)\s+(\w+)\s*=\s*async\s*\()/g;

function serverActions(ctx: ProjectContext, file: SourceFile, code: string): Unit[] {
  const out: Unit[] = [];
  const fields = (name: string) => ({
    kind: 'action' as const,
    name,
    method: 'POST',
    urlPath: null,
    paramsFromCaller: true,
    authOutside: false,
    adminOnly: false,
  });
  if (FILE_USE_SERVER.test(code)) {
    // Every exported async function in a "use server" file is an action anyone can POST to.
    for (const re of [EXPORTED_ASYNC_FN, EXPORTED_ASYNC_ARROW]) {
      re.lastIndex = 0;
      for (let m = re.exec(code); m; m = re.exec(code)) {
        const unit = unitFrom(ctx, file, code, m.index, m.index + m[0].length - 1, fields(m[1] || 'default'));
        if (unit) out.push(unit);
      }
    }
    return out;
  }
  if (!/["']use server["']/.test(code)) return out;
  // Inline actions: a function whose body starts with "use server" (inside a Server Component).
  INLINE_ACTION.lastIndex = 0;
  for (let m = INLINE_ACTION.exec(code); m; m = INLINE_ACTION.exec(code)) {
    const paren = m.index + m[0].length - 1;
    const body = bodyAfterParams(code, paren);
    if (!body || !/^\{\s*["']use server["']/.test(code.slice(body.start, body.start + 40))) continue;
    const unit = unitFrom(ctx, file, code, m.index, paren, fields(m[1] ?? m[2] ?? ''));
    if (unit) out.push(unit);
  }
  return out;
}

/** Next.js files that render pages: their default export is a component, not a request handler. */
const PAGE_FILE = /(^|\/)(?:page|layout|template|loading|error|not-found|default)\.[cm]?[jt]sx?$/;

function routeHandlers(ctx: ProjectContext, file: SourceFile): Unit[] {
  return handlersOf(ctx, file).map((h) => {
    const paren = h.text.indexOf('(');
    const close = paren === -1 ? -1 : matchBracket(h.text, paren);
    return {
      kind: 'route' as const,
      file,
      name: h.method,
      method: h.method === 'DEFAULT' ? 'ANY' : h.method,
      urlPath: h.urlPath,
      params: close === -1 ? '' : h.text.slice(paren + 1, close),
      text: h.text,
      start: ctx.codeOf(file).indexOf(h.text),
      line: h.line,
      paramsFromCaller: false,
      authOutside: evidenceOf(ctx, h).wrapped,
      adminOnly: /\b\w*[aA]dmin\w*\s*\(/.test(h.head),
      reachedCode: h.reached.map((f) => ctx.codeOf(f)).join('\n'),
      shared: '',
    };
  });
}

const EXPRESS_ROUTE = /\b(?:app|router|routes|\w+Router)\.(get|post|put|patch|delete|all)\s*\(\s*(["'`])([^"'`]*)\2/g;
/** Route middleware that signs the caller in (passed before the handler, or with app.use). */
const EXPRESS_AUTH_MW =
  /\b(?:\w*[aA]uth\w*|protect\w*|requireUser|requireLogin|ensureLoggedIn|isLoggedIn|loggedIn|verifyToken|verifyJwt|checkJwt|jwtCheck|requireSession|passport\.authenticate|clerkMiddleware|requireAdmin|isAdmin)\b/;
const EXPRESS_USE_AUTH =
  /\.use\(\s*(?:["'`][^"'`]*["'`]\s*,\s*)?[\w.]*(?:[aA]uth|protect|requireUser|requireLogin|ensureLoggedIn|verifyToken|verifyJwt|checkJwt|jwt|clerkMiddleware)\w*/;

function expressRoutes(ctx: ProjectContext, file: SourceFile, code: string): Unit[] {
  const out: Unit[] = [];
  const fileAuth = EXPRESS_USE_AUTH.test(code);
  EXPRESS_ROUTE.lastIndex = 0;
  for (let m = EXPRESS_ROUTE.exec(code); m; m = EXPRESS_ROUTE.exec(code)) {
    const open = code.indexOf('(', m.index);
    const close = matchBracket(code, open);
    if (close === -1) continue;
    const call = code.slice(open, close + 1);
    // The handler is the last function in the call; everything between the path and it is middleware.
    const fnStarts = [
      ...call.matchAll(/(?:async\s*)?(?:function\s*\w*\s*)?\(\s*(?:req|request|c|ctx)\b[^)]*\)\s*(?:=>|\{)/g),
    ];
    const last = fnStarts.at(-1);
    if (!last) continue;
    const middleware = call.slice(m[0].length - (open - m.index), last.index);
    const reached = reach(ctx, file, call);
    out.push({
      kind: 'express',
      file,
      name: `${m[1]!.toUpperCase()} ${m[3]!}`,
      method: m[1] === 'all' ? 'ANY' : m[1]!.toUpperCase(),
      urlPath: m[3] || null,
      params: '',
      text: call,
      start: open,
      line: ctx.lineOf(file, m.index),
      paramsFromCaller: false,
      authOutside: fileAuth || EXPRESS_AUTH_MW.test(middleware),
      adminOnly: /\b\w*[aA]dmin\w*\b/.test(middleware),
      reachedCode: reached.files.map((f) => ctx.codeOf(f)).join('\n'),
      shared: '',
    });
  }
  return out;
}

const TRPC_FILE = /@trpc\/server|createTRPCRouter|\bt\.router\s*\(|\bProcedure\b|\w+Procedure\s*[.=]/;
const TRPC_CALL = /\.(query|mutation)\s*\(/g;

function trpcProcedures(ctx: ProjectContext, file: SourceFile, code: string): Unit[] {
  if (!TRPC_FILE.test(code)) return [];
  const out: Unit[] = [];
  TRPC_CALL.lastIndex = 0;
  for (let m = TRPC_CALL.exec(code); m; m = TRPC_CALL.exec(code)) {
    const back = code.slice(Math.max(0, m.index - 800), m.index);
    // "name: protectedProcedure.input(...)" with no statement break before ".query(" / ".mutation(".
    const procs = [...back.matchAll(/(?:(\w+)\s*[:=]\s*)?\b(\w*[pP]rocedure)\b/g)];
    const proc = procs.at(-1);
    if (!proc || /;/.test(back.slice(proc.index))) continue;
    const open = m.index + m[0].length - 1;
    const close = matchBracket(code, open);
    if (close === -1) continue;
    const text = code.slice(open, close + 1);
    const procName = proc[2]!;
    const reached = reach(ctx, file, text);
    out.push({
      kind: 'trpc',
      file,
      name: proc[1] ?? procName,
      method: m[1] === 'mutation' ? 'POST' : 'GET',
      urlPath: null,
      params: 'input',
      text,
      start: open,
      line: ctx.lineOf(file, m.index),
      paramsFromCaller: true,
      authOutside:
        !/^public/i.test(procName) &&
        /protected|authed|auth|private|user|admin|member|org|team|signedIn/i.test(procName),
      adminOnly: /admin|superuser|staff/i.test(procName),
      reachedCode: reached.files.map((f) => ctx.codeOf(f)).join('\n'),
      shared: '',
    });
  }
  return out;
}

// ---------- Python ----------

const PY_ROUTE_DECORATOR = /^@\s*[\w.]+\.(get|post|put|patch|delete|route|api_route)\s*\(/;
/** Decorators and parameters that sign the caller in. */
export const PY_AUTH_DECORATOR =
  /^@\s*[\w.]*(?:login_required|jwt_required|auth\w*_required|requires?_auth\w*|token_required|permission_required|staff_member_required|user_passes_test|admin_required|roles_required|roles_accepted|superuser_required|authenticated)\b|^@\s*permission_classes\s*\(\s*\[[^\]]*IsAuthenticated|^@\s*[\w.]*(?:auth|login)\w*\s*$/;
/** Admin-only views: dependencies=[Depends(get_current_active_superuser)], @staff_member_required, IsAdminUser. */
const PY_ADMIN =
  /(?:Depends|Security)\(\s*[\w.]*(?:superuser|admin|staff)\w*|@\s*[\w.]*(?:staff_member_required|superuser_required|admin_required)\b|\bIsAdminUser\b/i;
const PY_AUTH_PARAM =
  /(?:Depends|Security)\(\s*[\w.]*(?:user|auth|current|session|token|login|verify|jwt|principal|account|member|admin|claims)\w*/i;

interface PyDef {
  name: string;
  indent: number;
  start: number;
  paren: number;
  decorators: string[];
}

function pythonDefs(code: string): PyDef[] {
  const out: PyDef[] = [];
  let pending: string[] = [];
  let lastEnd = 0;
  const re = /^([ \t]*)(?:(@[\w.]+)|(?:async[ \t]+)?def[ \t]+(\w+)[ \t]*\()/gm;
  for (let m = re.exec(code); m; m = re.exec(code)) {
    if (code.slice(lastEnd, m.index).trim()) pending = [];
    if (m[2]) {
      // A decorator; its arguments may span several lines.
      const after = m.index + m[0].length;
      const paren = /^\s*\(/.exec(code.slice(after, after + 20));
      let end = code.indexOf('\n', after);
      if (paren) {
        const close = matchBracket(code, after + paren[0].length - 1);
        if (close !== -1) end = close + 1;
      }
      if (end === -1) end = code.length;
      pending.push(code.slice(m.index + m[1]!.length, end));
      lastEnd = end;
      re.lastIndex = end;
      continue;
    }
    out.push({
      name: m[3]!,
      indent: m[1]!.replace(/\t/g, '    ').length,
      start: m.index + m[1]!.length,
      paren: m.index + m[0].length - 1,
      decorators: pending,
    });
    pending = [];
    lastEnd = m.index + m[0].length;
  }
  return out;
}

/** End of a Python function body: the first non-blank line indented no deeper than the def. */
function pythonBodyEnd(code: string, def: PyDef): number {
  const close = matchBracket(code, def.paren);
  let pos = close === -1 ? def.paren : close;
  pos = code.indexOf('\n', pos);
  if (pos === -1) return code.length;
  pos++;
  while (pos < code.length) {
    let next = code.indexOf('\n', pos);
    if (next === -1) next = code.length;
    const line = code.slice(pos, next);
    if (line.trim()) {
      const indent = /^[ \t]*/.exec(line)![0].replace(/\t/g, '    ').length;
      if (indent <= def.indent) return pos;
    }
    pos = next + 1;
  }
  return code.length;
}

/** FastAPI, Flask and Django views. */
function pythonViews(ctx: ProjectContext, file: SourceFile, code: string, projectAuth: boolean): Unit[] {
  const out: Unit[] = [];
  const isViewsFile = /(^|\/)views(?:\.py$|\/)/.test(file.path);
  // Sign-in applied to a whole router, app or blueprint.
  const fileAuth =
    projectAuth ||
    /(?:APIRouter|FastAPI)\s*\([^)]*dependencies\s*=\s*\[[^\]]*(?:Depends|Security)\(/s.test(code) ||
    /@\w+\.before_(?:app_)?request\b/.test(code);
  for (const def of pythonDefs(code)) {
    const decorators = def.decorators;
    const route = decorators.map((d) => PY_ROUTE_DECORATOR.exec(d)).find(Boolean);
    const apiView = decorators.find((d) => /^@\s*api_view\b/.test(d));
    const close = matchBracket(code, def.paren);
    if (close === -1) continue;
    const params = code.slice(def.paren + 1, close);
    const djangoView = isViewsFile && /^\s*request\b/.test(params);
    if (!route && !apiView && !djangoView) continue;
    let method = 'ANY';
    if (route) {
      const verb = route[1]!.toLowerCase();
      if (verb === 'route' || verb === 'api_route') {
        const listed = /methods\s*=\s*[[(]([^\])]*)[\])]/.exec(decorators.join('\n'))?.[1];
        const verbs = listed ? [...listed.matchAll(/["'](\w+)["']/g)].map((x) => x[1]!.toUpperCase()) : ['GET'];
        method = verbs.length === 1 ? verbs[0]! : verbs.some((v) => v !== 'GET') ? 'ANY' : 'GET';
      } else method = verb.toUpperCase();
    } else if (apiView) {
      const verbs = [...apiView.matchAll(/["'](\w+)["']/g)].map((x) => x[1]!.toUpperCase());
      method = verbs.length === 1 ? verbs[0]! : verbs.some((v) => v !== 'GET') ? 'ANY' : 'GET';
    }
    const end = pythonBodyEnd(code, def);
    const pathArg = route
      ? /\(\s*(?:path\s*=\s*)?["']([^"']*)["']/.exec(decorators.find((d) => PY_ROUTE_DECORATOR.test(d))!)
      : null;
    out.push({
      kind: 'python',
      file,
      name: def.name,
      method,
      urlPath: pathArg?.[1] ?? null,
      params,
      text: `${decorators.join('\n')}\n${code.slice(def.start, end)}`,
      start: def.start,
      line: ctx.lineOf(file, def.start),
      paramsFromCaller: true,
      authOutside: fileAuth || decorators.some((d) => PY_AUTH_DECORATOR.test(d)) || PY_AUTH_PARAM.test(params),
      adminOnly: PY_ADMIN.test(`${decorators.join('\n')}\n${params}`),
      reachedCode: '',
      shared: '',
    });
  }
  return out;
}

// ---------- all units ----------

/** Blank out the units' own text, leaving the helpers and module-level code around them. */
function sharedText(code: string, units: Unit[]): string {
  const chars = code.split('');
  for (const u of units) {
    if (u.start < 0) continue;
    for (let i = u.start; i < u.start + u.text.length && i < chars.length; i++) if (chars[i] !== '\n') chars[i] = ' ';
  }
  return chars.join('');
}

/**
 * Every request entry point in server code.
 * `isServer` says which files run on the server; `projectPythonAuth` is true when sign-in is enforced
 * for every Python view project-wide (Django's LoginRequiredMiddleware, a FastAPI router included with dependencies).
 */
export function findUnits(
  ctx: ProjectContext,
  isServer: (f: SourceFile) => boolean,
  isRoute: (f: SourceFile) => boolean,
  projectPythonAuth: boolean,
): Unit[] {
  const all: Unit[] = [];
  for (const file of ctx.files) {
    if (!isServer(file)) continue;
    const code = ctx.codeOf(file);
    let units: Unit[] = [];
    if (isPython(file)) {
      units = pythonViews(ctx, file, code, projectPythonAuth);
    } else if (isScript(file)) {
      units = serverActions(ctx, file, code);
      if (!FILE_USE_SERVER.test(code) && !PAGE_FILE.test(file.path) && isRoute(file)) {
        units.push(...routeHandlers(ctx, file), ...expressRoutes(ctx, file, code), ...trpcProcedures(ctx, file, code));
      }
    }
    if (!units.length) continue;
    const shared = sharedText(code, units);
    for (const u of units) u.shared = shared;
    all.push(...units);
  }
  return all;
}
