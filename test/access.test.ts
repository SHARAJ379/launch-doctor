import assert from 'node:assert/strict';
import { test } from 'node:test';
import { runDoctor } from '../src/index.js';
import type { Report } from '../src/types.js';
import { category, makeProject } from './helpers.js';

/** Scan a throwaway project and return the access-control category. */
async function access(files: Record<string, string>) {
  const report: Report = await runDoctor(makeProject(files), { offline: true, useGit: false, only: ['access'] });
  return category(report, 'access');
}

const findingIds = (c: Awaited<ReturnType<typeof access>>) => c.findings.map((f) => f.id);

const nextPkg = (extra: Record<string, string> = {}) =>
  JSON.stringify({
    name: 'app',
    dependencies: { next: '^16.0.0', react: '^19.0.0', '@prisma/client': '^7.0.0', 'next-auth': '^5.0.0', ...extra },
  });

// ---------- Server Actions ----------

test('a Server Action that deletes data without a sign-in check is flagged', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/notes/actions.ts': `'use server';
import { prisma } from '@/lib/prisma';
export async function deleteNote(id: string) {
  await prisma.note.delete({ where: { id } });
}
export async function renameNote(id: string, title: string) {
  await prisma.note.update({ where: { id }, data: { title } });
}
`,
    'lib/prisma.ts': `export const prisma = {} as any;\n`,
  });
  const f = c.findings.filter((x) => x.id === 'server-action-no-auth');
  assert.equal(f.length, 1, 'grouped into one finding per file');
  assert.match(f[0]!.title, /2 Server Actions/);
  assert.match(f[0]!.title, /deleteNote, renameNote/);
  assert.equal(f[0]!.location?.file, 'app/notes/actions.ts');
  assert.equal(f[0]!.location?.line, 3);
  assert.equal(f[0]!.severity, 'warning');
});

test('Server Actions that check the session, or are sign-in flows, are not flagged', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/actions.ts': `"use server";
import { auth } from '@/auth';
export async function deleteNote(id: string) {
  const session = await auth();
  if (!session?.user) throw new Error('Unauthorized');
  await prisma.note.delete({ where: { id, userId: session.user.id } });
}
export async function signUp(email: string) {
  await prisma.user.create({ data: { email } });
}
export const updateProfile = async (name: string): Promise<{ ok: boolean }> => {
  const user = await requireUser();
  await prisma.user.update({ where: { id: user.id }, data: { name } });
  return { ok: true };
};
`,
  });
  assert.deepEqual(findingIds(c), []);
  assert.ok(c.passed.includes('Server Actions check who is calling'));
});

test('an inline "use server" action inside a page is found', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/admin/page.tsx': `import { auth } from '@/auth';
export default async function Page() {
  const session = await auth();
  if (!session) redirect('/login');
  async function wipe() {
    'use server';
    await db.record.deleteMany();
  }
  return <form action={wipe}><button>Wipe</button></form>;
}
`,
  });
  // The page checks sign-in, but the action itself doesn't: Next.js says that doesn't carry over.
  assert.deepEqual(findingIds(c), ['server-action-no-auth']);
  assert.match(c.findings[0]!.title, /wipe/);
});

test('a helper defined in the same file that checks the session counts as a sign-in check', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/actions.ts': `'use server';
async function me() {
  const session = await getServerSession();
  if (!session) throw new Error('no');
  return session.user;
}
export async function addTodo(text: string) {
  const user = await me();
  await prisma.todo.create({ data: { text, userId: user.id } });
}
`,
  });
  assert.deepEqual(findingIds(c), []);
});

test('Server Actions in an app without accounts are not flagged', async () => {
  const c = await access({
    'package.json': JSON.stringify({ dependencies: { next: '^16.0.0', '@prisma/client': '^7.0.0' } }),
    'app/actions.ts': `'use server';\nexport async function addVote(id: string) { await prisma.poll.update({ where: { id }, data: { votes: { increment: 1 } } }); }\n`,
  });
  assert.deepEqual(findingIds(c), []);
});

test('Server Actions behind a blocking catch-all middleware become a checklist item, not a finding', async () => {
  const c = await access({
    'package.json': nextPkg({ '@clerk/nextjs': '^7.0.0' }),
    'middleware.ts': `import { clerkMiddleware } from '@clerk/nextjs/server';
export default clerkMiddleware(async (auth) => { await auth.protect(); });
export const config = { matcher: ['/((?!_next|.*\\\\..*).*)'] };
`,
    'app/actions.ts': `'use server';\nexport async function removeItem(id: string) { await prisma.item.delete({ where: { id } }); }\n`,
  });
  assert.deepEqual(findingIds(c), []);
  assert.ok(c.manual.some((m) => m.id === 'server-actions-middleware-only'));
});

test('Server Actions that write through the Supabase user client are left to RLS', async () => {
  const c = await access({
    'package.json': JSON.stringify({ dependencies: { next: '^16.0.0', '@supabase/ssr': '^1.0.0' } }),
    'app/actions.ts': `'use server';
import { createClient } from '@/lib/supabase/server';
export async function deleteNote(id: string) {
  const supabase = await createClient();
  await supabase.from('notes').delete().eq('id', id);
}
`,
    'app/login.tsx': `'use client';\nexport const L = () => supabase.auth.signInWithOtp({ email: '' });\n`,
  });
  assert.ok(!findingIds(c).includes('server-action-no-auth'));
});

// ---------- API routes ----------

test('a route handler that writes without sign-in is flagged, a webhook is not', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/api/notes/route.ts': `export async function POST(req: Request) {
  const { text } = await req.json();
  await prisma.note.create({ data: { text } });
  return Response.json({ ok: true });
}
export async function GET() { return Response.json(await prisma.note.findMany()); }
`,
    'app/api/webhooks/stripe/route.ts': `export async function POST(req: Request) {
  const event = stripe.webhooks.constructEvent(await req.text(), sig, secret);
  await prisma.order.update({ where: { id: event.data.object.id }, data: { paid: true } });
}
`,
    'app/dashboard/page.tsx': `import { auth } from '@/auth';\nexport default async function P() { const s = await auth(); return null; }\n`,
  });
  const f = c.findings.filter((x) => x.id === 'api-write-no-auth');
  assert.equal(f.length, 1);
  assert.match(f[0]!.title, /POST \/api\/notes/);
});

test('an Express route with auth middleware passes, one without it is flagged', async () => {
  const c = await access({
    'package.json': JSON.stringify({ dependencies: { express: '^5.0.0', mongoose: '^9.0.0', passport: '^0.7.0' } }),
    'server/routes.ts': `import express from 'express';
const router = express.Router();
router.post('/posts', requireAuth, async (req, res) => {
  await Post.create({ title: req.body.title, author: req.user.id });
  res.json({ ok: true });
});
router.delete('/posts/:id', async (req, res) => {
  await Post.findByIdAndDelete(req.params.id);
  res.sendStatus(204);
});
export default router;
`,
  });
  const f = c.findings.filter((x) => x.id === 'api-write-no-auth');
  assert.equal(f.length, 1);
  assert.match(f[0]!.title, /DELETE \/posts\/:id/);
});

// ---------- ownership (IDOR) ----------

test('a signed-in route that loads a record by URL id without an owner filter is flagged', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/api/invoices/[id]/route.ts': `import { auth } from '@/auth';
export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session) return new Response('Unauthorized', { status: 401 });
  const { id } = await params;
  const invoice = await prisma.invoice.findUnique({ where: { id } });
  return Response.json(invoice);
}
`,
  });
  const f = c.findings.find((x) => x.id === 'missing-ownership-check');
  assert.ok(f, JSON.stringify(c.findings));
  assert.match(f.title, /Loads a invoice record|invoice record/);
  assert.equal(f.location?.line, 6);
});

test('ownership checks in the forms apps really use are accepted', async () => {
  const route = (body: string) => `import { auth } from '@/auth';
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
${body}
}
`;
  const c = await access({
    'package.json': nextPkg({ 'drizzle-orm': '^1.0.0', mongoose: '^9.0.0' }),
    // scoped where
    'app/api/a/[id]/route.ts': route(
      `  await prisma.note.delete({ where: { id: params.id, userId: session.user.id } });`,
    ),
    // fetch then compare (the official Next.js pattern)
    'app/api/b/[id]/route.ts': route(
      `  const post = await prisma.post.findUnique({ where: { id: params.id } });\n  if (post.authorId !== session.user.id) return new Response(null, { status: 403 });\n  await prisma.post.delete({ where: { id: params.id } });`,
    ),
    // drizzle and(...)
    'app/api/c/[id]/route.ts': route(
      `  await db.delete(notes).where(and(eq(notes.id, params.id), eq(notes.userId, session.user.id)));`,
    ),
    // relation filter
    'app/api/d/[id]/route.ts': route(
      `  await prisma.doc.delete({ where: { id: params.id, workspace: { members: { some: { userId: session.user.id } } } } });`,
    ),
    // policy helper
    'app/api/e/[id]/route.ts': route(
      `  const doc = await prisma.doc.findUnique({ where: { id: params.id } });\n  await assertCanEdit(session.user, doc);\n  await prisma.doc.delete({ where: { id: params.id } });`,
    ),
    // admin gate
    'app/api/f/[id]/route.ts': route(
      `  if (session.user.role !== 'admin') return new Response(null, { status: 403 });\n  await prisma.user.delete({ where: { id: params.id } });`,
    ),
    // lookup of the caller's own record
    'app/api/g/route.ts': `import { auth } from '@/auth';
export async function PATCH(req: Request) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  await prisma.user.update({ where: { id: session.user.id }, data: { name: 'x' } });
}
`,
  });
  assert.deepEqual(
    c.findings.filter((x) => x.id === 'missing-ownership-check').map((x) => x.location?.file),
    [],
  );
  assert.ok(c.passed.includes('Records looked up by id are checked against the signed-in user'));
});

test('an owner filter taken from the request body does not count', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/api/notes/route.ts': `import { auth } from '@/auth';
export async function PUT(req: Request) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  const body = await req.json();
  await prisma.note.update({ where: { id: body.id, userId: body.userId }, data: { text: body.text } });
}
`,
  });
  assert.ok(findingIds(c).includes('missing-ownership-check'));
});

test('reading a public-looking model by id is not flagged, changing one is', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/api/products/[id]/route.ts': `import { auth } from '@/auth';
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  return Response.json(await prisma.product.findUnique({ where: { id: params.id } }));
}
export async function DELETE(req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  await prisma.product.delete({ where: { id: params.id } });
}
`,
  });
  const f = c.findings.filter((x) => x.id === 'missing-ownership-check');
  assert.equal(f.length, 1);
  assert.match(f[0]!.title, /^Changes/);
});

test('a tRPC protected mutation that deletes by input id is flagged', async () => {
  const c = await access({
    'package.json': JSON.stringify({
      dependencies: { '@trpc/server': '^11.0.0', '@prisma/client': '^7.0.0', 'next-auth': '^5.0.0' },
    }),
    'src/server/api/routers/note.ts': `import { createTRPCRouter, protectedProcedure } from '../trpc';
import { z } from 'zod';
export const noteRouter = createTRPCRouter({
  delete: protectedProcedure.input(z.object({ id: z.string() })).mutation(async ({ ctx, input }) => {
    return ctx.db.note.delete({ where: { id: input.id } });
  }),
  mine: protectedProcedure.query(({ ctx }) => ctx.db.note.findMany({ where: { userId: ctx.session.user.id } })),
});
`,
  });
  assert.deepEqual(findingIds(c), ['missing-ownership-check']);
  assert.match(c.findings[0]!.title, /tRPC procedure delete/);
});

test('a Supabase service-role client in a route needs its own owner filter; the user client does not', async () => {
  const route = (client: string) => `import { createClient } from '@supabase/supabase-js';
const supabase = ${client};
export async function GET(req: Request, { params }: { params: { id: string } }) {
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response(null, { status: 401 });
  const { data } = await supabase.from('invoices').select('*').eq('id', params.id).single();
  return Response.json(data);
}
`;
  const pkg = JSON.stringify({ dependencies: { next: '^16.0.0', '@supabase/supabase-js': '^2.0.0' } });
  const admin = await access({
    'package.json': pkg,
    'app/api/invoices/[id]/route.ts': route('createClient(url, process.env.SUPABASE_SERVICE_ROLE_KEY!)'),
  });
  assert.ok(findingIds(admin).includes('missing-ownership-check'));
  const user = await access({
    'package.json': pkg,
    'app/api/invoices/[id]/route.ts': route('createClient(url, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!)'),
  });
  assert.ok(!findingIds(user).includes('missing-ownership-check'));
});

// ---------- Python ----------

test('FastAPI: a signed-in route that deletes by path id without an owner filter is flagged', async () => {
  const c = await access({
    'requirements.txt': 'fastapi\nsqlalchemy\n',
    'app/main.py': `from fastapi import FastAPI, Depends
app = FastAPI()

@app.delete("/notes/{note_id}")
def delete_note(note_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    note = db.get(Note, note_id)
    db.delete(note)
    db.commit()

@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    todo = db.scalar(select(Todo).where(Todo.id == todo_id, Todo.owner_id == user.id))
    db.delete(todo)
    db.commit()

@app.post("/items")
def add_item(db: Session = Depends(get_db)):
    db.add(Item())
    db.commit()
`,
  });
  const own = c.findings.filter((x) => x.id === 'missing-ownership-check');
  assert.equal(own.length, 1, JSON.stringify(c.findings, null, 1));
  assert.match(own[0]!.title, /delete_note/);
  const open = c.findings.filter((x) => x.id === 'api-write-no-auth');
  assert.equal(open.length, 1);
  assert.match(open[0]!.title, /add_item/);
});

test('Django: get_object_or_404 without an owner, and a serializer with every field, are flagged', async () => {
  const c = await access({
    'requirements.txt': 'django\ndjangorestframework\n',
    'notes/views.py': `from django.contrib.auth.decorators import login_required

@login_required
def note_detail(request, pk):
    note = get_object_or_404(Note, pk=pk)
    return render(request, "note.html", {"note": note})

@login_required
def my_note(request, pk):
    note = get_object_or_404(Note, pk=pk, owner=request.user)
    return render(request, "note.html", {"note": note})
`,
    'notes/serializers.py': `from rest_framework import serializers

class NoteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = "__all__"

class SafeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Note
        fields = ["title"]
`,
  });
  const own = c.findings.filter((x) => x.id === 'missing-ownership-check');
  assert.equal(own.length, 1);
  assert.match(own[0]!.title, /note_detail/);
  const mass = c.findings.filter((x) => x.id === 'mass-assignment');
  assert.equal(mass.length, 1);
  assert.equal(mass[0]!.location?.line, 6);
});

// ---------- metadata ----------

test('an RLS policy that trusts user_metadata is critical', async () => {
  const c = await access({
    'package.json': JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2.0.0' } }),
    'supabase/migrations/001.sql': `create table orders (id uuid primary key);
alter table orders enable row level security;
create policy "admins" on orders for all
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
`,
  });
  const f = c.findings.find((x) => x.id === 'user-metadata-role');
  assert.ok(f);
  assert.equal(f.severity, 'critical');
  assert.equal(f.location?.line, 4);
});

test('the standard handle_new_user trigger copying full_name is not flagged, copying a role is', async () => {
  const trigger = (key: string) => `create function public.handle_new_user() returns trigger as $$
begin
  insert into public.profiles (id, ${key}) values (new.id, new.raw_user_meta_data->>'${key}');
  return new;
end;
$$ language plpgsql security definer;
`;
  const pkg = JSON.stringify({ dependencies: { '@supabase/supabase-js': '^2.0.0' } });
  const ok = await access({ 'package.json': pkg, 'supabase/migrations/001.sql': trigger('full_name') });
  assert.ok(!findingIds(ok).includes('user-metadata-role'));
  const bad = await access({ 'package.json': pkg, 'supabase/migrations/001.sql': trigger('role') });
  assert.ok(findingIds(bad).includes('user-metadata-role'));
});

test('a role read from user_metadata is critical on the server and a warning in the browser', async () => {
  const c = await access({
    'package.json': JSON.stringify({ dependencies: { next: '^16.0.0', '@supabase/ssr': '^1.0.0' } }),
    'app/api/admin/route.ts': `export async function GET() {
  const { data: { user } } = await supabase.auth.getUser();
  if (user?.user_metadata?.role !== 'admin') return new Response(null, { status: 403 });
  return Response.json({});
}
`,
    'components/Nav.tsx': `'use client';\nexport const Nav = ({ user }) => user.user_metadata['is_admin'] ? <a href="/admin">Admin</a> : null;\n`,
  });
  const f = c.findings.filter((x) => x.id === 'user-metadata-role');
  assert.deepEqual(
    f.map((x) => [x.location?.file, x.severity]),
    [
      ['app/api/admin/route.ts', 'critical'],
      ['components/Nav.tsx', 'warning'],
    ],
  );
});

test("Clerk's unsafeMetadata used for a role is flagged; display names from user_metadata are not", async () => {
  const c = await access({
    'package.json': JSON.stringify({ dependencies: { next: '^16.0.0', '@clerk/nextjs': '^7.0.0' } }),
    'middleware.ts': `export default clerkMiddleware(async (auth, req) => {\n  const user = await currentUser();\n  if (user?.unsafeMetadata.role === 'admin') return;\n});\n`,
    'components/Hello.tsx': `'use client';\nexport const Hello = ({ user }) => <p>Hi {user.user_metadata.full_name}</p>;\n`,
  });
  const f = c.findings.filter((x) => x.id === 'user-metadata-role');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.location?.file, 'middleware.ts');
  assert.match(f[0]!.title, /unsafeMetadata/);
});

// ---------- mass assignment ----------

test('saving req.body or a spread of it is flagged; picked fields and zod-parsed data are not', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'prisma/schema.prisma': 'model User {\n  id String @id\n  role String @default("user")\n}\n',
    'app/api/profile/route.ts': `import { auth } from '@/auth';
export async function PATCH(req: Request) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  const body = await req.json();
  await prisma.user.update({ where: { id: session.user.id }, data: { ...body } });
}
`,
    'app/api/safe/route.ts': `import { auth } from '@/auth';
export async function PATCH(req: Request) {
  const session = await auth();
  if (!session) return new Response(null, { status: 401 });
  const body = await req.json();
  const data = Profile.parse(body);
  await prisma.user.update({ where: { id: session.user.id }, data });
  await prisma.user.update({ where: { id: session.user.id }, data: { name: body.name } });
}
`,
  });
  const f = c.findings.filter((x) => x.id === 'mass-assignment');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.location?.file, 'app/api/profile/route.ts');
  assert.match(f[0]!.why, /"role" \(your schema has it\)/);
});

test('Mongoose create(req.body) is flagged; new Response(body) and hash.update(body) are not', async () => {
  const c = await access({
    'package.json': JSON.stringify({ dependencies: { express: '^5.0.0', mongoose: '^9.0.0' } }),
    'server/api.ts': `app.post('/signup', async (req, res) => {
  const user = await User.create(req.body);
  res.json(user);
});
`,
    'server/proxy.ts': `export async function handler(req: Request) {
  const body = await req.json();
  hash.update(body);
  return new Response(body);
}
`,
  });
  const f = c.findings.filter((x) => x.id === 'mass-assignment');
  assert.deepEqual(
    f.map((x) => x.location?.file),
    ['server/api.ts'],
  );
});

// ---------- client-only admin ----------

test('an admin check only in the browser is flagged; with a server-side check it passes', async () => {
  const files = {
    'package.json': JSON.stringify({
      dependencies: { react: '^19.0.0', vite: '^7.0.0', '@supabase/supabase-js': '^2.0.0' },
    }),
    'src/pages/Admin.tsx': `export function Admin({ user }) {\n  if (user.email !== 'me@site.com') return null;\n  return <AdminPanel />;\n}\n`,
  };
  const open = await access(files);
  assert.ok(findingIds(open).includes('client-only-admin-check'));
  const guarded = await access({
    ...files,
    'supabase/migrations/001.sql': `create policy "admins read all" on orders for select using (exists (select 1 from admins where user_id = auth.uid()));\n`,
  });
  assert.ok(!findingIds(guarded).includes('client-only-admin-check'));
});

// ---------- tokens ----------

test('jwt.decode without verify is flagged, verify is not, and the none algorithm is critical', async () => {
  const c = await access({
    'package.json': JSON.stringify({ dependencies: { express: '^5.0.0', jsonwebtoken: '^9.0.0' } }),
    'server/auth.ts': `import jwt from 'jsonwebtoken';\nexport const who = (t: string) => (jwt.decode(t) as any).sub;\n`,
    'server/ok.ts': `import jwt from 'jsonwebtoken';\nexport const who = (t: string) => jwt.verify(t, process.env.SECRET!);\n`,
    'server/none.ts': `import jwt from 'jsonwebtoken';\nexport const who = (t: string) => jwt.verify(t, key, { algorithms: ['HS256', 'none'] });\n`,
    // Reading the expiry in the browser is fine: the server still verifies.
    'components/Session.tsx': `'use client';\nimport { jwtDecode } from 'jwt-decode';\nexport const exp = (t: string) => jwtDecode(t).exp;\n`,
  });
  assert.deepEqual(
    c.findings.filter((x) => x.id.startsWith('jwt-')).map((x) => [x.id, x.location?.file, x.severity]),
    [
      ['jwt-not-verified', 'server/auth.ts', 'warning'],
      ['jwt-none-algorithm', 'server/none.ts', 'critical'],
    ],
  );
});

test('PyJWT with verify_signature off is flagged', async () => {
  const c = await access({
    'requirements.txt': 'flask\npyjwt\n',
    'app/auth.py': `import jwt\n\ndef user_id(token):\n    return jwt.decode(token, options={"verify_signature": False})["sub"]\n`,
  });
  assert.ok(findingIds(c).includes('jwt-not-verified'));
});

// ---------- Supabase getSession ----------

test('getSession() in server code is flagged unless the file verifies with getUser/getClaims', async () => {
  const c = await access({
    'package.json': JSON.stringify({ dependencies: { next: '^16.0.0', '@supabase/ssr': '^1.0.0' } }),
    'app/dashboard/page.tsx': `export default async function Page() {\n  const { data: { session } } = await supabase.auth.getSession();\n  if (!session) redirect('/login');\n  return null;\n}\n`,
    'app/settings/page.tsx': `export default async function Page() {\n  const { data } = await supabase.auth.getClaims();\n  const { data: { session } } = await supabase.auth.getSession();\n  return null;\n}\n`,
    'components/Menu.tsx': `'use client';\nexport const M = () => supabase.auth.getSession();\n`,
  });
  assert.deepEqual(
    c.findings.filter((x) => x.id === 'supabase-getsession-server').map((x) => x.location?.file),
    ['app/dashboard/page.tsx'],
  );
});

// ---------- the category as a whole ----------

test('a CLI tool with no routes or accounts skips the category', async () => {
  const c = await access({
    'package.json': JSON.stringify({ name: 'tool', bin: { tool: 'cli.js' } }),
    'cli.js': 'console.log(process.argv);\n',
  });
  assert.equal(c.applicable, false);
});

test('a clean app gets an A in access control with the manual check', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/api/notes/[id]/route.ts': `import { auth } from '@/auth';
export async function DELETE(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session?.user) return new Response('Unauthorized', { status: 401 });
  const { id } = await params;
  await prisma.note.deleteMany({ where: { id, userId: session.user.id } });
  return new Response(null, { status: 204 });
}
`,
  });
  assert.deepEqual(findingIds(c), []);
  assert.equal(c.grade, 'A');
  assert.ok(c.manual.some((m) => m.id === 'test-other-users-data'));
});

test('every finding has a fix prompt that names the file', async () => {
  const c = await access({
    'package.json': nextPkg({ jsonwebtoken: '^9.0.0' }),
    'app/actions.ts': `'use server';\nexport async function del(id: string) { await prisma.x.delete({ where: { id } }); }\n`,
    'app/api/a/route.ts': `import jwt from 'jsonwebtoken';\nexport async function POST(req: Request) { const b = await req.json(); await prisma.y.create({ data: b }); jwt.decode(b.t); }\n`,
  });
  assert.ok(c.findings.length >= 3);
  for (const f of c.findings) {
    assert.ok(f.location?.file, f.id);
    assert.ok(f.fixPrompt.includes(f.location.file), `${f.id} prompt doesn't name ${f.location.file}`);
    assert.ok(c.findings.every((x) => x.why.length > 40));
  }
});

// ---------- regressions from real open-source apps ----------

test('regression: a Server Action that stores a string argument in a cookie is not mass assignment (vercel/ai-chatbot)', async () => {
  const c = await access({
    'package.json': nextPkg(),
    'app/actions.ts': `"use server";
import { cookies } from "next/headers";
export async function saveChatModelAsCookie(model: string) {
  const cookieStore = await cookies();
  cookieStore.set("chat-model", model);
}
`,
  });
  assert.ok(!findingIds(c).includes('mass-assignment'), JSON.stringify(c.findings));
});

test('regression: a FastAPI route with an admin-only dependency is not an ownership problem (full-stack-fastapi-template)', async () => {
  const c = await access({
    'requirements.txt': 'fastapi\nsqlmodel\n',
    'app/api/routes/users.py': `from fastapi import APIRouter, Depends
router = APIRouter(prefix="/users")

@router.delete("/{user_id}", dependencies=[Depends(get_current_active_superuser)])
def delete_user(session: SessionDep, current_user: CurrentUser, user_id: uuid.UUID):
    user = session.get(User, user_id)
    session.delete(user)
    session.commit()
`,
  });
  assert.deepEqual(findingIds(c), []);
});

test('query builders: drizzle .set(body) and supabase .insert(body) are mass assignment, a hash update is not', async () => {
  const c = await access({
    'package.json': JSON.stringify({
      dependencies: { next: '^16.0.0', 'drizzle-orm': '^1.0.0', '@supabase/supabase-js': '^2.0.0' },
    }),
    'app/api/a/route.ts': `export async function PATCH(req: Request) {\n  const body = await req.json();\n  await db.update(users).set(body).where(eq(users.id, 1));\n}\n`,
    'app/api/b/route.ts': `export async function POST(req: Request) {\n  const body = await req.json();\n  await supabase.from('profiles').insert(body);\n}\n`,
    'app/api/c/route.ts': `export async function POST(req: Request) {\n  const body = await req.json();\n  const sig = crypto.createHash('sha256').update(body).digest('hex');\n}\n`,
  });
  assert.deepEqual(
    c.findings.filter((x) => x.id === 'mass-assignment').map((x) => x.location?.file),
    ['app/api/a/route.ts', 'app/api/b/route.ts'],
  );
});

test('regression: tRPC admin procedures may load any record by id (documenso)', async () => {
  const c = await access({
    'package.json': JSON.stringify({
      dependencies: { '@trpc/server': '^11.0.0', '@prisma/client': '^7.0.0', 'next-auth': '^5.0.0' },
    }),
    'packages/trpc/server/admin-router/delete-claim.ts': `import { adminProcedure } from '../trpc';
export const deleteClaimRoute = adminProcedure.input(ZRequest).mutation(async ({ input }) => {
  const { id } = input;
  await prisma.subscriptionClaim.delete({ where: { id } });
});
`,
    'server/routes.ts': `router.delete('/users/:id', requireAdmin, async (req, res) => {\n  await User.findByIdAndDelete(req.params.id);\n  res.sendStatus(204);\n});\n`,
  });
  assert.deepEqual(findingIds(c), []);
});

test('regression: a lookup whose result is passed on with the caller id counts as delegated ownership (documenso)', async () => {
  const c = await access({
    'package.json': JSON.stringify({
      dependencies: { '@trpc/server': '^11.0.0', '@prisma/client': '^7.0.0', 'next-auth': '^5.0.0' },
    }),
    'packages/trpc/server/envelope-router/delete-envelope.ts': `export const deleteEnvelopeRoute = authenticatedProcedure
  .input(ZDeleteEnvelopeRequestSchema)
  .mutation(async ({ input, ctx }) => {
    const { teamId } = ctx;
    const { envelopeId } = input;
    const unsafeEnvelope = await prisma.envelope.findUnique({ where: { id: envelopeId }, select: { type: true } });
    if (!unsafeEnvelope) throw new AppError('NOT_FOUND');
    await deleteDocument({ id: envelopeId, userId: ctx.user.id, teamId });
  });
`,
  });
  assert.deepEqual(findingIds(c), []);
});

test('regression: jwt-decode in frontend code we cannot classify is not flagged (juice-shop Angular app)', async () => {
  const c = await access({
    'package.json': JSON.stringify({
      dependencies: { express: '^5.0.0', 'jwt-decode': '^4.0.0', jsonwebtoken: '^9.0.0' },
    }),
    'frontend/src/app/app.guard.ts': `import { jwtDecode } from 'jwt-decode';\nexport const payload = (t: string) => jwtDecode(t);\n`,
    'routes/me.ts': `import { jwtDecode } from 'jwt-decode';\nexport const me = () => (req, res) => res.json(jwtDecode(req.cookies.token));\n`,
  });
  assert.deepEqual(
    c.findings.map((x) => x.location?.file),
    ['routes/me.ts'],
  );
});

test('regression: an update after a lookup scoped to the caller is not flagged (documenso)', async () => {
  const c = await access({
    'package.json': JSON.stringify({
      dependencies: { '@trpc/server': '^11.0.0', '@prisma/client': '^7.0.0', 'next-auth': '^5.0.0' },
    }),
    'server/router/update-email.ts': `export const updateEmailRoute = authenticatedProcedure.input(Z).mutation(async ({ input, ctx }) => {
  const { emailId, emailName } = input;
  const { user } = ctx;
  const email = await prisma.organisationEmail.findFirst({
    where: { id: emailId, organisation: buildOrganisationWhereQuery({ userId: user.id }) },
  });
  if (!email) throw new AppError('UNAUTHORIZED');
  await prisma.organisationEmail.update({ where: { id: emailId }, data: { emailName } });
});
`,
  });
  assert.deepEqual(findingIds(c), []);
});

// ---------- every stack the README names ----------

test('Flask: a POST route without @login_required that writes is flagged, a protected one is not', async () => {
  const c = await access({
    'requirements.txt': 'flask\nflask-login\nsqlalchemy\n',
    'app.py': `from flask import Flask, request
from flask_login import login_required, current_user
app = Flask(__name__)

@app.route("/notes", methods=["POST"])
def add_note():
    db.session.add(Note(text=request.form["text"]))
    db.session.commit()
    return "ok"

@app.route("/notes/<int:note_id>", methods=["DELETE"])
@login_required
def delete_note(note_id):
    note = Note.query.get_or_404(note_id)
    if note.owner_id != current_user.id:
        abort(403)
    db.session.delete(note)
    db.session.commit()
    return "ok"
`,
  });
  assert.deepEqual(
    c.findings.map((x) => [x.id, x.title.includes('add_note')]),
    [['api-write-no-auth', true]],
  );
});

test('Sequelize findByPk and Firebase Admin doc lookups by request id are checked for ownership', async () => {
  const c = await access({
    'package.json': JSON.stringify({
      dependencies: { express: '^5.0.0', sequelize: '^7.0.0', 'firebase-admin': '^13.0.0', passport: '^0.7.0' },
    }),
    'server/routes.ts': `router.put('/orders/:id', requireAuth, async (req, res) => {
  const order = await Order.findByPk(req.params.id);
  await order.update({ status: 'cancelled' });
  res.json(order);
});
router.get('/files/:id', requireAuth, async (req, res) => {
  const snap = await db.collection('files').doc(req.params.id).get();
  res.json(snap.data());
});
router.get('/mine/:id', requireAuth, async (req, res) => {
  const snap = await db.collection('files').doc(req.params.id).get();
  if (snap.data().uid !== req.user.uid) return res.sendStatus(404);
  res.json(snap.data());
});
`,
  });
  assert.deepEqual(
    c.findings.filter((x) => x.id === 'missing-ownership-check').map((x) => x.location?.line),
    [2, 7],
  );
});

test('a Django ModelForm with every field, and a Server Action argument saved whole, are mass assignment', async () => {
  const c = await access({
    'requirements.txt': 'django\n',
    'package.json': nextPkg(),
    'accounts/forms.py': `from django import forms\n\nclass ProfileForm(forms.ModelForm):\n    class Meta:\n        model = Profile\n        fields = "__all__"\n`,
    'app/actions.ts': `'use server';
export async function saveProfile(profile: ProfileInput) {
  const session = await auth();
  if (!session) throw new Error('no');
  await prisma.profile.update({ where: { userId: session.user.id }, data: profile });
}
`,
  });
  assert.deepEqual(
    c.findings
      .filter((x) => x.id === 'mass-assignment')
      .map((x) => x.location?.file)
      .sort(),
    ['accounts/forms.py', 'app/actions.ts'],
  );
});
