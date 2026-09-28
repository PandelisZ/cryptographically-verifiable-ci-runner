import fs from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { threadId } from "node:worker_threads";
const orig = { appendFileSync: fs.appendFileSync };
const log = (m) => orig.appendFileSync(new URL("./preload.log", import.meta.url), `tid=${threadId} file=${globalThis.__vitest_worker__?.filepath?.split('/').pop()} ${m}\n`);
const INTERNAL = /\/node_modules\/(vitest|@vitest\/[^/]+|vite)\//;
function frames() {
  const lim = Error.stackTraceLimit, prep = Error.prepareStackTrace;
  Error.stackTraceLimit = 100; Error.prepareStackTrace = (_, cs) => cs;
  const o = {}; Error.captureStackTrace(o, frames); const cs = o.stack;
  Error.stackTraceLimit = lim; Error.prepareStackTrace = prep;
  return cs.map(c => ({ f: c.getFileName() || '<native>', a: c.isAsync?.() })).filter(x => !x.f.includes('/spike/preload'));
}
function classify() {
  const fr = frames();
  const user = fr.filter(x => !x.f.startsWith('node:') && x.f !== '<native>' && !INTERNAL.test(x.f));
  return `syncUser=${user.filter(x=>!x.a).length} asyncUser=${user.filter(x=>x.a).length} top=${(fr.find(x=>!x.f.startsWith('node:'))||{}).f?.split('/').slice(-3).join('/')}`;
}
for (const name of ["readFileSync", "readFile", "statSync", "existsSync", "readdirSync", "lstatSync", "openSync", "accessSync", "realpathSync"]) {
  const o = fs[name];
  fs[name] = function (p, ...rest) { log(`${name} ${String(p).replace(/.*spike5/, '')} ${classify()}`); return o.call(this, p, ...rest); };
}
for (const name of ["readFile", "stat", "readdir", "access", "open"]) {
  const o = fs.promises[name];
  fs.promises[name] = function (p, ...rest) { log(`promises.${name} ${String(p).replace(/.*spike5/, '')} ${classify()}`); return o.call(this, p, ...rest); };
}
const envTarget = process.env;
process.env = new Proxy(envTarget, { set(t,k,v){ t[k]=v; return true; }, defineProperty(t,k,d){ t[k]=d.value; return true; }, get(t, k, r) { if (typeof k === 'string') log(`env ${k} ${classify()}`); return Reflect.get(t, k); } });
syncBuiltinESMExports();
log("preload done");
