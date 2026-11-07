'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const HOST = process.env.HOST || '0.0.0.0';
const PORT = Number(process.env.PORT || 3000);
const ROOT = __dirname;
const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || ROOT;
const DB_PATH = process.env.DB_PATH || path.join(DATA_DIR, 'lotacao.sqlite');
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || '';
const ADMIN_SESSION_TTL = 8 * 60 * 60 * 1000;
const adminSessions = new Map();
const loginAttempts = new Map();
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const LOGIN_MAX_ATTEMPTS = 8;
const IS_PRODUCTION = process.env.NODE_ENV === 'production' || Boolean(process.env.RAILWAY_ENVIRONMENT);

const db = new DatabaseSync(DB_PATH);
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA foreign_keys = ON;

  CREATE TABLE IF NOT EXISTS escolhas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    matricula TEXT NOT NULL UNIQUE,
    cidade TEXT NOT NULL,
    criado_em TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_escolhas_cidade ON escolhas(cidade);
`);

const inserir = db.prepare(`
  INSERT INTO escolhas (matricula, cidade)
  VALUES (?, ?)
`);

const ranking = db.prepare(`
  SELECT cidade, COUNT(*) AS votos
  FROM escolhas
  GROUP BY cidade
  ORDER BY votos DESC, cidade COLLATE NOCASE ASC
  LIMIT 10
`);

const rankingCompleto = db.prepare(`
  SELECT cidade, COUNT(*) AS votos
  FROM escolhas
  GROUP BY cidade
  ORDER BY votos DESC, cidade COLLATE NOCASE ASC
`);

const total = db.prepare(`SELECT COUNT(*) AS total FROM escolhas`);
const listarEscolhasAdmin = db.prepare(`
  SELECT id, matricula, cidade, criado_em
  FROM escolhas
  ORDER BY criado_em DESC, id DESC
`);
const excluirEscolhaAdmin = db.prepare(`DELETE FROM escolhas WHERE id = ?`);

function json(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store'
  });
  res.end(body);
}

function normalizarMatricula(valor) {
  return String(valor ?? '').trim().replace(/\s+/g, '');
}

function normalizarCidade(valor) {
  return String(valor ?? '').trim().replace(/\s+/g, ' ');
}

function lerJson(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', chunk => {
      data += chunk;
      if (data.length > 16_384) {
        reject(new Error('Payload muito grande'));
        req.destroy();
      }
    });
    req.on('end', () => {
      try { resolve(JSON.parse(data || '{}')); }
      catch { reject(new Error('JSON inválido')); }
    });
    req.on('error', reject);
  });
}

function servirArquivo(res, file, contentType) {
  fs.readFile(file, (err, data) => {
    if (err) return json(res, 404, { erro: 'Arquivo não encontrado.' });
    res.writeHead(200, {
      'Content-Type': contentType,
      'Content-Length': data.length,
      'Cache-Control': 'no-cache'
    });
    res.end(data);
  });
}



function securityHeaders(res) {
  res.setHeader('X-Content-Type-Options','nosniff');
  res.setHeader('X-Frame-Options','DENY');
  res.setHeader('Referrer-Policy','no-referrer');
  res.setHeader('Permissions-Policy','geolocation=(), camera=(), microphone=()');
  res.setHeader('Content-Security-Policy',"default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; frame-src https://www.google.com https://maps.google.com; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'");
}
function clientKey(req) {
  const f=String(req.headers['x-forwarded-for']||'').split(',')[0].trim();
  return f || req.socket.remoteAddress || 'unknown';
}
function bloqueioLogin(req) {
  const key=clientKey(req), now=Date.now();
  let a=loginAttempts.get(key);
  if(!a || now-a.inicio>LOGIN_WINDOW_MS){a={inicio:now,tentativas:0};loginAttempts.set(key,a)}
  return {key,a,bloqueado:a.tentativas>=LOGIN_MAX_ATTEMPTS};
}
function cookieAdmin(token,maxAge) {
  return `pcce_admin=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${IS_PRODUCTION?'; Secure':''}`;
}

function cookies(req) {
  const raw=req.headers.cookie || '';
  return Object.fromEntries(raw.split(';').map(x=>x.trim()).filter(Boolean).map(x=>{
    const i=x.indexOf('=');
    return i<0 ? [x,''] : [x.slice(0,i),decodeURIComponent(x.slice(i+1))];
  }));
}
function adminAutenticado(req) {
  const token=cookies(req).pcce_admin;
  if(!token) return false;
  const exp=adminSessions.get(token);
  if(!exp || exp<Date.now()) { if(token) adminSessions.delete(token); return false; }
  return true;
}
function criarSessaoAdmin() {
  const token=crypto.randomBytes(32).toString('hex');
  adminSessions.set(token,Date.now()+ADMIN_SESSION_TTL);
  return token;
}
function limparSessoes() {
  const agora=Date.now();
  for(const [token,exp] of adminSessions) if(exp<agora) adminSessions.delete(token);
}
setInterval(limparSessoes,30*60*1000).unref();

function escaparHtml(s='') {
  return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

const ADMIN_HTML = `<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Administração • PCCE Lotação</title>
<style>
:root{--gold:#C8A24A;--bg:#090a0b;--card:#111315;--line:#2b2d2f;--text:#eee;--muted:#92969a}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 50% 0,#1a1c1f 0,#090a0b 42%);color:var(--text);font-family:Arial,sans-serif}
.wrap{max-width:1180px;margin:auto;padding:28px 18px 60px}.top{display:flex;justify-content:space-between;gap:18px;align-items:center;margin-bottom:24px}
.kicker{color:var(--gold);font-size:11px;font-weight:900;letter-spacing:.16em}.title{font-size:26px;font-weight:900;margin-top:5px}.muted{color:var(--muted);font-size:12px}
.actions{display:flex;gap:8px;flex-wrap:wrap}.btn{border:1px solid rgba(200,162,74,.55);background:transparent;color:var(--gold);border-radius:7px;padding:10px 13px;font-weight:900;font-size:11px;cursor:pointer;text-decoration:none}.btn.primary{background:var(--gold);color:#090a0b}
.cards{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:18px}.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}.num{font-size:27px;font-weight:950}.label{color:var(--muted);font-size:10px;margin-top:5px;text-transform:uppercase;letter-spacing:.1em}
.toolbar{display:flex;gap:8px;margin-bottom:10px}.toolbar input{flex:1;background:#0d0f10;color:#eee;border:1px solid var(--line);border-radius:7px;padding:11px 12px;outline:none}
.tablebox{overflow:auto;border:1px solid var(--line);border-radius:10px;background:var(--card)}table{width:100%;border-collapse:collapse;min-width:720px}th,td{text-align:left;padding:12px 13px;border-bottom:1px solid #252729;font-size:12px}th{position:sticky;top:0;background:#151719;color:var(--gold);font-size:10px;letter-spacing:.08em}td:last-child{text-align:right}
.del{border:1px solid #67373b;background:transparent;color:#e98c94;border-radius:6px;padding:6px 9px;cursor:pointer}.empty{text-align:center!important;color:var(--muted);padding:28px!important}
.login{max-width:420px;margin:12vh auto;padding:25px;background:var(--card);border:1px solid var(--line);border-radius:12px}.login input{width:100%;margin:16px 0 10px;padding:12px;background:#090a0b;border:1px solid var(--line);border-radius:7px;color:white}.err{color:#e98c94;font-size:12px;min-height:18px}
@media(max-width:700px){.top{align-items:flex-start;flex-direction:column}.cards{grid-template-columns:1fr}.title{font-size:21px}}
</style></head><body>
<div id="app"></div>
<script>
const app=document.getElementById('app');
function esc(s){const d=document.createElement('div');d.textContent=String(s??'');return d.innerHTML}
async function api(url,opt){const r=await fetch(url,opt);if(r.status===401){login();throw new Error('Não autenticado')}const d=await r.json().catch(()=>({}));if(!r.ok)throw new Error(d.erro||'Erro');return d}
function login(msg=''){
 app.innerHTML='<div class="login"><div class="kicker">ÁREA RESTRITA</div><div class="title">Administração</div><p class="muted">Acesso aos registros de escolha de lotação.</p><input id="senha" type="password" placeholder="Senha de administrador" autofocus><div class="err">'+esc(msg)+'</div><button class="btn primary" id="entrar">ENTRAR</button></div>';
 document.getElementById('entrar').onclick=entrar;document.getElementById('senha').onkeydown=e=>{if(e.key==='Enter')entrar()};
}
async function entrar(){try{await api('/api/admin/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({senha:document.getElementById('senha').value})});painel()}catch(e){login(e.message)}}
async function painel(){
 try{
 const d=await api('/api/admin/escolhas');
 app.innerHTML='<div class="wrap"><div class="top"><div><div class="kicker">PCCE • LOTAÇÃO</div><div class="title">Painel administrativo</div><div class="muted">Matrículas são dados administrativos e não aparecem no ranking público.</div></div><div class="actions"><a class="btn primary" href="/api/admin/exportar.xlsx">EXPORTAR EXCEL</a><button class="btn" id="sair">SAIR</button></div></div><div class="cards"><div class="card"><div class="num">'+d.total+'</div><div class="label">Escolhas registradas</div></div><div class="card"><div class="num">'+d.cidades+'</div><div class="label">Cidades escolhidas</div></div><div class="card"><div class="num">'+d.registros.length+'</div><div class="label">Registros exibidos</div></div></div><div class="toolbar"><input id="busca" placeholder="Pesquisar matrícula ou cidade..."></div><div class="tablebox"><table><thead><tr><th>ID</th><th>Matrícula</th><th>Cidade</th><th>Data/hora</th><th>Ação</th></tr></thead><tbody id="tbody"></tbody></table></div></div>';
 window.__regs=d.registros;render(d.registros);
 document.getElementById('busca').oninput=e=>{const q=e.target.value.toLowerCase().trim();render(d.registros.filter(x=>x.matricula.toLowerCase().includes(q)||x.cidade.toLowerCase().includes(q)))};
 document.getElementById('sair').onclick=async()=>{await fetch('/api/admin/logout',{method:'POST'});login()};
 }catch(e){}
}
function render(rows){const tb=document.getElementById('tbody');if(!tb)return;if(!rows.length){tb.innerHTML='<tr><td colspan="5" class="empty">Nenhum registro encontrado.</td></tr>';return}tb.innerHTML=rows.map(x=>'<tr><td>'+x.id+'</td><td>'+esc(x.matricula)+'</td><td>'+esc(x.cidade)+'</td><td>'+esc(x.criado_em)+'</td><td><button class="del" onclick="excluir('+x.id+',\\''+esc(x.matricula).replace(/'/g,"\\\\'")+'\\')">EXCLUIR</button></td></tr>').join('')}
async function excluir(id,mat){if(!confirm('Excluir a escolha da matrícula '+mat+'? A matrícula poderá votar novamente depois disso.'))return;try{await api('/api/admin/escolhas/'+id,{method:'DELETE'});painel()}catch(e){alert(e.message)}}
fetch('/api/admin/escolhas').then(r=>r.status===401?login():painel()).catch(()=>login());
</script></body></html>`;

function xmlEsc(s='') {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&apos;');
}
function colunaExcel(n) {
  let s=''; while(n){n--;s=String.fromCharCode(65+(n%26))+s;n=Math.floor(n/26)} return s;
}
function crc32(buf) {
  let c=0xffffffff;
  for(const b of buf){c^=b;for(let k=0;k<8;k++)c=(c>>>1)^((c&1)?0xedb88320:0)}
  return (c^0xffffffff)>>>0;
}
function zipStore(files) {
  const locals=[], centrals=[]; let offset=0;
  for(const [name,data0] of files){
    const data=Buffer.isBuffer(data0)?data0:Buffer.from(data0,'utf8'), nb=Buffer.from(name), crc=crc32(data);
    const lh=Buffer.alloc(30);lh.writeUInt32LE(0x04034b50,0);lh.writeUInt16LE(20,4);lh.writeUInt16LE(0,6);lh.writeUInt16LE(0,8);lh.writeUInt16LE(0,10);lh.writeUInt16LE(0,12);lh.writeUInt32LE(crc,14);lh.writeUInt32LE(data.length,18);lh.writeUInt32LE(data.length,22);lh.writeUInt16LE(nb.length,26);lh.writeUInt16LE(0,28);
    locals.push(lh,nb,data);
    const ch=Buffer.alloc(46);ch.writeUInt32LE(0x02014b50,0);ch.writeUInt16LE(20,4);ch.writeUInt16LE(20,6);ch.writeUInt16LE(0,8);ch.writeUInt16LE(0,10);ch.writeUInt16LE(0,12);ch.writeUInt16LE(0,14);ch.writeUInt32LE(crc,16);ch.writeUInt32LE(data.length,20);ch.writeUInt32LE(data.length,24);ch.writeUInt16LE(nb.length,28);ch.writeUInt16LE(0,30);ch.writeUInt16LE(0,32);ch.writeUInt16LE(0,34);ch.writeUInt16LE(0,36);ch.writeUInt32LE(0,38);ch.writeUInt32LE(offset,42);
    centrals.push(ch,nb);offset+=lh.length+nb.length+data.length;
  }
  const central=Buffer.concat(centrals), local=Buffer.concat(locals), end=Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50,0);end.writeUInt16LE(0,4);end.writeUInt16LE(0,6);end.writeUInt16LE(files.length,8);end.writeUInt16LE(files.length,10);end.writeUInt32LE(central.length,12);end.writeUInt32LE(local.length,16);end.writeUInt16LE(0,20);
  return Buffer.concat([local,central,end]);
}
function gerarXlsx(registros) {
  const headers=['ID','Matrícula','Cidade','Data/Hora'];
  const rows=[headers,...registros.map(r=>[r.id,r.matricula,r.cidade,r.criado_em])];
  const sheetRows=rows.map((row,ri)=>'<row r="'+(ri+1)+'">'+row.map((v,ci)=>{
    const ref=colunaExcel(ci+1)+(ri+1);
    if(typeof v==='number')return '<c r="'+ref+'"><v>'+v+'</v></c>';
    return '<c r="'+ref+'" t="inlineStr"><is><t>'+xmlEsc(v)+'</t></is></c>';
  }).join('')+'</row>').join('');
  const sheet=`<?xml version="1.0" encoding="UTF-8" standalone="yes"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><cols><col min="1" max="1" width="10" customWidth="1"/><col min="2" max="2" width="20" customWidth="1"/><col min="3" max="3" width="28" customWidth="1"/><col min="4" max="4" width="24" customWidth="1"/></cols><sheetData>${sheetRows}</sheetData><autoFilter ref="A1:D${rows.length}"/></worksheet>`;
  const files=[
    ['[Content_Types].xml',`<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/></Types>`],
    ['_rels/.rels',`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>`],
    ['xl/workbook.xml',`<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Escolhas" sheetId="1" r:id="rId1"/></sheets></workbook>`],
    ['xl/_rels/workbook.xml.rels',`<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/></Relationships>`],
    ['xl/worksheets/sheet1.xml',sheet]
  ];
  return zipStore(files);
}

const server = http.createServer(async (req, res) => {
  securityHeaders(res);
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (req.method === 'GET' && url.pathname === '/admin') {
    res.writeHead(200, {'Content-Type':'text/html; charset=utf-8','Cache-Control':'no-store'});
    return res.end(ADMIN_HTML);
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/login') {
    if (!ADMIN_PASSWORD) return json(res, 503, {erro:'ADMIN_PASSWORD não foi configurada no servidor.'});
    const lim=bloqueioLogin(req);
    if(lim.bloqueado) return json(res,429,{erro:'Muitas tentativas. Aguarde 15 minutos e tente novamente.'});
    try {
      const body=await lerJson(req);
      const recebida=Buffer.from(String(body.senha||''));
      const correta=Buffer.from(ADMIN_PASSWORD);
      const ok=recebida.length===correta.length && crypto.timingSafeEqual(recebida,correta);
      if(!ok){lim.a.tentativas++;return json(res,401,{erro:'Senha incorreta.'});}
      loginAttempts.delete(lim.key);
      const token=criarSessaoAdmin();
      res.setHeader('Set-Cookie',cookieAdmin(token,ADMIN_SESSION_TTL/1000));
      return json(res,200,{ok:true});
    } catch(e) { return json(res,400,{erro:'Requisição inválida.'}); }
  }

  if (req.method === 'POST' && url.pathname === '/api/admin/logout') {
    const token=cookies(req).pcce_admin;if(token)adminSessions.delete(token);
    res.setHeader('Set-Cookie',cookieAdmin('',0));
    return json(res,200,{ok:true});
  }

  if (req.method === 'GET' && url.pathname === '/api/admin/escolhas') {
    if(!adminAutenticado(req)) return json(res,401,{erro:'Não autenticado.'});
    const registros=listarEscolhasAdmin.all().map(r=>({...r,id:Number(r.id)}));
    const cidades=new Set(registros.map(r=>r.cidade)).size;
    return json(res,200,{registros,total:registros.length,cidades});
  }

  if (req.method === 'DELETE' && url.pathname.startsWith('/api/admin/escolhas/')) {
    if(!adminAutenticado(req)) return json(res,401,{erro:'Não autenticado.'});
    const id=Number(url.pathname.split('/').pop());
    if(!Number.isInteger(id)||id<1) return json(res,400,{erro:'ID inválido.'});
    const r=excluirEscolhaAdmin.run(id);
    if(!r.changes) return json(res,404,{erro:'Registro não encontrado.'});
    return json(res,200,{ok:true});
  }

  if (req.method === 'GET' && url.pathname === '/api/admin/exportar.xlsx') {
    if(!adminAutenticado(req)) return json(res,401,{erro:'Não autenticado.'});
    const registros=listarEscolhasAdmin.all().map(r=>({...r,id:Number(r.id)}));
    const arquivo=gerarXlsx(registros);
    const data=new Date().toISOString().slice(0,10);
    res.writeHead(200,{
      'Content-Type':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'Content-Disposition':`attachment; filename="pcce-lotacao-${data}.xlsx"`,
      'Content-Length':arquivo.length,
      'Cache-Control':'no-store'
    });
    return res.end(arquivo);
  }


  if (req.method === 'GET' && url.pathname === '/api/ranking-completo') {
    const rows = rankingCompleto.all().map(r => ({ cidade: r.cidade, votos: Number(r.votos) }));
    return json(res, 200, { ranking: rows, total: Number(total.get().total) });
  }

  if (req.method === 'GET' && url.pathname === '/api/ranking') {
    const rows = ranking.all().map(r => ({ cidade: r.cidade, votos: Number(r.votos) }));
    return json(res, 200, {
      ranking: rows,
      total: Number(total.get().total)
    });
  }

  if (req.method === 'POST' && url.pathname === '/api/escolhas') {
    try {
      const body = await lerJson(req);
      const matricula = normalizarMatricula(body.matricula);
      const cidade = normalizarCidade(body.cidade);

      if (!matricula || matricula.length > 30) {
        return json(res, 400, { erro: 'Matrícula inválida.' });
      }
      if (!/^[0-9A-Za-z.-]+$/.test(matricula)) {
        return json(res, 400, { erro: 'A matrícula contém caracteres inválidos.' });
      }
      if (!cidade || cidade.length > 100) {
        return json(res, 400, { erro: 'Cidade inválida.' });
      }

      try {
        const result = inserir.run(matricula, cidade);
        return json(res, 201, {
          ok: true,
          id: Number(result.lastInsertRowid),
          cidade
        });
      } catch (e) {
        if (String(e.message).includes('UNIQUE constraint failed')) {
          return json(res, 409, {
            erro: 'Esta matrícula já registrou uma escolha.'
          });
        }
        throw e;
      }
    } catch (e) {
      console.error(e);
      return json(res, 400, { erro: 'Requisição inválida.' });
    }
  }

  if (req.method === 'GET' && (url.pathname === '/' || url.pathname === '/index.html')) {
    return servirArquivo(res, path.join(ROOT, 'index.html'), 'text/html; charset=utf-8');
  }

  return json(res, 404, { erro: 'Rota não encontrada.' });
});

if (!ADMIN_PASSWORD) {
  console.warn('AVISO: ADMIN_PASSWORD não configurada. /admin não aceitará login.');
}
server.listen(PORT, HOST, () => {
  console.log(`PCCE Lotação: http://localhost:${PORT}`);
  console.log(`Banco SQLite: ${DB_PATH}`);
});
