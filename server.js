// Base Socorro — servidor
// Variáveis de ambiente:
//   DATABASE_URL      conexão Postgres (ex.: Neon)
//   ADMIN_MATRICULA   matrícula do administrador (ex.: K7P2X9QM)
//   SESSION_SECRET    texto longo e aleatório para assinar o login
//   META_VOTOS        opcional, padrão 1500
'use strict';

const express = require('express');
const crypto = require('crypto');
const path = require('path');
const { Pool } = require('pg');

const PORT = process.env.PORT || 3000;
const META = Number(process.env.META_VOTOS) || 1500;
const SECRET = process.env.SESSION_SECRET || '';
const ADMIN = String(process.env.ADMIN_MATRICULA || '').trim().toUpperCase();
const PROD = process.env.NODE_ENV === 'production';
const SESSAO_MS = 12 * 60 * 60 * 1000;

if (!process.env.DATABASE_URL || SECRET.length < 16 || ADMIN.length < 6) {
  console.error('Configure DATABASE_URL, SESSION_SECRET (16+ caracteres) e ADMIN_MATRICULA (6+ caracteres).');
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: /localhost|127\.0\.0\.1/.test(process.env.DATABASE_URL) ? false : { rejectUnauthorized: false }
});

const BAIRROS_INICIAIS = ['Sede / Centro', 'Complexo Taiçoca', 'Complexo João Alves', 'Complexo Marcos Freire',
  'Albano Franco', 'Fernando Collor', 'Piabeta', 'Parque dos Faróis', 'Povoados / Zona rural'];
const NIVEIS = ['certo', 'provavel', 'indeciso'];
const TITULOS = ['vota', 'transferiu'];

/* ---------- Banco ---------- */

async function prepararBanco() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS coordenadores (
      matricula TEXT PRIMARY KEY,
      nome TEXT NOT NULL,
      perfil TEXT NOT NULL DEFAULT 'coordenador',
      ativo BOOLEAN NOT NULL DEFAULT TRUE,
      criado_em TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE TABLE IF NOT EXISTS bairros (
      nome TEXT PRIMARY KEY,
      ordem INT NOT NULL DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS eleitores (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      nome TEXT NOT NULL,
      telefone TEXT NOT NULL DEFAULT '',
      bairro TEXT NOT NULL,
      lideranca TEXT NOT NULL DEFAULT '',
      nivel TEXT NOT NULL DEFAULT 'provavel',
      titulo TEXT NOT NULL DEFAULT 'vota',
      secao TEXT NOT NULL DEFAULT '',
      matricula TEXT NOT NULL,
      coordenador TEXT NOT NULL DEFAULT '',
      criado_em TIMESTAMPTZ NOT NULL DEFAULT now(),
      editado_em TIMESTAMPTZ
    );
    CREATE INDEX IF NOT EXISTS eleitores_matricula ON eleitores (matricula);
    ALTER TABLE eleitores ADD COLUMN IF NOT EXISTS num_titulo TEXT NOT NULL DEFAULT '';
    ALTER TABLE eleitores ADD COLUMN IF NOT EXISTS zona TEXT NOT NULL DEFAULT '';
    ALTER TABLE eleitores ADD COLUMN IF NOT EXISTS sec_eleitoral TEXT NOT NULL DEFAULT '';
    ALTER TABLE coordenadores ADD COLUMN IF NOT EXISTS nome_chave TEXT;
    ALTER TABLE coordenadores ADD COLUMN IF NOT EXISTS ip_cadastro TEXT NOT NULL DEFAULT '';
    CREATE UNIQUE INDEX IF NOT EXISTS coordenadores_nome_chave ON coordenadores (nome_chave);
  `);
  const antigos = await pool.query('SELECT matricula, nome FROM coordenadores WHERE nome_chave IS NULL');
  for (const c of antigos.rows) {
    await pool.query('UPDATE coordenadores SET nome_chave = $1 WHERE matricula = $2', [chaveNome(c.nome), c.matricula])
      .catch(e => { if (e.code !== '23505') throw e; });
  }
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM bairros');
  if (rows[0].n === 0) {
    for (let i = 0; i < BAIRROS_INICIAIS.length; i++) {
      await pool.query('INSERT INTO bairros (nome, ordem) VALUES ($1, $2) ON CONFLICT DO NOTHING', [BAIRROS_INICIAIS[i], i]);
    }
  }
  await pool.query(
    `INSERT INTO coordenadores (matricula, nome, nome_chave, perfil, ativo) VALUES ($1, 'Administrador', 'administrador', 'admin', TRUE)
     ON CONFLICT (matricula) DO UPDATE SET perfil = 'admin', ativo = TRUE`, [ADMIN]);
}

async function listarBairros() {
  const { rows } = await pool.query('SELECT nome FROM bairros ORDER BY ordem, nome');
  return rows.map(r => r.nome);
}

/* ---------- Sessão (cookie assinado) ---------- */

function assinar(dados) {
  const corpo = Buffer.from(JSON.stringify(dados)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(corpo).digest('base64url');
  return corpo + '.' + sig;
}

function verificar(valor) {
  if (!valor || valor.indexOf('.') < 0) return null;
  const [corpo, sig] = valor.split('.');
  const esperado = crypto.createHmac('sha256', SECRET).update(corpo).digest('base64url');
  const a = Buffer.from(sig || ''), b = Buffer.from(esperado);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const d = JSON.parse(Buffer.from(corpo, 'base64url').toString());
    return d.exp > Date.now() ? d : null;
  } catch (e) { return null; }
}

function lerCookie(req, nome) {
  const c = req.headers.cookie || '';
  const m = c.split(/;\s*/).find(p => p.startsWith(nome + '='));
  return m ? decodeURIComponent(m.slice(nome.length + 1)) : null;
}

function definirCookie(res, valor, maxAgeSeg) {
  res.setHeader('Set-Cookie', `bs=${encodeURIComponent(valor)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSeg}${PROD ? '; Secure' : ''}`);
}

// Confere o cookie e se a matrícula continua ativa
async function exigirLogin(req, res, next) {
  try {
    const s = verificar(lerCookie(req, 'bs'));
    if (!s) return res.status(401).json({ erro: 'SESSAO' });
    const { rows } = await pool.query('SELECT matricula, nome, perfil FROM coordenadores WHERE matricula = $1 AND ativo', [s.m]);
    if (!rows.length) return res.status(401).json({ erro: 'SESSAO' });
    req.user = { matricula: rows[0].matricula, nome: rows[0].nome, admin: rows[0].perfil === 'admin' };
    next();
  } catch (e) { next(e); }
}

function exigirAdmin(req, res, next) {
  if (!req.user || !req.user.admin) return res.status(403).json({ erro: 'Só o administrador pode fazer isso.' });
  next();
}

// Ações que mudam dados só aceitam JSON (bloqueia envio de formulário de outro site)
function exigirJson(req, res, next) {
  if (['POST', 'PUT', 'PATCH', 'DELETE'].includes(req.method) && !req.is('application/json')) {
    return res.status(415).json({ erro: 'Formato inválido.' });
  }
  next();
}

// Limite simples de tentativas de login por IP
const tentativas = new Map();
function limiteLogin(req, res, next) {
  const ip = req.ip, agora = Date.now();
  const t = tentativas.get(ip) || { n: 0, desde: agora };
  if (agora - t.desde > 10 * 60 * 1000) { t.n = 0; t.desde = agora; }
  if (t.n >= 10) return res.status(429).json({ erro: 'Muitas tentativas. Aguarde 10 minutos.' });
  req._tentativa = t; tentativas.set(ip, t);
  next();
}

/* ---------- Auxiliares ---------- */

const limpar = (v, max) => String(v == null ? '' : v).replace(/\s+/g, ' ').trim().slice(0, max);

// Nome comparável: sem acento, minúsculo, espaços simples ("João  Silva" = "joao silva")
const chaveNome = nome => String(nome).normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/\s+/g, ' ').trim();

const NOME_REPETIDO = 'Já existe um coordenador com esse nome. Use nome e sobrenome.';
const nomeRepetido = e => e.code === '23505' && e.constraint === 'coordenadores_nome_chave';

function gerarMatricula() {
  const letras = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const b = crypto.randomBytes(8);
  let s = '';
  for (let i = 0; i < 8; i++) s += letras[b[i] % letras.length];
  return s;
}

async function validarEleitor(d) {
  const e = {
    nome: limpar(d.nome, 120),
    telefone: limpar(d.telefone, 30),
    bairro: limpar(d.bairro, 80),
    lideranca: limpar(d.lideranca, 80),
    nivel: NIVEIS.includes(d.nivel) ? d.nivel : 'provavel',
    titulo: TITULOS.includes(d.titulo) ? d.titulo : 'vota',
    secao: d.secao === undefined ? null : limpar(d.secao, 80),
    num_titulo: String(d.num_titulo || '').replace(/\D/g, '').slice(0, 12),
    zona: String(d.zona || '').replace(/\D/g, '').slice(0, 4),
    sec_eleitoral: String(d.sec_eleitoral || '').replace(/\D/g, '').slice(0, 4)
  };
  if (!e.nome) throw Object.assign(new Error('Informe o nome.'), { status: 400 });
  const bairros = await listarBairros();
  if (!bairros.includes(e.bairro)) throw Object.assign(new Error('Escolha um bairro da lista.'), { status: 400 });
  return e;
}

async function dadosDoUsuario(u) {
  const q = u.admin
    ? await pool.query('SELECT * FROM eleitores ORDER BY criado_em DESC')
    : await pool.query('SELECT * FROM eleitores WHERE matricula = $1 ORDER BY criado_em DESC', [u.matricula]);
  return {
    rows: q.rows.map(r => ({
      id: r.id, nome: r.nome, telefone: r.telefone, bairro: r.bairro, lideranca: r.lideranca,
      nivel: r.nivel, titulo: r.titulo, secao: r.secao, num_titulo: r.num_titulo, zona: r.zona, sec_eleitoral: r.sec_eleitoral, coordenador: r.coordenador
    })),
    bairros: await listarBairros(),
    meta: META, nome: u.nome, admin: u.admin
  };
}

async function eleitorPermitido(u, id) {
  if (!/^[0-9a-f-]{36}$/i.test(String(id))) return null;
  const { rows } = await pool.query('SELECT matricula FROM eleitores WHERE id = $1', [id]);
  if (!rows.length) throw Object.assign(new Error('Cadastro não encontrado. Atualize a lista.'), { status: 404 });
  if (!u.admin && rows[0].matricula !== u.matricula) throw Object.assign(new Error('Você só pode alterar os seus cadastros.'), { status: 403 });
  return rows[0];
}

const rota = fn => (req, res, next) => Promise.resolve(fn(req, res)).catch(next);

/* ---------- App ---------- */

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use(express.json({ limit: '20kb' }));
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'same-origin');
  res.setHeader('X-Frame-Options', 'DENY');
  next();
});
app.use('/api', exigirJson);

app.get('/api/saude', (req, res) => res.json({ ok: true }));

app.post('/api/entrar', limiteLogin, rota(async (req, res) => {
  const m = limpar(req.body.matricula, 20).toUpperCase();
  if (!/^[A-Z0-9.\-]{3,20}$/.test(m)) {
    req._tentativa.n++;
    return res.status(400).json({ erro: 'Matrícula inválida. Use de 3 a 20 letras e números.' });
  }
  const { rows } = await pool.query('SELECT ativo FROM coordenadores WHERE matricula = $1', [m]);
  if (rows.length && !rows[0].ativo) {
    req._tentativa.n++;
    return res.status(403).json({ erro: 'Esta matrícula foi desativada. Fale com o administrador.' });
  }
  // Primeiro acesso: cadastra a matrícula com o nome informado
  if (!rows.length) {
    const nome = limpar(req.body.nome, 80);
    if (nome.length < 3) return res.status(400).json({ erro: 'Primeiro acesso: informe também o seu nome completo.' });
    req._tentativa.n++;
    try {
      await pool.query('INSERT INTO coordenadores (matricula, nome, nome_chave, ip_cadastro) VALUES ($1, $2, $3, $4)',
        [m, nome, chaveNome(nome), req.ip || '']);
    } catch (e) {
      if (nomeRepetido(e)) return res.status(409).json({ erro: NOME_REPETIDO });
      if (e.code === '23505') return res.status(409).json({ erro: 'Tente entrar de novo.' });
      throw e;
    }
  }
  definirCookie(res, assinar({ m, exp: Date.now() + SESSAO_MS }), SESSAO_MS / 1000);
  res.json({ ok: true });
}));

app.post('/api/sair', (req, res) => { definirCookie(res, '', 0); res.json({ ok: true }); });

app.get('/api/dados', exigirLogin, rota(async (req, res) => res.json(await dadosDoUsuario(req.user))));

app.post('/api/eleitores', exigirLogin, rota(async (req, res) => {
  const e = await validarEleitor(req.body);
  await pool.query(
    `INSERT INTO eleitores (nome, telefone, bairro, lideranca, nivel, titulo, secao, matricula, coordenador, num_titulo, zona, sec_eleitoral)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
    [e.nome, e.telefone, e.bairro, e.lideranca, e.nivel, e.titulo, e.secao || '', req.user.matricula, req.user.nome, e.num_titulo, e.zona, e.sec_eleitoral]);
  res.json(await dadosDoUsuario(req.user));
}));

app.put('/api/eleitores/:id', exigirLogin, rota(async (req, res) => {
  if (!(await eleitorPermitido(req.user, req.params.id))) return res.status(404).json({ erro: 'Cadastro não encontrado.' });
  const e = await validarEleitor(req.body);
  await pool.query(
    `UPDATE eleitores SET nome=$1, telefone=$2, bairro=$3, lideranca=$4, nivel=$5, titulo=$6, secao=COALESCE($7, secao), num_titulo=$9, zona=$10, sec_eleitoral=$11, editado_em=now()
     WHERE id=$8`,
    [e.nome, e.telefone, e.bairro, e.lideranca, e.nivel, e.titulo, e.secao, req.params.id, e.num_titulo, e.zona, e.sec_eleitoral]);
  res.json(await dadosDoUsuario(req.user));
}));

app.delete('/api/eleitores/:id', exigirLogin, rota(async (req, res) => {
  if (!(await eleitorPermitido(req.user, req.params.id))) return res.status(404).json({ erro: 'Cadastro não encontrado.' });
  await pool.query('DELETE FROM eleitores WHERE id = $1', [req.params.id]);
  res.json(await dadosDoUsuario(req.user));
}));

/* ----- Administração ----- */

async function listaCoordenadores() {
  const { rows } = await pool.query(
    `SELECT c.matricula, c.nome, c.perfil, c.ativo, c.ip_cadastro, count(e.id)::int AS cadastros
     FROM coordenadores c LEFT JOIN eleitores e ON e.matricula = c.matricula
     GROUP BY c.matricula ORDER BY c.perfil = 'admin' DESC, c.nome`);
  return rows;
}

app.get('/api/coordenadores', exigirLogin, exigirAdmin, rota(async (req, res) => res.json(await listaCoordenadores())));

app.post('/api/coordenadores', exigirLogin, exigirAdmin, rota(async (req, res) => {
  const nome = limpar(req.body.nome, 80);
  if (!nome) return res.status(400).json({ erro: 'Informe o nome do coordenador.' });
  let m;
  for (let i = 0; i < 5; i++) {
    m = gerarMatricula();
    try {
      await pool.query('INSERT INTO coordenadores (matricula, nome, nome_chave) VALUES ($1, $2, $3)', [m, nome, chaveNome(nome)]);
      break;
    } catch (e) {
      if (nomeRepetido(e)) return res.status(409).json({ erro: NOME_REPETIDO });
      if (e.code !== '23505' || i === 4) throw e;
    }
  }
  res.json({ matricula: m, lista: await listaCoordenadores() });
}));

app.patch('/api/coordenadores/:matricula', exigirLogin, exigirAdmin, rota(async (req, res) => {
  const m = limpar(req.params.matricula, 20).toUpperCase();
  if (m === ADMIN) return res.status(400).json({ erro: 'A matrícula do administrador não pode ser desativada.' });
  await pool.query('UPDATE coordenadores SET ativo = $1 WHERE matricula = $2', [!!req.body.ativo, m]);
  res.json(await listaCoordenadores());
}));

app.put('/api/bairros', exigirLogin, exigirAdmin, rota(async (req, res) => {
  const lista = [...new Set((Array.isArray(req.body.lista) ? req.body.lista : []).map(b => limpar(b, 80)).filter(Boolean))].slice(0, 50);
  if (!lista.length) return res.status(400).json({ erro: 'Deixe pelo menos um bairro.' });
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    await client.query('DELETE FROM bairros');
    for (let i = 0; i < lista.length; i++) await client.query('INSERT INTO bairros (nome, ordem) VALUES ($1, $2)', [lista[i], i]);
    await client.query('COMMIT');
  } catch (e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
  res.json(await listaBairros());
}));
async function listaBairros() { return { bairros: await listarBairros() }; }

/* ----- Página ----- */

app.use(express.static(path.join(__dirname, 'public'), { index: false, maxAge: '1h' }));
['/', '/lista', '/admin'].forEach(p => app.get(p, (req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
}));

app.use((err, req, res, next) => {
  if (err.status) return res.status(err.status).json({ erro: err.message });
  console.error(err);
  res.status(500).json({ erro: 'Erro no servidor. Tente de novo em instantes.' });
});

prepararBanco()
  .then(() => app.listen(PORT, () => console.log('Base Socorro rodando na porta ' + PORT)))
  .catch(e => { console.error('Falha ao preparar o banco:', e); process.exit(1); });
