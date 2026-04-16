require('dotenv').config();

if (!process.env.JWT_SECRET)           { console.error('FATAL: JWT_SECRET nao definido');           process.exit(1); }
if (!process.env.ENCRYPTION_SECRET)    { console.error('FATAL: ENCRYPTION_SECRET nao definido');    process.exit(1); }
if (!process.env.SUPABASE_URL)         { console.error('FATAL: SUPABASE_URL nao definido');         process.exit(1); }
if (!process.env.SUPABASE_SERVICE_KEY) { console.error('FATAL: SUPABASE_SERVICE_KEY nao definido'); process.exit(1); }
if (!process.env.RESEND_API_KEY)       { console.error('FATAL: RESEND_API_KEY nao definido');       process.exit(1); }

const express      = require('express');
const bodyParser   = require('body-parser');
const cors         = require('cors');
const jwt          = require('jsonwebtoken');
const crypto       = require('crypto');
const rateLimit    = require('express-rate-limit');
const cookieParser = require('cookie-parser');
const path         = require('path');
const { createClient } = require('@supabase/supabase-js');
const { Resend }       = require('resend');

const app     = express();
const PORT    = process.env.PORT || 3001;
const IS_PROD = process.env.NODE_ENV === 'production';

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);
const resend   = new Resend(process.env.RESEND_API_KEY);

// ─── Criptografia ─────────────────────────────────────────────────────────────

function deriveKey(entryId) {
  return crypto.createHmac('sha256', process.env.ENCRYPTION_SECRET).update(entryId).digest();
}

function encryptPassword(plaintext, entryId) {
  const key    = deriveKey(entryId);
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc      = cipher.update(plaintext, 'utf8', 'hex');
  enc         += cipher.final('hex');
  return { encrypted: enc, iv: iv.toString('hex') };
}

function decryptPassword(entry) {
  const key      = deriveKey(entry.id);
  const decipher = crypto.createDecipheriv('aes-256-cbc', key, Buffer.from(entry.iv, 'hex'));
  let dec        = decipher.update(entry.encrypted_password, 'hex', 'utf8');
  dec           += decipher.final('utf8');
  return dec;
}

function generateAccessCode() {
  return '7TH-' + crypto.randomBytes(3).toString('hex').toUpperCase();
}

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// ─── Middleware ───────────────────────────────────────────────────────────────

app.use(cors({ origin: process.env.CORS_ORIGIN || `http://localhost:${PORT}`, credentials: true }));
app.use(rateLimit({ windowMs: 60 * 1000, max: 60, message: { error: 'Too many requests' } }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, '../frontend/public')));

// Rate limit especifico para envio de OTP (max 5 por IP por minuto)
const otpLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  message: { error: 'Muitas tentativas. Aguarde 1 minuto.' }
});

// ─── Auth middleware ──────────────────────────────────────────────────────────

function authenticateJWT(req, res, next) {
  const token = req.cookies?.authToken;
  if (!token) return res.status(401).json({ error: 'Token ausente' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ error: 'Token invalido' });
  }
}

function ensureAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Acesso negado' });
  next();
}

// ─── Seed admin ───────────────────────────────────────────────────────────────

async function seedAdminUser() {
  if (!process.env.ADMIN_USERNAME) {
    console.warn('WARN: ADMIN_USERNAME nao definido — seed ignorado.');
    return;
  }
  const username  = process.env.ADMIN_USERNAME;
  const fullName  = process.env.ADMIN_FULL_NAME || 'Administrador';
  const dept      = process.env.ADMIN_DEPARTMENT || 'TI';

  const { data: existing } = await supabase.from('users').select('id, role').eq('username', username).single();

  if (!existing) {
    await supabase.from('users').insert({ username, full_name: fullName, department: dept, role: 'admin' });
    console.log(`Admin criado: ${username}`);
  } else if (existing.role !== 'admin') {
    await supabase.from('users').update({ role: 'admin', full_name: fullName, department: dept }).eq('id', existing.id);
    console.log(`Admin atualizado: ${username}`);
  } else {
    console.log(`Admin ja existe: ${username}`);
  }
}

seedAdminUser().catch(err => console.error('Erro no seed:', err));

// Limpeza de OTPs expirados a cada hora
setInterval(async () => {
  await supabase.from('otp_codes').delete().lt('expires_at', new Date().toISOString());
}, 60 * 60 * 1000);

// ─── Rotas publicas ───────────────────────────────────────────────────────────

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/public/index.html'));
});

// Passo 1: recebe email, valida se existe, envia OTP
app.post('/send-otp', otpLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email obrigatorio' });

    // Verifica se o email esta cadastrado
    const { data: user } = await supabase.from('users').select('id, full_name').eq('username', email).single();
    if (!user) return res.status(404).json({ error: 'Email nao cadastrado na plataforma' });

    // Invalida OTPs anteriores do mesmo email
    await supabase.from('otp_codes').update({ used: true }).eq('email', email).eq('used', false);

    // Gera novo OTP com validade de 10 minutos
    const code      = generateOTP();
    const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString();
    const codeHash  = crypto.createHash('sha256').update(code).digest('hex');

    await supabase.from('otp_codes').insert({ email, code: codeHash, expires_at: expiresAt });

    // Envia email via Resend
    await resend.emails.send({
      from: 'S7 Security <noreply@seven7th.com>',
      to:   email,
      subject: 'Seu codigo de acesso - S7 Security',
      html: `
        <div style="font-family:sans-serif;max-width:400px;margin:0 auto;padding:2rem;background:#1a1f2e;color:#e2e8f0;border-radius:12px">
          <h2 style="color:#00d4ff;margin-bottom:0.5rem">S7 Security</h2>
          <p style="color:#8892a4;margin-bottom:2rem">Plataforma de senhas Seven7th Digital</p>
          <p>Ola, <strong>${user.full_name}</strong>!</p>
          <p style="margin-top:1rem">Seu codigo de acesso:</p>
          <div style="background:#0f1117;border:1px solid #2e3550;border-radius:8px;padding:1.5rem;text-align:center;margin:1.5rem 0">
            <span style="font-size:2rem;font-weight:700;letter-spacing:0.3em;color:#00d4ff;font-family:monospace">${code}</span>
          </div>
          <p style="color:#8892a4;font-size:0.85rem">Valido por <strong>10 minutos</strong>. Nao compartilhe este codigo.</p>
        </div>
      `
    });

    res.json({ message: 'Codigo enviado para o email' });
  } catch (err) {
    console.error('Erro ao enviar OTP:', err);
    res.status(500).json({ error: 'Erro ao enviar codigo' });
  }
});

// Passo 2: valida OTP e faz login
app.post('/verify-otp', otpLimiter, async (req, res) => {
  try {
    const { email, code } = req.body;
    if (!email || !code) return res.status(400).json({ error: 'Email e codigo obrigatorios' });

    // Busca OTP valido
    const inputHash = crypto.createHash('sha256').update(code).digest('hex');

    const { data: otp } = await supabase
      .from('otp_codes')
      .select('*')
      .eq('email', email)
      .eq('code', inputHash)
      .eq('used', false)
      .gt('expires_at', new Date().toISOString())
      .order('created_at', { ascending: false })
      .limit(1)
      .single();

    if (!otp) return res.status(401).json({ error: 'Codigo invalido ou expirado' });

    // Marca OTP como usado
    await supabase.from('otp_codes').update({ used: true }).eq('id', otp.id);

    // Busca usuario
    const { data: user } = await supabase.from('users').select('*').eq('username', email).single();
    if (!user) return res.status(404).json({ error: 'Usuario nao encontrado' });

    const token = jwt.sign(
      { id: user.id, username: user.username, full_name: user.full_name, department: user.department, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '4d' }
    );

    res.cookie('authToken', token, { httpOnly: true, secure: IS_PROD, sameSite: 'strict', maxAge: 4 * 24 * 3600000 });
    res.json({ username: user.username, full_name: user.full_name, role: user.role });
  } catch {
    res.status(500).json({ error: 'Erro ao verificar codigo' });
  }
});

app.post('/logout', (req, res) => {
  res.clearCookie('authToken', { httpOnly: true, secure: IS_PROD, sameSite: 'strict' });
  res.json({ message: 'Logout realizado' });
});

// ─── Rotas autenticadas ───────────────────────────────────────────────────────

app.get('/me', authenticateJWT, (req, res) => {
  res.json({
    username:   req.user.username,
    full_name:  req.user.full_name,
    department: req.user.department,
    role:       req.user.role
  });
});

app.get('/categories', authenticateJWT, async (req, res) => {
  try {
    const { data, error } = await supabase.from('categories').select('name').order('sort_order').order('name');
    if (error) throw error;
    res.json(data.map(c => c.name));
  } catch {
    res.status(500).json({ error: 'Erro ao buscar categorias' });
  }
});

app.post('/admin/categories', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name || !name.trim()) return res.status(400).json({ error: 'Nome obrigatorio' });
    const { error } = await supabase.from('categories').insert({ name: name.trim() });
    if (error) {
      if (error.code === '23505') return res.status(409).json({ error: 'Categoria ja existe' });
      throw error;
    }
    res.json({ message: 'Categoria criada' });
  } catch {
    res.status(500).json({ error: 'Erro ao criar categoria' });
  }
});

app.delete('/admin/categories/:name', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const name = decodeURIComponent(req.params.name);
    const { error } = await supabase.from('categories').delete().eq('name', name);
    if (error) throw error;
    res.json({ message: 'Categoria removida' });
  } catch {
    res.status(500).json({ error: 'Erro ao remover categoria' });
  }
});

app.get('/passwords', authenticateJWT, async (req, res) => {
  try {
    // Admin vê tudo
    if (req.user.role === 'admin') {
      const { data, error } = await supabase
        .from('password_entries')
        .select('id, name, username, url, category, notes')
        .order('name');
      if (error) throw error;
      return res.json(data);
    }

    // Usuário comum: verifica se tem permissões restritas
    const { data: perms } = await supabase
      .from('user_permissions')
      .select('entry_id')
      .eq('user_id', req.user.id);

    // Sem restrições cadastradas → vê tudo
    if (!perms || perms.length === 0) {
      const { data, error } = await supabase
        .from('password_entries')
        .select('id, name, username, url, category, notes')
        .order('name');
      if (error) throw error;
      return res.json(data);
    }

    // Com restrições → vê só as permitidas
    const allowedIds = perms.map(p => p.entry_id);
    const { data, error } = await supabase
      .from('password_entries')
      .select('id, name, username, url, category, notes')
      .in('id', allowedIds)
      .order('name');
    if (error) throw error;
    res.json(data);
  } catch {
    res.status(500).json({ error: 'Erro ao buscar senhas' });
  }
});

app.get('/admin/users/:id/permissions', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('user_permissions')
      .select('entry_id')
      .eq('user_id', req.params.id);
    if (error) throw error;
    res.json(data.map(p => p.entry_id));
  } catch {
    res.status(500).json({ error: 'Erro ao buscar permissoes' });
  }
});

app.put('/admin/users/:id/permissions', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { entry_ids } = req.body; // array de IDs ou [] para irrestrito
    const userId = req.params.id;

    // Remove permissões anteriores
    await supabase.from('user_permissions').delete().eq('user_id', userId);

    // Insere novas (se houver)
    if (entry_ids && entry_ids.length > 0) {
      const rows = entry_ids.map(entry_id => ({ user_id: userId, entry_id }));
      const { error } = await supabase.from('user_permissions').insert(rows);
      if (error) throw error;
    }

    res.json({ message: 'Permissoes atualizadas' });
  } catch {
    res.status(500).json({ error: 'Erro ao salvar permissoes' });
  }
});

// Acesso a senha — nome vem do JWT, nao digitado pelo usuario
app.post('/access-password', authenticateJWT, async (req, res) => {
  try {
    const { id, squad, reason } = req.body;
    if (!id || !squad) return res.status(400).json({ error: 'id e squad sao obrigatorios' });

    const { data: entry } = await supabase.from('password_entries').select('*').eq('id', id).single();
    if (!entry) return res.status(404).json({ error: 'Entrada nao encontrada' });

    const password   = decryptPassword(entry);
    const accessCode = generateAccessCode();

    // full_name vem do JWT — a pessoa nao pode alterar
    await supabase.from('audit_logs').insert({
      user_id:    req.user.id,
      username:   req.user.username,
      full_name:  req.user.full_name,
      squad,
      reason:     reason || '',
      operation:  'access-password',
      target:     entry.name,
      access_code: accessCode,
      ip:         req.ip
    });

    res.json({ password, access_code: accessCode, username: entry.username, url: entry.url, notes: entry.notes });
  } catch {
    res.status(500).json({ error: 'Erro ao descriptografar' });
  }
});

// ─── Rotas admin ──────────────────────────────────────────────────────────────

app.post('/register', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { username, full_name, department, role } = req.body;
    if (!username || !full_name || !department) {
      return res.status(400).json({ error: 'username, full_name e department sao obrigatorios' });
    }
    const validRole = role === 'admin' ? 'admin' : 'user';
    const { data: existing } = await supabase.from('users').select('id').eq('username', username).single();
    if (existing) return res.status(409).json({ error: 'Usuario ja existe' });

    const { error } = await supabase.from('users').insert({ username, full_name, department, role: validRole });
    if (error) throw error;
    res.json({ message: 'Usuario criado com sucesso' });
  } catch {
    res.status(500).json({ error: 'Erro ao criar usuario' });
  }
});

app.post('/admin/add-password', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { name, username, url, category, notes, password } = req.body;
    if (!name || !category || !password) {
      return res.status(400).json({ error: 'name, category e password sao obrigatorios' });
    }
    const entryId = crypto.randomUUID();
    const { encrypted, iv } = encryptPassword(password, entryId);

    const { error } = await supabase.from('password_entries').insert({
      id: entryId, name, username: username || '', url: url || '',
      category, notes: notes || '', encrypted_password: encrypted, iv
    });
    if (error) throw error;

    await supabase.from('audit_logs').insert({
      user_id: req.user.id, username: req.user.username, full_name: req.user.full_name,
      operation: 'add-password', target: name, ip: req.ip
    });

    res.json({ message: 'Senha adicionada com sucesso' });
  } catch {
    res.status(500).json({ error: 'Erro ao adicionar senha' });
  }
});

app.get('/admin/users', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase.from('users').select('id, username, full_name, department, role');
    if (error) throw error;
    res.json(data);
  } catch {
    res.status(500).json({ error: 'Erro ao listar usuarios' });
  }
});

app.delete('/admin/users/:id', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: 'Voce nao pode excluir sua propria conta' });
    }
    const { error } = await supabase.from('users').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Usuario removido' });
  } catch {
    res.status(500).json({ error: 'Erro ao remover usuario' });
  }
});

app.get('/admin/passwords', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('password_entries')
      .select('id, name, username, url, category, notes')
      .order('category').order('name');
    if (error) throw error;
    res.json(data);
  } catch {
    res.status(500).json({ error: 'Erro ao listar senhas' });
  }
});

app.get('/admin/audit', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('audit_logs')
      .select('*')
      .order('timestamp', { ascending: false })
      .limit(200);
    if (error) throw error;
    res.json(data);
  } catch {
    res.status(500).json({ error: 'Erro ao buscar logs' });
  }
});

app.put('/admin/passwords/:id', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { name, username, url, category, notes, password } = req.body;
    if (!name || !category) return res.status(400).json({ error: 'name e category sao obrigatorios' });

    const updates = { name, username: username || '', url: url || '', category, notes: notes || '' };

    // Só re-encripta se uma nova senha foi fornecida
    if (password && password.trim()) {
      const { encrypted, iv } = encryptPassword(password, req.params.id);
      updates.encrypted_password = encrypted;
      updates.iv = iv;
    }

    const { error } = await supabase.from('password_entries').update(updates).eq('id', req.params.id);
    if (error) throw error;

    await supabase.from('audit_logs').insert({
      user_id: req.user.id, username: req.user.username, full_name: req.user.full_name,
      operation: 'edit-password', target: name, ip: req.ip
    });

    res.json({ message: 'Senha atualizada com sucesso' });
  } catch {
    res.status(500).json({ error: 'Erro ao atualizar senha' });
  }
});

app.delete('/admin/passwords/:id', authenticateJWT, ensureAdmin, async (req, res) => {
  try {
    const { error } = await supabase.from('password_entries').delete().eq('id', req.params.id);
    if (error) throw error;
    res.json({ message: 'Senha removida' });
  } catch {
    res.status(500).json({ error: 'Erro ao remover senha' });
  }
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
