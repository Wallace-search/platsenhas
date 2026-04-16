require('dotenv').config();
const { createClient } = require('@supabase/supabase-js');
const crypto = require('crypto');

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

function deriveKey(entryId) {
  return crypto.createHmac('sha256', process.env.ENCRYPTION_SECRET).update(entryId).digest();
}

function encrypt(text, entryId) {
  const key    = deriveKey(entryId);
  const iv     = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let enc      = cipher.update(text, 'utf8', 'hex');
  enc         += cipher.final('hex');
  return { encrypted: enc, iv: iv.toString('hex') };
}

const entries = [
  // ── Email ──────────────────────────────────────────────────────────────────
  { category: 'Email', name: 'Gmail Leads',       username: 'leads@seven7th.com',                         password: 'Seven7th2025*#@#*_X',      url: 'gmail.com',                              notes: '' },
  { category: 'Email', name: 'Gmail Produtos',    username: 'produtosseventh@gmail.com',                  password: 'Seven7th2025*#@#*',         url: 'gmail.com',                              notes: '' },
  { category: 'Email', name: 'Gmail Tecnologia',  username: 'tecnologia@seven7th.com',                    password: 'Seven7th2025*#@#*',         url: '',                                       notes: '' },
  { category: 'Email', name: 'Gmail Contato',     username: 'contato@seven7th.com',                       password: 'Seven7th2025!!',            url: '',                                       notes: '' },

  // ── Redes Sociais ──────────────────────────────────────────────────────────
  { category: 'Redes Sociais', name: 'LinkedIn Seven7th',       username: 'produtosseventh@gmail.com', password: '7th@2020',               url: 'linkedin.com',          notes: '' },
  { category: 'Redes Sociais', name: 'Linktree 7th',            username: '7th.digital',               password: 'Seven7th2024*#@ / Seven7th2025*#@#*_X', url: '', notes: '' },
  { category: 'Redes Sociais', name: 'Facebook',                username: 'produtosseventh@gmail.com', password: 'Seven7th2020@7th2024',   url: 'facebook.com',          notes: '' },
  { category: 'Redes Sociais', name: 'TikTok Business Center',  username: 'leads@seven7th.com',        password: 'Seven7th2022@',          url: 'business.tiktok.com',   notes: 'Entrar com o Gmail do Leads' },

  // ── Ads ────────────────────────────────────────────────────────────────────
  { category: 'Ads', name: 'Google Ads',      username: 'produtosseventh@gmail.com', password: 'Seven7th2020*#@',   url: 'ads.google.com',             notes: 'Nao usar para clientes novos, usar o mcc.seven7th' },
  { category: 'Ads', name: 'Google Ads MCC',  username: 'mcc.seven7th@gmail.com',   password: '*#@Seven7th2022',   url: 'ads.google.com',             notes: 'Apenas para incluir conta de cliente novo na MCC' },
  { category: 'Ads', name: 'Bing Ads',        username: 'produtosseventh@gmail.com', password: 'Seven7th2022#@#',  url: 'ui.ads.microsoft.com',       notes: '' },
  { category: 'Ads', name: 'Taboola',         username: 'leads@seven7th.com',        password: '7th@2023',         url: 'ads.taboola.com',            notes: '' },
  { category: 'Ads', name: 'Spotify Ads',     username: 'produtosseventh@gmail.com', password: 'Seven7th2024*#@', url: 'ads.spotify.com',            notes: 'Entrar com o Gmail do ProdutosSeventh' },

  // ── SEO & Analytics ────────────────────────────────────────────────────────
  { category: 'SEO & Analytics', name: 'Google Analytics', username: 'produtosseventh@gmail.com',              password: 'Seven7th2025*#@#*',  url: 'analytics.google.com',         notes: '' },
  { category: 'SEO & Analytics', name: 'Sem Rush',         username: 'produtosseventh@gmail.com',              password: 'Seven7th2020',       url: 'pt.semrush.com',               notes: '' },
  { category: 'SEO & Analytics', name: 'SeRanking',        username: 'leads@seven7th.com',                     password: 'Se2022@@',           url: 'online.seranking.com',         notes: '' },
  { category: 'SEO & Analytics', name: 'Power BI',         username: 'Seven7th@Seven7thdigital.onmicrosoft.com', password: 'qweasd2023@@#',    url: '',                             notes: '' },
  { category: 'SEO & Analytics', name: 'Reportei',         username: 'produtosseventh@gmail.com',              password: 'growth7th2026',      url: 'app.reportei.com',             notes: '' },

  // ── Automacao ──────────────────────────────────────────────────────────────
  { category: 'Automacao', name: 'Zapier',          username: 'leads@seven7th.com',            password: 'aaCLU4yT',       url: 'zapier.com',          notes: '' },
  { category: 'Automacao', name: 'Zapier (Marcelo)', username: 'marcelo.fontainha@seven7th.com', password: 'mazi7th@2025',  url: 'zapier.com',          notes: 'Entrar com e-mail do Ma' },
  { category: 'Automacao', name: 'Pabbly',          username: 'leads@seven7th.com',            password: 'login via Gmail', url: 'pabbly.com',         notes: 'Acessar por email Google' },
  { category: 'Automacao', name: 'N8N',             username: 'leonardo.sisilio@seven7th.com', password: 'Seven7th!',      url: 'app.n8n.cloud',       notes: 'Nome da conta: seven7th' },
  { category: 'Automacao', name: 'Supermetrics',    username: 'leads@seven7th.com',            password: 'Seven7th2025*#@#*_X', url: 'hub.supermetrics.com', notes: '' },

  // ── Design & Midia ─────────────────────────────────────────────────────────
  { category: 'Design & Midia', name: 'Freepik',          username: 'tecnologia@seven7th.com',  password: 'Seven7th2024*#@',  url: 'br.freepik.com',       notes: 'Acessar por email (nao pelo Google)' },
  { category: 'Design & Midia', name: 'Shutterstock',     username: 'financeiro@seven7th.com',  password: 'Seven7th2023@',    url: 'shutterstock.com',     notes: 'CANCELADO' },
  { category: 'Design & Midia', name: 'Envato Elements',  username: 'seven7th',                 password: 'Seven7th2025*#@#*', url: 'elements.envato.com', notes: 'Codigo para o email tecnologia' },
  { category: 'Design & Midia', name: 'Midjourney',       username: 'tecnologia@seven7th.com',  password: 'Seven7th2025*#@#*', url: 'midjourney.com',      notes: '' },

  // ── Outros ─────────────────────────────────────────────────────────────────
  { category: 'Outros', name: 'Syonet',              username: 'n/a',                           password: 'n/a',                url: 'integrationfb.syonet.com:8282', notes: '' },
  { category: 'Outros', name: 'Dropbox',             username: 'produtos@seven7th.com',         password: '*#@Seven7th2020',    url: 'dropbox.com',                   notes: 'Acesso pelo Google' },
  { category: 'Outros', name: 'RD Station',          username: 'produtosseventh@gmail.com',     password: 'Seven7th202$',       url: 'accounts.rdstation.com.br',     notes: '' },
  { category: 'Outros', name: 'Mlabs',               username: 'produtosseventh@gmail.com',     password: 'Seven7th2019',       url: 'mlabs.com.br',                  notes: '' },
  { category: 'Outros', name: 'Mlabs (Leads)',        username: 'leads@seven7th.com',            password: '7th2022@@',          url: 'mlabs.com.br',                  notes: 'CONTA DESATIVADA 02/01/25' },
  { category: 'Outros', name: 'SocialIQ',             username: 'victor.leite@seven7th.com',    password: 'Seven7th2023',       url: 'socialiq.impulze.ai',           notes: '' },
  { category: 'Outros', name: 'Blog WordPress',       username: 'contato@seven7th.com',         password: 'Seven7th2025$$',     url: '7th.digital/blog/wp-admin',     notes: '' },
  { category: 'Outros', name: 'Gemini Ultra / VEO3',  username: 'produtosseventh@gmail.com',    password: 'Seven7th2025*#@#*',  url: 'gemini.google.com',             notes: '' },
  { category: 'Outros', name: 'Brainstorm Academy',   username: 'financeiro@seven7th.com',      password: 'Seven7th2025*#@#*',  url: 'brainstorm.academy',            notes: '' },
  { category: 'Outros', name: 'Nova BM Facebook',     username: 'ID: 212117470912800',           password: 'n/a',                url: '',                              notes: '' },
];

async function seed() {
  console.log(`Inserindo ${entries.length} senhas no Supabase...\n`);
  let ok = 0, fail = 0;

  for (const e of entries) {
    const entryId = crypto.randomUUID();
    const { encrypted, iv } = encrypt(e.password, entryId);

    const { error } = await supabase.from('password_entries').insert({
      id:                entryId,
      name:              e.name,
      username:          e.username,
      url:               e.url,
      category:          e.category,
      notes:             e.notes,
      encrypted_password: encrypted,
      iv
    });

    if (error) {
      console.error(`  ERRO  ${e.name}: ${error.message}`);
      fail++;
    } else {
      console.log(`  OK    ${e.name}`);
      ok++;
    }
  }

  console.log(`\nConcluido: ${ok} inseridas, ${fail} erros.`);
  process.exit(fail > 0 ? 1 : 0);
}

seed();
