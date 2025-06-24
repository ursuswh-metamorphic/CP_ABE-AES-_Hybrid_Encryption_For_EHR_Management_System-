// const API_BASE = 'https://api.your-domain.com';
const API_BASE = 'http://127.0.0.1:5000';

async function request(path, opts = {}) {
  const token = localStorage.getItem('token');
  const headers = opts.headers || {};
  if (token) headers['Authorization'] = `Bearer ${token}`;
  const res = await fetch(API_BASE + path, { ...opts, headers });
  if (!res.ok) throw await res.json();
  return res;
}

async function getJson(path, opts) {
  const res = await request(path, opts);
  return res.json();
}

async function login(email, password) {
  const res = await getJson('/api/auth/login', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({ email, password })
  });
  return res;
}

async function keygen(attrs) {
  const res = await request('/api/ehr/keygen', { 
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ attributes: attrs })
  });
  return res.json();
}

async function uploadEhr(file, policy) {
  const form = new FormData();
  form.append('file', file);
  form.append('policy', policy);
  const res = await request('/api/ehr/upload', {
    method:'POST',
    body: form
  });
  return res.json();
}

async function downloadEhr(rid, skFile) {
  const skContent = await skFile.text();
  let secretKeyBase64;
  try {
    const keyData = JSON.parse(skContent);
    secretKeyBase64 = keyData.secret_key;
  } catch (e) {
    secretKeyBase64 = skContent.trim();
  }

  const res = await fetch(API_BASE + `/api/ehr/download/${rid}`, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('token')}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      secret_key: secretKeyBase64
    })
  });

  if (!res.ok) throw await res.json();

  // Lấy header 'Content-Disposition'
  const disposition = res.headers.get('Content-Disposition');
  let filename = 'decrypted_file'; // Tên mặc định
  if (disposition && disposition.indexOf('attachment') !== -1) {
    const filenameRegex = /filename[^;=\n]*=((['"]).*?\2|[^;\n]*)/;
    const matches = filenameRegex.exec(disposition);
    if (matches != null && matches[1]) {
      filename = matches[1].replace(/['"]/g, '');
    }
  }

  const blob = await res.blob();

  // Trả về một object chứa cả hai
  return { filename, blob };
}