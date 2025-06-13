// const API_BASE = 'https://api.your-domain.com';
const API_BASE = 'https://127.0.0.1:5000';

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

// async function register(data) {
//   return getJson('/api/auth/register', {
//     method:'POST',
//     headers:{'Content-Type':'application/json'},
//     body: JSON.stringify(data)
//   });
// }

async function keygen(attrs) {
  // const res = await getJson('/api/keygen/', {
  //   method:'POST',
  //   headers:{'Content-Type':'application/json'},
  //   body: JSON.stringify({ attributes: attrs })
  // });
  // return res;
  const res = await request('/api/keygen/', {
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
  const form = new FormData();
  form.append('sk_file', skFile);
  const res = await fetch(API_BASE + `/api/ehr/download/${rid}`, {
    method:'POST',
    headers:{
      'Authorization': `Bearer ${localStorage.getItem('token')}`
    },
    body: form
  });
  if (!res.ok) throw await res.json();
  return res.blob();
}
