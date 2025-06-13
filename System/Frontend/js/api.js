// // const API_BASE = 'https://api.your-domain.com';
// const API_BASE = 'https://127.0.0.1:5000';

// async function request(path, opts = {}) {
//   const token = localStorage.getItem('token');
//   const headers = opts.headers || {};
//   if (token) headers['Authorization'] = `Bearer ${token}`;
//   const res = await fetch(API_BASE + path, { ...opts, headers });
//   if (!res.ok) throw await res.json();
//   return res;
// }

// async function getJson(path, opts) {
//   const res = await request(path, opts);
//   return res.json();
// }

// async function login(email, password) {
//   const res = await getJson('/api/auth/login', {
//     method:'POST',
//     headers:{'Content-Type':'application/json'},
//     body: JSON.stringify({ email, password })
//   });
//   return res;
// }

// // async function register(data) {
// //   return getJson('/api/auth/register', {
// //     method:'POST',
// //     headers:{'Content-Type':'application/json'},
// //     body: JSON.stringify(data)
// //   });
// // }

// async function keygen(attrs) {
//   // const res = await getJson('/api/keygen/', {
//   //   method:'POST',
//   //   headers:{'Content-Type':'application/json'},
//   //   body: JSON.stringify({ attributes: attrs })
//   // });
//   // return res;
//   const res = await request('/api/keygen/', {
//     method: 'POST',
//     headers: { 'Content-Type': 'application/json' },
//     body: JSON.stringify({ attributes: attrs })
//   });
//   return res.json();
// }

// async function uploadEhr(file, policy) {
//   const form = new FormData();
//   form.append('file', file);
//   form.append('policy', policy);
//   const res = await request('/api/ehr/upload', {
//     method:'POST',
//     body: form
//   });
//   return res.json();
// }

// async function downloadEhr(rid, skFile) {
//   const form = new FormData();
//   form.append('sk_file', skFile);
//   const res = await fetch(API_BASE + `/api/ehr/download/${rid}`, {
//     method:'POST',
//     headers:{
//       'Authorization': `Bearer ${localStorage.getItem('token')}`
//     },
//     body: form
//   });
//   if (!res.ok) throw await res.json();
//   return res.blob();
// }


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
  // const res = await request('/api/keygen/', {
  //   method: 'POST',
  //   headers: { 'Content-Type': 'application/json' },
  //   body: JSON.stringify({ attributes: attrs })
  // });
  // return res.json();
  const res = await request('/api/ehr/keygen', { // <-- KIỂM TRA ĐƯỜNG DẪN NÀY
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

// api.js

async function downloadEhr(rid, skFile) {
  // 1. Đọc nội dung của file secret key mà người dùng đã chọn
  const skContent = await skFile.text();

  // 2. Lấy secret_key từ nội dung file.
  // Giả sử file key của bạn là file JSON có dạng {"secret_key": "..."}
  let secretKeyBase64;
  try {
    const keyData = JSON.parse(skContent);
    secretKeyBase64 = keyData.secret_key;
  } catch (e) {
    // Nếu file chỉ chứa chuỗi base64, dùng trực tiếp nội dung file
    secretKeyBase64 = skContent.trim();
  }

  // 3. Gửi yêu cầu POST với đúng định dạng application/json
  const res = await fetch(API_BASE + `/api/ehr/download/${rid}`, {
    method: 'POST',
    // headers: {
    //   'Authorization': `Bearer ${localStorage.getItem('token')}`,
    //   'Content-Type': 'application/json' // <-- Header quan trọng nhất!
    // },
    headers: {
      'Authorization': `Bearer ${localStorage.getItem('token')}`,
      'Content-Type':  'application/json',
      'Accept-Encoding': 'identity'
    },
    // Gửi đi một body dạng JSON
    body: JSON.stringify({
      secret_key: secretKeyBase64
    })
  });

  if (!res.ok) throw await res.json();

  // 4. Trả về file đã được giải mã dưới dạng blob
  return res.blob();
}
