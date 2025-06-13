// document.getElementById('genBtn').addEventListener('click', async () => {
//   const alert = document.getElementById('alert');
//   alert.classList.add('d-none');
//   const attrs = document.getElementById('attrs').value.split(',').map(s=>s.trim());
//   try {
//     // const { sk } = await keygen(attrs);
//     const { secret_key } = await keygen(attrs);
//     // Base64 → binary
//     // const bin = atob(sk).split('').map(c=>c.charCodeAt(0));
//     const bin = atob(secret_key).split('').map(c=>c.charCodeAt(0));
//     const blob = new Blob([new Uint8Array(bin)], { type:'application/octet-stream' });
//     const url = URL.createObjectURL(blob);
//     const a = document.createElement('a');
//     a.href = url; a.download = 'user_sk.key'; document.body.appendChild(a); a.click(); a.remove();
//     URL.revokeObjectURL(url);
//     alert.textContent = 'Đã tải khóa về máy!';
//     alert.className = 'alert alert-success';
//     alert.classList.remove('d-none');
//   } catch(err) {
//     alert.textContent = err.msg || 'Lỗi tạo khóa';
//     alert.className = 'alert alert-danger';
//     alert.classList.remove('d-none');
//   }
// });
document.getElementById('genBtn').addEventListener('click', async () => {
  const alert = document.getElementById('alert');
  alert.classList.add('d-none');
  const attrs = document.getElementById('attrs').value.split(',').map(s => s.trim());

  try {
    const res = await fetch(API_BASE + '/api/keygen/', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      },
      body: JSON.stringify({ attributes: attrs })
    });

    if (res.status === 403) {
      const err = await res.json();
      throw new Error(err.msg);
    }
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.msg || 'Lỗi tạo khóa');
    }

    const { sk } = await res.json();
    const bin = atob(sk).split('').map(c => c.charCodeAt(0));
    const blob = new Blob([new Uint8Array(bin)], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'user_sk.key'; document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);

    alert.textContent = 'Đã tải khóa về máy!';
    alert.className = 'alert alert-success';
    alert.classList.remove('d-none');

  } catch (err) {
    alert.textContent = err.message;
    alert.className   = 'alert alert-danger';
    alert.classList.remove('d-none');
  }
});
