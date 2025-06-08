document.getElementById('genBtn').addEventListener('click', async () => {
  const alert = document.getElementById('alert');
  alert.classList.add('d-none');
  const attrs = document.getElementById('attrs').value.split(',').map(s=>s.trim());
  try {
    const { sk } = await keygen(attrs);
    // Base64 → binary
    const bin = atob(sk).split('').map(c=>c.charCodeAt(0));
    const blob = new Blob([new Uint8Array(bin)], { type:'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = 'user_sk.key'; document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    alert.textContent = 'Đã tải khóa về máy!';
    alert.className = 'alert alert-success';
    alert.classList.remove('d-none');
  } catch(err) {
    alert.textContent = err.msg || 'Lỗi tạo khóa';
    alert.className = 'alert alert-danger';
    alert.classList.remove('d-none');
  }
});
