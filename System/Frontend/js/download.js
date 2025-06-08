document.getElementById('downloadForm').addEventListener('submit', async e => {
  e.preventDefault();
  const alert = document.getElementById('alert');
  alert.classList.add('d-none');
  const rid    = document.getElementById('recordId').value;
  const skFile= document.getElementById('skFile').files[0];
  try {
    const blob = await downloadEhr(rid, skFile);
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = 'decrypted_ehr'; document.body.appendChild(a); a.click(); a.remove();
    URL.revokeObjectURL(url);
    alert.textContent = 'Download và giải mã thành công!';
    alert.className = 'alert alert-success';
    alert.classList.remove('d-none');
  } catch(err) {
    alert.textContent = err.msg || 'Lỗi download';
    alert.className = 'alert alert-danger';
    alert.classList.remove('d-none');
  }
});
