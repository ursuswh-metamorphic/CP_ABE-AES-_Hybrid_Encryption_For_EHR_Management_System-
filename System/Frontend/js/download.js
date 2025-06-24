document.getElementById('downloadForm').addEventListener('submit', async e => {
  e.preventDefault();
  const alert = document.getElementById('alert');
  alert.classList.add('d-none');
  const rid = document.getElementById('recordId').value;
  const skFile = document.getElementById('skFile').files[0];

  try {
    // downloadEhr giờ trả về một object
    const { filename, blob } = await downloadEhr(rid, skFile);

    // Sử dụng blob và filename nhận được
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.style.display = 'none'; // Ẩn thẻ a đi cho đẹp
    a.href = url; 
    a.download = filename; // Đặt tên file tải về tại đây!
    
    document.body.appendChild(a);
    a.click();
    
    // Dọn dẹp
    window.URL.revokeObjectURL(url);
    a.remove();

    alert.textContent = `File '${filename}' đã được download và giải mã thành công!`;
    alert.className = 'alert alert-success';
    alert.classList.remove('d-none');
    
  } catch(err) {
    let errorMessage = err.msg || 'Lỗi download';
    if (err.reason) {
        errorMessage += ` - Lý do: ${err.reason}`;
    }
    if (err.policy_required) {
        errorMessage += ` (Policy yêu cầu: ${err.policy_required})`;
    }
    alert.textContent = errorMessage;
    alert.className = 'alert alert-danger';
    alert.classList.remove('d-none');
  }
});