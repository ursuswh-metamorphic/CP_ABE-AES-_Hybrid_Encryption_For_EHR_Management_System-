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
    // Log lỗi đầy đủ ra console để dev xem, nhưng không hiển thị cho user
    console.error("Download Error:", err); 

    let errorMessage;
    // Kiểm tra mã lỗi từ server
    if (err.msg && err.msg.includes("Decryption failed")) {
        // Nếu giải mã thất bại, chỉ thông báo chung chung
        errorMessage = "Giải mã thất bại. Khóa bí mật được cung cấp không hợp lệ hoặc không đủ quyền để truy cập file này.";
    } else {
        // Với các lỗi khác (kết nối, file không tồn tại), hiển thị thông báo của server
        errorMessage = err.msg || 'Đã xảy ra lỗi trong quá trình download.';
    }
    
    alert.textContent = errorMessage;
    alert.className = 'alert alert-danger';
    alert.classList.remove('d-none');
  }
});