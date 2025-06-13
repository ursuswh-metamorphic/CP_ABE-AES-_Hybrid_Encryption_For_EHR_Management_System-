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
// document.getElementById('genBtn').addEventListener('click', async () => {
//   const alert = document.getElementById('alert');
//   alert.classList.add('d-none');
//   const attrs = document.getElementById('attrs').value.split(',').map(s => s.trim());

//   try {
//     const res = await fetch(API_BASE + '/api/keygen/', {
//       method: 'POST',
//       headers: {
//         'Content-Type': 'application/json',
//         'Authorization': `Bearer ${localStorage.getItem('token')}`
//       },
//       body: JSON.stringify({ attributes: attrs })
//     });

//     if (res.status === 403) {
//       const err = await res.json();
//       throw new Error(err.msg);
//     }
//     if (!res.ok) {
//       const err = await res.json();
//       throw new Error(err.msg || 'Lỗi tạo khóa');
//     }

//     const { sk } = await res.json();
//     const bin = atob(sk).split('').map(c => c.charCodeAt(0));
//     const blob = new Blob([new Uint8Array(bin)], { type: 'application/octet-stream' });
//     const url = URL.createObjectURL(blob);
//     const a = document.createElement('a');
//     a.href = url; a.download = 'user_sk.key'; document.body.appendChild(a); a.click(); a.remove();
//     URL.revokeObjectURL(url);

//     alert.textContent = 'Đã tải khóa về máy!';
//     alert.className = 'alert alert-success';
//     alert.classList.remove('d-none');

//   } catch (err) {
//     alert.textContent = err.message;
//     alert.className   = 'alert alert-danger';
//     alert.classList.remove('d-none');
//   }
// });

// // keygen.js - PHIÊN BẢN ĐÃ SỬA LỖI

// document.getElementById('genBtn').addEventListener('click', async () => {
//   const alert = document.getElementById('alert');
//   alert.classList.add('d-none');
  
//   // Lấy danh sách attributes từ input và lọc ra các giá trị rỗng
//   const attributesInput = document.getElementById('attrs').value;
//   const attributes = attributesInput.split(',')
//                                      .map(s => s.trim())
//                                      .filter(s => s.length > 0);

//   if (attributes.length === 0) {
//     alert.textContent = 'Vui lòng nhập ít nhất một thuộc tính.';
//     alert.className = 'alert alert-danger';
//     alert.classList.remove('d-none');
//     return;
//   }

//   try {
//     // 1. GỌI HÀM keygen TỪ api.js (ĐÂY LÀ THAY ĐỔI QUAN TRỌNG NHẤT)
//     const responseData = await keygen(attributes);

//     // 2. Tạo file JSON để tải về. Backend trả về đã đủ thông tin.
//     // Chúng ta sẽ lưu toàn bộ response để người dùng có thể xem lại attributes của key.
//     const fileContent = JSON.stringify(responseData, null, 2); // Định dạng JSON cho đẹp
//     const blob = new Blob([fileContent], { type: 'application/json' });
//     const url = URL.createObjectURL(blob);
//     const a = document.createElement('a');

//     // Lấy tên file từ response của backend hoặc đặt tên mặc định
//     a.href = url;
//     a.download = responseData.instructions?.save_as || 'user_sk.json';
    
//     document.body.appendChild(a);
//     a.click();
//     a.remove();
//     URL.revokeObjectURL(url);

//     // 3. Hiển thị thông báo thành công
//     alert.textContent = 'Đã tạo và tải file Secret Key (.json) thành công!';
//     alert.className = 'alert alert-success';
//     alert.classList.remove('d-none');

//   } catch (err) {
//     // 4. Xử lý lỗi
//     // `err.msg` là từ JSON lỗi mà backend trả về, ví dụ { "msg": "Lỗi gì đó" }
//     alert.textContent = err.msg || err.message || 'Một lỗi không xác định đã xảy ra.';
//     alert.className   = 'alert alert-danger';
//     alert.classList.remove('d-none');
//   }
// });

// keygen.js - PHIÊN BẢN TẠO FILE .KEY THÂN THIỆN

document.getElementById('genBtn').addEventListener('click', async () => {
  const alert = document.getElementById('alert');
  alert.classList.add('d-none');
  
  const attributesInput = document.getElementById('attrs').value;
  const attributes = attributesInput.split(',')
                                     .map(s => s.trim())
                                     .filter(s => s.length > 0);

  if (attributes.length === 0) {
    alert.textContent = 'Vui lòng nhập ít nhất một thuộc tính.';
    alert.className = 'alert alert-danger';
    alert.classList.remove('d-none');
    return;
  }

  try {
    // 1. Gọi hàm keygen từ api.js để lấy đối tượng JSON từ backend
    const responseData = await keygen(attributes);

    // 2. === THAY ĐỔI QUAN TRỌNG Ở ĐÂY ===
    // Trích xuất chuỗi secret_key từ đối tượng JSON nhận được
    const secretKeyString = responseData.secret_key;

    if (!secretKeyString) {
      // Báo lỗi nếu backend không trả về key
      throw new Error("Không nhận được secret key từ máy chủ.");
    }
    
    // 3. Tạo blob chứa DUY NHẤT chuỗi secret key
    const blob = new Blob([secretKeyString], { type: 'application/octet-stream' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');

    // 4. Đặt tên file là .key
    a.href = url;
    a.download = responseData.instructions?.save_as.replace('.json', '.key') || 'user_sk.key';
    
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);

    // 5. Hiển thị thông báo thành công
    alert.textContent = 'Đã tạo và tải file Secret Key (.key) thành công!';
    alert.className = 'alert alert-success';
    alert.classList.remove('d-none');

  } catch (err) {
    // 6. Xử lý lỗi
    alert.textContent = err.msg || err.message || 'Một lỗi không xác định đã xảy ra.';
    alert.className   = 'alert alert-danger';
    alert.classList.remove('d-none');
  }
});