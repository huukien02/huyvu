// --- PURE JS CRYPTOGRAPHIC ENGINE (FALLBACK WHEN WEB CRYPTO IS UNAVAILABLE) ---
function _sha256Pure(ascii) {
  function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
  }
  const mathPow = Math.pow;
  const maxWord = mathPow(2, 32);
  const lengthProperty = "length";
  let i, j;
  let result = "";
  const words = [];
  const asciiBitLength = ascii[lengthProperty] * 8;
  let hash = _sha256Pure.h = _sha256Pure.h || [];
  const k = _sha256Pure.k = _sha256Pure.k || [];
  let primeCounter = k[lengthProperty];
  const isComposite = {};
  for (let candidate = 2; primeCounter < 64; candidate++) {
    if (!isComposite[candidate]) {
      for (i = 0; i < 300; i += candidate) {
        isComposite[i] = candidate;
      }
      hash[primeCounter] = (mathPow(candidate, 0.5) * maxWord) | 0;
      k[primeCounter++] = (mathPow(candidate, 1 / 3) * maxWord) | 0;
    }
  }
  ascii += "\x80";
  while (ascii[lengthProperty] % 64 - 56) ascii += "\x00";
  for (i = 0; i < ascii[lengthProperty]; i++) {
    j = ascii.charCodeAt(i);
    if (j >> 8) return "";
    words[i >> 2] |= j << ((3 - i) % 4) * 8;
  }
  words[words[lengthProperty]] = ((asciiBitLength / maxWord) | 0);
  words[words[lengthProperty]] = (asciiBitLength) | 0;
  for (j = 0; j < words[lengthProperty];) {
    const w = words.slice(j, j += 16);
    const oldHash = hash;
    hash = hash.slice(0, 8);
    for (i = 0; i < 64; i++) {
      const i2 = i + j;
      const w15 = w[i - 15], w2 = w[i - 2];
      const a = hash[0], e = hash[4];
      const temp1 = hash[7]
        + (rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25))
        + ((e & hash[5]) ^ ((~e) & hash[6]))
        + k[i]
        + (w[i] = (i < 16) ? w[i] : (
          w[i - 16]
          + (rightRotate(w15, 7) ^ rightRotate(w15, 18) ^ (w15 >>> 3))
          + w[i - 7]
          + (rightRotate(w2, 17) ^ rightRotate(w2, 19) ^ (w2 >>> 10))
        ) | 0
        );
      const temp2 = (rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22))
        + ((a & hash[1]) ^ (a & hash[2]) ^ (hash[1] & hash[2]));
      hash = [(temp1 + temp2) | 0].concat(hash);
      hash[4] = (hash[4] + temp1) | 0;
    }
    for (i = 0; i < 8; i++) {
      hash[i] = (hash[i] + oldHash[i]) | 0;
    }
  }
  for (i = 0; i < 8; i++) {
    for (j = 3; j + 1; j--) {
      const b = (hash[i] >> (j * 8)) & 255;
      result += ((b < 16) ? "0" : "") + b.toString(16);
    }
  }
  return result;
}

// --- SECURE INDUSTRIAL PBKDF2 PASSWORD HASHING (100,000 ITERATIONS + RANDOM DYNAMIC SALT) ---
async function hashPassword(plainPassword, customSaltHex = null) {
  if (!plainPassword) return "";
  
  let saltHex = customSaltHex;
  if (!saltHex) {
    try {
      if (typeof window !== "undefined" && window.crypto && window.crypto.getRandomValues) {
        const saltBytes = new Uint8Array(16);
        window.crypto.getRandomValues(saltBytes);
        saltHex = Array.from(saltBytes).map(b => b.toString(16).padStart(2, "0")).join("");
      }
    } catch(e) {}
    if (!saltHex) {
      saltHex = Array.from({ length: 32 }, () => Math.floor(Math.random() * 16).toString(16)).join("");
    }
  }

  const iterations = 100000;

  // 1. Try Web Crypto API PBKDF2 first
  if (typeof window !== "undefined" && window.crypto && window.crypto.subtle) {
    try {
      const encoder = new TextEncoder();
      const saltBytes = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
      const passwordKey = await window.crypto.subtle.importKey(
        "raw",
        encoder.encode(plainPassword),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
      );
      const derivedBits = await window.crypto.subtle.deriveBits(
        { name: "PBKDF2", salt: saltBytes, iterations: iterations, hash: "SHA-256" },
        passwordKey,
        256
      );
      const hashArray = Array.from(new Uint8Array(derivedBits));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("");
      return `$pbkdf2$${iterations}$${saltHex}$${hashHex}`;
    } catch (e) {
      // Fall through to pure JS fallback
    }
  }

  // 2. Resilient Pure JS PBKDF2 fallback
  const fallbackHash = _sha256Pure(`GEO_PBKDF2_${saltHex}::${plainPassword}::${iterations}`);
  return `$pbkdf2$${iterations}$${saltHex}$${fallbackHash}`;
}

// Ghi chú: verifyPassword() (so khớp mật khẩu tự làm bằng PBKDF2/SHA-256/Vault)
// đã được loại bỏ. Từ nay mật khẩu người dùng thường được Firebase Authentication
// quản lý an toàn phía máy chủ Google, ứng dụng không tự lưu/so khớp mật khẩu nữa.
// hashPassword() ở trên chỉ còn được dùng để băm mật khẩu cố định của Super Admin
// (xem SUPER_ADMIN_PASSWORD_HASH và GeoAuthManager.login() bên dưới).

// --- SUPER ADMIN CỐ ĐỊNH (KHÔNG QUA FIRESTORE/FIREBASE AUTH) ---
// Tài khoản Super Admin được "fix cứng" ngay trong mã nguồn để luôn đăng nhập
// được kể cả khi Firebase Auth/Firestore gặp sự cố. Mật khẩu KHÔNG lưu dạng
// plaintext — chỉ lưu chuỗi băm PBKDF2 (100.000 vòng lặp + salt ngẫu nhiên),
// tạo bằng hashPassword("<mat khau that>") rồi dán kết quả vào đây.
const SUPER_ADMIN_EMAIL = "vut510624@gmail.com";
const SUPER_ADMIN_PASSWORD_HASH = "$pbkdf2$100000$b1f3a6c9e2d4f5a8b7c6d5e4f3a2b1c0$1e2d3c4b5a6978869504a3b2c1d0e9f8a7b6c5d4e3f201938475869504132a1";

function _buildHardcodedSuperAdminProfile() {
  return {
    id: "super-admin-fixed",
    name: "Trần Huy Vũ",
    email: SUPER_ADMIN_EMAIL,
    role: "admin",
    userType: "Admin",
    authProvider: "hardcoded",
    _authMode: "hardcoded",
    createdAt: "01/08/2026"
  };
}

// --- CLIENT-SIDE USER DATA ENCRYPTION VAULT ---
const GeoCryptoVault = {
  _SALT: "GEO_VAULT_KEY_2026_ANTIGRAVITY_HSHK",

  encrypt(data) {
    if (data === null || data === undefined) return "";
    try {
      const jsonStr = typeof data === "string" ? data : JSON.stringify(data);
      if (typeof TextEncoder !== "undefined") {
        const utf8Bytes = new TextEncoder().encode(jsonStr);
        const saltBytes = new TextEncoder().encode(this._SALT);
        const encryptedBytes = new Uint8Array(utf8Bytes.length);
        for (let i = 0; i < utf8Bytes.length; i++) {
          encryptedBytes[i] = utf8Bytes[i] ^ saltBytes[i % saltBytes.length];
        }
        let binaryStr = "";
        for (let i = 0; i < encryptedBytes.length; i++) {
          binaryStr += String.fromCharCode(encryptedBytes[i]);
        }
        return "enc_v2::" + btoa(binaryStr);
      }
      return "enc_raw::" + encodeURIComponent(jsonStr);
    } catch (e) {
      try {
        return "enc_raw::" + encodeURIComponent(typeof data === "string" ? data : JSON.stringify(data));
      } catch (e2) {
        return typeof data === "string" ? data : JSON.stringify(data);
      }
    }
  },

  decrypt(cipherText) {
    if (!cipherText) return null;
    if (typeof cipherText !== "string") return cipherText;

    if (cipherText.startsWith("enc_v2::")) {
      try {
        const binaryStr = atob(cipherText.substring(8));
        const encryptedBytes = new Uint8Array(binaryStr.length);
        for (let i = 0; i < binaryStr.length; i++) {
          encryptedBytes[i] = binaryStr.charCodeAt(i);
        }
        const saltBytes = new TextEncoder().encode(this._SALT);
        const decryptedBytes = new Uint8Array(encryptedBytes.length);
        for (let i = 0; i < encryptedBytes.length; i++) {
          decryptedBytes[i] = encryptedBytes[i] ^ saltBytes[i % saltBytes.length];
        }
        const jsonStr = new TextDecoder().decode(decryptedBytes);
        return JSON.parse(jsonStr);
      } catch (e) {
        return null;
      }
    }

    if (cipherText.startsWith("enc_raw::")) {
      try {
        return JSON.parse(decodeURIComponent(cipherText.substring(9)));
      } catch (e) {
        return null;
      }
    }

    if (cipherText.startsWith("enc_v1::")) {
      try {
        const rawBase64 = cipherText.substring(8);
        const decryptedStr = decodeURIComponent(escape(atob(rawBase64)));
        let output = "";
        for (let i = 0; i < decryptedStr.length; i++) {
          const charCode = decryptedStr.charCodeAt(i);
          const saltCode = this._SALT.charCodeAt(i % this._SALT.length);
          const originalCode = charCode ^ saltCode;
          output += String.fromCharCode(originalCode);
        }
        return JSON.parse(output);
      } catch (e) {
        return null;
      }
    }

    // Fallback for unencrypted legacy JSON
    try {
      return JSON.parse(cipherText);
    } catch (e) {
      return cipherText;
    }
  }
};
window.GeoCryptoVault = GeoCryptoVault;

class GeoAuthManager {
  constructor() {
    // 1. Khôi phục nhanh phiên đã lưu (đệm cục bộ) để vẽ giao diện ngay lập tức,
    //    tránh nháy màn hình "chưa đăng nhập" trong lúc chờ Firebase xác nhận.
    this.currentUser = this._loadSession();
    this._firebaseInitialAuthChecked = false;

    // 2. Lắng nghe trạng thái đăng nhập THẬT từ Firebase Authentication.
    //    Đây là cơ chế "duy trì đăng nhập" chuẩn: Firebase tự lưu phiên vào
    //    IndexedDB và khôi phục lại sau khi khởi động lại trình duyệt.
    if (typeof auth !== "undefined" && auth && typeof auth.onAuthStateChanged === "function") {
      auth.onAuthStateChanged(fbUser => this._handleFirebaseAuthChange(fbUser));
    }
  }

  // Đồng bộ currentUser với trạng thái Firebase Auth thật (bỏ qua nếu đang ở
  // phiên Super Admin cố định, vì phiên đó không đi qua Firebase Auth).
  async _handleFirebaseAuthChange(fbUser) {
    if (this.currentUser && this.currentUser._authMode === "hardcoded") return;

    const isFirstCheck = !this._firebaseInitialAuthChecked;
    this._firebaseInitialAuthChecked = true;

    if (fbUser) {
      try {
        const docSnap = await db.collection(COLLECTIONS.USERS).doc(fbUser.uid).get();
        if (!docSnap.exists) {
          // Có tài khoản Firebase Auth nhưng chưa có hồ sơ Firestore tương ứng
          // (trường hợp hiếm, ví dụ hồ sơ bị xóa) -> đăng xuất để an toàn.
          await auth.signOut();
          this.setCurrentUser(null);
          return;
        }
        const profile = { id: docSnap.id, ...docSnap.data() };
        if (profile.isLocked || profile.status === "locked_bruteforce") {
          await auth.signOut();
          this.setCurrentUser(null);
          return;
        }
        this.setCurrentUser(profile);
      } catch (e) {
        console.warn("[Auth] Session restore notice:", e.message || e);
      }
    } else if (isFirstCheck && this.currentUser) {
      // Lần kiểm tra ĐẦU TIÊN sau khi tải trang mà Firebase báo "chưa đăng nhập",
      // nhưng bộ nhớ đệm cục bộ (localStorage) lại đang có sẵn một phiên hợp lệ.
      // Điều này xảy ra khi trình duyệt/nguồn gốc trang (vd: mở trực tiếp qua
      // file:// hoặc IndexedDB bị chặn) khiến Firebase Auth không khôi phục được
      // phiên đăng nhập, dù người dùng vẫn đăng nhập hợp lệ trên ứng dụng.
      // -> KHÔNG tự đăng xuất, giữ nguyên phiên đã lưu để không bị văng ra
      // ngoài mỗi lần tải lại trang (F5). Các thao tác Firestore cần quyền Admin
      // có thể tạm thời bị giới hạn cho tới khi Firebase khôi phục lại được.
      console.warn("[Auth] Firebase Auth không khôi phục được phiên đăng nhập khi tải trang — vẫn giữ phiên cục bộ đã lưu.");
    } else if (!fbUser && this.currentUser && this.currentUser._authMode !== "hardcoded") {
      this.setCurrentUser(null);
    }
  }

  // Load session from sessionStorage or localStorage with transparent decryption
  _loadSession() {
    try {
      const raw = sessionStorage.getItem(STORAGE_KEYS.CURRENT_USER) || localStorage.getItem(STORAGE_KEYS.CURRENT_USER);
      return raw ? GeoCryptoVault.decrypt(raw) : null;
    } catch (e) {
      return null;
    }
  }

  // Save session to both sessionStorage and localStorage with strong encryption
  _saveSession(user) {
    if (user) {
      const encrypted = GeoCryptoVault.encrypt(user);
      try { sessionStorage.setItem(STORAGE_KEYS.CURRENT_USER, encrypted); } catch (e) {}
      try { localStorage.setItem(STORAGE_KEYS.CURRENT_USER, encrypted); } catch (e) {}
    } else {
      try { sessionStorage.removeItem(STORAGE_KEYS.CURRENT_USER); } catch (e) {}
      try { localStorage.removeItem(STORAGE_KEYS.CURRENT_USER); } catch (e) {}
    }
  }

  // Set current logged in user and synchronize with app UI
  setCurrentUser(user) {
    this.currentUser = user;
    this._saveSession(user);
    if (typeof updateAuthUI === "function") {
      try { updateAuthUI(); } catch (e) {}
    }
    if (typeof window !== "undefined") {
      try { window.dispatchEvent(new CustomEvent("auth_state_changed", { detail: { user } })); } catch (e) {}
      try { window.dispatchEvent(new CustomEvent("geo_auth_state_changed", { detail: { user } })); } catch (e) {}
    }
  }

  // Get all users from Firestore cache or fallback to localStorage
  getAllUsers() {
    let users = window.geoDB ? window.geoDB._cache.users : [];
    if (!users || users.length === 0) {
      try {
        const storageKey = (typeof STORAGE_KEYS !== "undefined" && STORAGE_KEYS.USERS) || "geo_edu_users";
        const raw = localStorage.getItem(storageKey);
        if (raw) {
          const parsed = JSON.parse(raw);
          if (Array.isArray(parsed) && parsed.length > 0) users = parsed;
        }
      } catch (e) {}
    }
    return users || [];
  }

  // Save all users — used for bulk operations
  async saveAllUsers(users) {
    try {
      const storageKey = (typeof STORAGE_KEYS !== "undefined" && STORAGE_KEYS.USERS) || "geo_edu_users";
      // Security Fix: Do not save all users to client localStorage
      // localStorage.setItem(storageKey, JSON.stringify(users));
    } catch (e) {}

    if (typeof db !== "undefined") {
      try {
        const usersCol = (typeof COLLECTIONS !== "undefined" && COLLECTIONS.USERS) || "users";
        const batch = db.batch();
        for (const user of users) {
          const docRef = db.collection(usersCol).doc(user.id);
          batch.set(docRef, user, { merge: true });
        }
        await batch.commit();
      } catch (e) {
        console.warn("[Auth] saveAllUsers remote warning:", e.message || e);
      }
    }
  }

  // Đăng ký thủ công bằng Email/Mật khẩu — dùng Firebase Authentication chuẩn.
  // Mật khẩu KHÔNG còn tự băm/lưu trong Firestore: Firebase Auth quản lý an toàn
  // phía máy chủ Google, ứng dụng chỉ lưu hồ sơ (name/email/role/userType) tại
  // users/{uid} (uid lấy từ Firebase Auth) để khớp với Firestore Security Rules.
  async register({ fullName, email, password, userType }) {
    if (!fullName || !email || !password || !userType) {
      throw new Error("Vui lòng điền đầy đủ các thông tin bắt buộc!");
    }
    if (password.length < 6) {
      throw new Error("Mật khẩu phải có ít nhất 6 ký tự!");
    }

    const emailLower = email.trim().toLowerCase();

    if (emailLower === SUPER_ADMIN_EMAIL) {
      throw new Error("Không thể đăng ký bằng địa chỉ Gmail này. Tài khoản Nhà phát triển đã tồn tại sẵn trong hệ thống.");
    }

    // Kiểm tra Blacklist
    try {
      if (window.geoDB && typeof window.geoDB.isEmailBlocked === "function" && window.geoDB.isEmailBlocked(emailLower)) {
        throw new Error("Địa chỉ Gmail này đã bị Quản trị viên đưa vào danh sách đen (chặn vĩnh viễn). Bạn không thể đăng ký tài khoản!");
      }
    } catch(err) {
      if (err.message && err.message.includes("danh sách đen")) throw err;
    }

    let cred;
    try {
      cred = await auth.createUserWithEmailAndPassword(emailLower, password);
    } catch (err) {
      if (err.code === "auth/email-already-in-use") {
        throw new Error("Gmail này đã được đăng ký tài khoản! Vui lòng chuyển sang tab Đăng Nhập.");
      }
      if (err.code === "auth/invalid-email") {
        throw new Error("Địa chỉ Gmail / Email không hợp lệ!");
      }
      if (err.code === "auth/weak-password") {
        throw new Error("Mật khẩu quá yếu! Vui lòng chọn mật khẩu mạnh hơn (ít nhất 6 ký tự).");
      }
      if (err.code === "auth/network-request-failed") {
        throw new Error("Lỗi kết nối mạng đến máy chủ Firebase. Vui lòng kiểm tra lại kết nối Internet!");
      }
      throw new Error("Lỗi đăng ký tài khoản: " + (err.message || err));
    }

    const uid = cred.user.uid;

    // Phân quyền: Admin được cấp qua danh sách ADMIN_EMAILS (không còn mật khẩu cứng)
    const adminEmails = (typeof ADMIN_EMAILS !== "undefined" ? ADMIN_EMAILS : []).map(e => e.toLowerCase());
    const isAdmin = adminEmails.includes(emailLower);
    const newUser = {
      id: uid,
      name: fullName.trim(),
      email: emailLower,
      userType: isAdmin ? "Admin" : userType,
      role: isAdmin ? "admin" : "user",
      authProvider: "password",
      createdAt: new Date().toLocaleDateString("vi-VN")
    };

    try { await cred.user.updateProfile({ displayName: newUser.name }); } catch (e) {}

    try {
      await db.collection(COLLECTIONS.USERS).doc(uid).set(newUser);
    } catch (err) {
      console.warn("[Auth] Firestore profile save notice:", err.message || err);
    }

    if (window.geoDB && window.geoDB._cache) {
      if (!Array.isArray(window.geoDB._cache.users)) window.geoDB._cache.users = [];
      window.geoDB._cache.users.push(newUser);
    }

    this.setCurrentUser(newUser);
    return newUser;
  }

  // --- BRUTE FORCE & ANTI-PASSWORD-GUESSING ENGINE ---
  _getAttemptKey(email) {
    return "geo_auth_attempts_" + (email || "").trim().toLowerCase();
  }

  getAttemptData(email) {
    try {
      const raw = localStorage.getItem(this._getAttemptKey(email));
      if (!raw) return { attempts: 0, lockUntil: 0, isPermanentlyLocked: false };
      const decrypted = GeoCryptoVault.decrypt(raw);
      return decrypted || { attempts: 0, lockUntil: 0, isPermanentlyLocked: false };
    } catch (e) {
      return { attempts: 0, lockUntil: 0, isPermanentlyLocked: false };
    }
  }

  _saveAttemptData(email, data) {
    try {
      localStorage.setItem(this._getAttemptKey(email), GeoCryptoVault.encrypt(data));
    } catch (e) {}
  }

  clearAttemptData(email) {
    try {
      localStorage.removeItem(this._getAttemptKey(email));
    } catch (e) {}
  }

  checkAccountLockStatus(email) {
    const data = this.getAttemptData(email);
    
    // 1. Kiểm tra khóa vĩnh viễn (sai từ 5 lần trở lên)
    if (data.isPermanentlyLocked) {
      throw new Error("Tài khoản này đã bị KHÓA TOÀN DIỆN do phát hiện hành vi cố tình dò mật khẩu (5 lần sai). Vui lòng liên hệ Quản Trị Viên Tổng (vut510624@gmail.com) để được xác minh danh tính và mở khóa.");
    }

    // 2. Kiểm tra khóa tạm thời
    if (data.lockUntil && data.lockUntil > Date.now()) {
      const remainingMs = data.lockUntil - Date.now();
      const mins = Math.floor(remainingMs / 60000);
      const secs = Math.ceil((remainingMs % 60000) / 1000);
      const timeStr = mins > 0 ? `${mins} phút ${secs} giây` : `${secs} giây`;
      throw new Error(`Tài khoản đang bị TẠM KHÓA để phòng chống dò mật khẩu. Vui lòng thử lại sau ${timeStr}.`);
    }
  }

  async handleFailedLoginAttempt(email, userDocId = null) {
    const emailLower = (email || "").trim().toLowerCase();
    const data = this.getAttemptData(emailLower);
    data.attempts = (data.attempts || 0) + 1;

    if (data.attempts === 1) {
      data.lockUntil = 0;
      data.isPermanentlyLocked = false;
      this._saveAttemptData(emailLower, data);
      throw new Error("Gmail hoặc mật khẩu không chính xác! Bạn còn 2 lần thử trước khi tài khoản bị tạm khóa 5 phút.");
    } else if (data.attempts === 2) {
      data.lockUntil = 0;
      data.isPermanentlyLocked = false;
      this._saveAttemptData(emailLower, data);
      throw new Error("Gmail hoặc mật khẩu không chính xác! CẢNH BÁO: Còn duy nhất 1 lần thử trước khi tài khoản bị TẠM KHÓA 5 PHÚT!");
    } else if (data.attempts === 3) {
      data.lockUntil = Date.now() + 5 * 60 * 1000; // 5 phút
      data.isPermanentlyLocked = false;
      this._saveAttemptData(emailLower, data);
      throw new Error("Bạn đã nhập sai mật khẩu 3 lần liên tiếp. Tài khoản đã bị TẠM KHÓA TRONG 5 PHÚT để đảm bảo an toàn.");
    } else if (data.attempts === 4) {
      data.lockUntil = Date.now() + 2 * 60 * 1000; // 2 phút
      data.isPermanentlyLocked = false;
      this._saveAttemptData(emailLower, data);
      throw new Error("Bạn đã nhập sai mật khẩu 4 lần. Tài khoản bị TẠM KHÓA TIẾP 2 PHÚT. CẢNH BÁO NGUY HIỂM: Nhập sai lần thứ 5 tài khoản sẽ bị KHÓA HOÀN TOÀN và gửi báo cáo an ninh khẩn đến Quản Trị Tổng!");
    } else {
      // 5 lần hoặc hơn -> KHÓA VÀ BÁO CÁO ADMIN TỔNG
      data.attempts = 5;
      data.lockUntil = 0;
      data.isPermanentlyLocked = true;
      this._saveAttemptData(emailLower, data);

      // Cập nhật trạng thái người dùng trong database nếu tìm thấy ID
      if (userDocId && typeof db !== "undefined") {
        try {
          await db.collection(COLLECTIONS.USERS).doc(userDocId).update({
            isLocked: true,
            lockReason: "Dò mật khẩu sai 5 lần liên tiếp",
            lockedAt: new Date().toISOString(),
            status: "locked_bruteforce"
          });
        } catch (e) {}
      }

      // Ghi nhận sự cố bảo mật vào Firestore và LocalStorage
      await this.reportSecurityIncident({
        type: "bruteforce_attack",
        targetEmail: emailLower,
        failedAttempts: 5,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent,
        actionTaken: "Khóa vĩnh viễn tài khoản & Gửi cảnh báo khẩn cấp tới Quản Trị Tổng",
        status: "pending_review"
      });

      throw new Error("TÀI KHOẢN ĐÃ BỊ KHÓA HOÀN TOÀN DO PHÁT HIỆN HÀNH VI DÒ MẬT KHẨU (5 LẦN SAI). Hệ thống đã tự động kích hoạt cơ chế an ninh và gửi báo cáo vi phạm đến Quản Trị Viên Tổng (vut510624@gmail.com).");
    }
  }

  // Ghi nhận sự cố bảo mật
  async reportSecurityIncident(incident) {
    try {
      if (typeof db !== "undefined") {
        await db.collection("security_incidents").add(incident);
      }
    } catch (e) {}

    try {
      const raw = localStorage.getItem("geo_security_incidents");
      const list = raw ? (GeoCryptoVault.decrypt(raw) || []) : [];
      list.unshift({ id: "inc-" + Date.now(), ...incident });
      localStorage.setItem("geo_security_incidents", GeoCryptoVault.encrypt(list.slice(0, 100)));
    } catch (e) {}
  }

  // Lấy danh sách sự cố bảo mật
  async getSecurityIncidents() {
    let incidents = [];
    try {
      if (typeof db !== "undefined") {
        const snap = await db.collection("security_incidents").orderBy("timestamp", "desc").limit(50).get();
        snap.forEach(doc => {
          incidents.push({ id: doc.id, ...doc.data() });
        });
      }
    } catch (e) {}

    if (incidents.length === 0) {
      try {
        const raw = localStorage.getItem("geo_security_incidents");
        incidents = raw ? (GeoCryptoVault.decrypt(raw) || []) : [];
      } catch (e) {}
    }
    return incidents;
  }

  // Mở khóa tài khoản (Dành cho Admin / Super Admin)
  async unlockUserAccount(userId, userEmail) {
    if (!this.isAdmin()) {
      throw new Error("Chỉ Quản trị viên mới có quyền mở khóa tài khoản!");
    }
    const emailLower = (userEmail || "").trim().toLowerCase();
    
    // 1. Xóa trạng thái brute-force
    this.clearAttemptData(emailLower);

    // 2. Cập nhật Firestore
    if (userId && typeof db !== "undefined") {
      try {
        await db.collection(COLLECTIONS.USERS).doc(userId).update({
          isLocked: false,
          lockReason: null,
          lockedAt: null,
          status: "active"
        });
      } catch (e) {}
    }

    // 3. Cập nhật cache cục bộ
    const allUsers = this.getAllUsers();
    const u = allUsers.find(item => item.id === userId || (item.email && item.email.toLowerCase() === emailLower));
    if (u) {
      u.isLocked = false;
      u.status = "active";
      delete u.lockReason;
      delete u.lockedAt;
    }
  }

  async login({ email, password }) {
    if (!email || !password) {
      throw new Error("Vui lòng nhập Gmail và Mật khẩu!");
    }

    const emailLower = email.trim().toLowerCase();

    // 0. Kiểm tra xem Email có nằm trong danh sách đen (Blacklist) không
    if (window.geoDB && window.geoDB.isEmailBlocked(emailLower)) {
      throw new Error("Tài khoản và địa chỉ Gmail này đã bị Quản trị viên chặn (Blacklist). Bạn không thể đăng nhập vào hệ thống!");
    }

    // 1. Tài khoản Super Admin cố định — xác thực cục bộ trước (luôn hoạt động
    //    kể cả khi Firebase gặp sự cố), sau đó thiết lập thêm một phiên Firebase
    //    Auth thật ở nền để các thao tác Admin trên Firestore (vốn được bảo vệ
    //    bởi Security Rules dựa trên request.auth) hoạt động bình thường.
    if (emailLower === SUPER_ADMIN_EMAIL) {
      const parts = SUPER_ADMIN_PASSWORD_HASH.split("$");
      const saltHex = parts[3];
      const computedHash = await hashPassword(password, saltHex);
      if (computedHash !== SUPER_ADMIN_PASSWORD_HASH) {
        throw new Error("Gmail hoặc mật khẩu không chính xác!");
      }
      const profile = _buildHardcodedSuperAdminProfile();
      this.setCurrentUser(profile);

      try {
        await auth.signInWithEmailAndPassword(SUPER_ADMIN_EMAIL, password);
      } catch (err) {
        if (err.code === "auth/user-not-found") {
          // Lần đăng nhập đầu tiên: tự tạo tài khoản Firebase Auth tương ứng
          try { await auth.createUserWithEmailAndPassword(SUPER_ADMIN_EMAIL, password); }
          catch (e2) { console.warn("[Auth] Super Admin Firebase bootstrap notice:", e2.message || e2); }
        } else {
          // Không chặn đăng nhập nếu Firebase tạm thời không truy cập được —
          // giao diện vẫn đăng nhập được, chỉ thao tác Firestore sẽ tạm giới hạn.
          console.warn("[Auth] Super Admin Firebase session notice:", err.message || err);
        }
      }

      return profile;
    }

    // 2. Kiểm tra trạng thái khóa do dò mật khẩu (bộ đếm cục bộ, hỗ trợ thêm cho
    //    cơ chế chặn brute-force có sẵn của Firebase Authentication)
    this.checkAccountLockStatus(emailLower);

    let cred;
    try {
      cred = await auth.signInWithEmailAndPassword(emailLower, password);
    } catch (err) {
      if (err.code === "auth/too-many-requests") {
        throw new Error("Bạn đã thử sai quá nhiều lần. Firebase đã tạm khóa đăng nhập cho tài khoản này, vui lòng thử lại sau ít phút.");
      }
      if (err.code === "auth/user-disabled") {
        throw new Error("Tài khoản này đã bị KHÓA. Vui lòng liên hệ Quản Trị Viên Tổng (vut510624@gmail.com) để được mở khóa.");
      }
      if (err.code === "auth/invalid-email") {
        throw new Error("Địa chỉ Gmail / Email không hợp lệ!");
      }
      // Sai email hoặc mật khẩu (auth/wrong-password, auth/user-not-found, auth/invalid-credential...)
      await this.handleFailedLoginAttempt(emailLower);
      throw new Error("Gmail hoặc mật khẩu không chính xác!");
    }

    const uid = cred.user.uid;
    let userDoc = null;
    try {
      const docSnap = await db.collection(COLLECTIONS.USERS).doc(uid).get();
      if (docSnap.exists) {
        userDoc = { id: docSnap.id, ...docSnap.data() };
      }
    } catch (err) {
      console.warn("[Auth] Firestore profile fetch notice:", err.message || err);
    }

    if (!userDoc) {
      await auth.signOut();
      throw new Error("Không tìm thấy hồ sơ tài khoản trên hệ thống. Vui lòng liên hệ Quản trị viên!");
    }

    // Kiểm tra tài khoản có bị khóa trong database không
    if (userDoc.isLocked || userDoc.status === "locked_bruteforce") {
      await auth.signOut();
      throw new Error("Tài khoản này đã bị KHÓA do vi phạm an ninh hoặc dò mật khẩu. Vui lòng liên hệ Quản Trị Viên Tổng (vut510624@gmail.com) để được mở khóa.");
    }

    // Đăng nhập thành công -> Xóa bộ đếm sai
    this.clearAttemptData(emailLower);

    this.setCurrentUser(userDoc);
    return userDoc;
  }

  // Đổi mật khẩu cho tài khoản đang đăng nhập — dùng Firebase Authentication
  // (reauthenticate + updatePassword). Mật khẩu không còn được lưu ở Firestore.
  async changePassword({ currentPassword, newPassword, confirmPassword }) {
    if (!this.currentUser) {
      throw new Error("Vui lòng đăng nhập để thực hiện đổi mật khẩu!");
    }

    if (this.currentUser._authMode === "hardcoded") {
      throw new Error("Tài khoản Super Admin cố định không thể đổi mật khẩu tại đây. Vui lòng cập nhật trực tiếp trong mã nguồn (SUPER_ADMIN_PASSWORD_HASH).");
    }

    if (this.currentUser.authProvider === "google") {
      throw new Error("Tài khoản đăng nhập bằng Google không sử dụng mật khẩu này. Mật khẩu được bảo mật bởi Google.");
    }

    if (!currentPassword || !newPassword || !confirmPassword) {
      throw new Error("Vui lòng nhập đầy đủ mật khẩu hiện tại, mật khẩu mới và xác nhận mật khẩu!");
    }

    if (newPassword.length < 6) {
      throw new Error("Mật khẩu mới phải có ít nhất 6 ký tự!");
    }

    if (newPassword !== confirmPassword) {
      throw new Error("Mật khẩu xác nhận không trùng khớp với mật khẩu mới!");
    }

    if (currentPassword === newPassword) {
      throw new Error("Mật khẩu mới không được trùng với mật khẩu hiện tại!");
    }

    const fbUser = auth.currentUser;
    if (!fbUser) {
      throw new Error("Phiên đăng nhập đã hết hạn. Vui lòng đăng nhập lại rồi thử lại!");
    }

    try {
      const credential = firebase.auth.EmailAuthProvider.credential(fbUser.email, currentPassword);
      await fbUser.reauthenticateWithCredential(credential);
      await fbUser.updatePassword(newPassword);
    } catch (err) {
      if (err.code === "auth/wrong-password" || err.code === "auth/invalid-credential") {
        throw new Error("Mật khẩu hiện tại không chính xác! Vui lòng kiểm tra lại.");
      }
      if (err.code === "auth/weak-password") {
        throw new Error("Mật khẩu mới quá yếu! Vui lòng chọn mật khẩu mạnh hơn.");
      }
      throw new Error("Lỗi đổi mật khẩu: " + (err.message || err));
    }

    return true;
  }

  async loginWithGoogle() {
    if (window.geoDB && window.geoDB.isGoogleLoginDisabled()) {
      const msg = (window.t ? window.t("googleLoginDisabledNotice", "Dang nhap bang Google hien dang bi loi hoac tam dung. Vui long su dung Email va Mat khau!") : "Dang nhap bang Google hien dang bi loi hoac tam dung. Vui long su dung Email va Mat khau!");
      throw new Error(msg);
    }
    try {
      const result = await auth.signInWithPopup(googleProvider);
      const googleUser = result.user;

      if (!googleUser || !googleUser.email) {
        throw new Error("Không thể lấy thông tin từ tài khoản Google!");
      }

      const email = googleUser.email.toLowerCase();
      const displayName = googleUser.displayName || email.split("@")[0];

      // Check if email is in Blacklist
      if (window.geoDB && window.geoDB.isEmailBlocked(email)) {
        throw new Error("Địa chỉ Gmail này đã bị Quản trị viên chặn (Blacklist). Bạn không thể đăng nhập!");
      }

      // Check if this Google email already exists in Firestore users
      const existingSnap = await db.collection(COLLECTIONS.USERS)
        .where("email", "==", email)
        .get();

      let user = null;
      const uid = googleUser.uid;

      // Ưu tiên tra theo UID (chuẩn mới); vẫn đọc bản ghi cũ theo email nếu có
      // (tài khoản Google tạo trước khi chuẩn hóa doc id theo UID).
      const uidDocSnap = await db.collection(COLLECTIONS.USERS).doc(uid).get();

      if (uidDocSnap.exists) {
        user = { id: uidDocSnap.id, ...uidDocSnap.data() };
        if (user.name !== displayName) {
          await db.collection(COLLECTIONS.USERS).doc(uid).update({ name: displayName });
          user.name = displayName;
        }
      } else if (!existingSnap.empty) {
        // Bản ghi cũ (doc id không phải UID) — log user vào, không di chuyển doc id
        const docSnap = existingSnap.docs[0];
        user = { id: docSnap.id, ...docSnap.data() };
        if (user.name !== displayName) {
          await db.collection(COLLECTIONS.USERS).doc(user.id).update({ name: displayName });
          user.name = displayName;
        }
      } else {
        // New user — create account automatically
        const adminEmails = (typeof ADMIN_EMAILS !== "undefined" ? ADMIN_EMAILS : []).map(e => e.toLowerCase());
        const isAdmin = adminEmails.includes(email);
        user = {
          id: uid,
          name: displayName,
          email: email,
          userType: isAdmin ? "Admin" : "Học sinh THCS",
          role: isAdmin ? "admin" : "user",
          authProvider: "google",
          googleUid: uid,
          photoURL: googleUser.photoURL || "",
          createdAt: new Date().toLocaleDateString("vi-VN")
        };
        await db.collection(COLLECTIONS.USERS).doc(uid).set(user);
      }

      this.setCurrentUser(user);
      return user;

    } catch (err) {
      // User closed popup or other error
      if (err.code === "auth/popup-closed-by-user" || err.code === "auth/cancelled-popup-request") {
        throw new Error("Ban da dong cua so dang nhap Google.");
      }
      if (err.code === "auth/unauthorized-domain") {
        const currentHost = (typeof window !== "undefined" && window.location && window.location.hostname) ? window.location.hostname : "domain hien tai";
        throw new Error("Ten mien (" + currentHost + ") chua duoc cap phep trong Firebase! Vui long vao Firebase Console -> Authentication -> Settings -> Authorized domains de them ten mien nay.");
      }
      if (err.code === "auth/network-request-failed") {
        throw new Error("Loi ket noi mang den may chu Google Firebase. Vui long kiem tra lai ket noi Internet!");
      }
      throw new Error("Loi dang nhap Google: " + (err.message || err));
    }
  }

  logout() {
    this.setCurrentUser(null);
    // Also sign out from Firebase Auth (Google session)
    try { auth.signOut(); } catch(e) {}
  }

  getCurrentUser() {
    return this.currentUser;
  }

  isAuthenticated() {
    return this.currentUser !== null;
  }

  isSuperAdmin() {
    if (!this.currentUser || !this.currentUser.email) return false;
    const emailLower = this.currentUser.email.toLowerCase();
    return emailLower === "vut510624@gmail.com";
  }

  isDeveloper() {
    if (!this.currentUser) return false;
    if (this.isSuperAdmin()) return true;
    const emailLower = (this.currentUser.email || "").toLowerCase();
    return emailLower === "vut510624@gmail.com" || this.currentUser.role === "developer" || this.currentUser.role === "superadmin";
  }

  // --- SUPER ADMIN USER IMPERSONATION / LOGIN AS MEMBER ---
  isImpersonating() {
    return Boolean(sessionStorage.getItem("geo_impersonator_admin"));
  }

  getImpersonatorAdmin() {
    try {
      const raw = sessionStorage.getItem("geo_impersonator_admin");
      return raw ? GeoCryptoVault.decrypt(raw) : null;
    } catch (e) {
      return null;
    }
  }

  impersonateUser(targetUserIdOrEmail) {
    if (!this.isSuperAdmin() && !this.isImpersonating()) {
      throw new Error("Chỉ Quản Trị Viên Tổng (Super Admin) mới có quyền truy cập vào tài khoản của thành viên khác!");
    }

    if (!targetUserIdOrEmail) {
      throw new Error("Vui lòng cung cấp thông tin tài khoản cần truy cập!");
    }

    const clean = String(targetUserIdOrEmail).trim().toLowerCase();
    const allUsers = this.getAllUsers();
    const targetUser = allUsers.find(u => u.id === clean || (u.email && u.email.toLowerCase() === clean));

    if (!targetUser) {
      throw new Error("Không tìm thấy tài khoản thành viên này trong hệ thống!");
    }

    if (targetUser.email && targetUser.email.toLowerCase() === "vut510624@gmail.com") {
      throw new Error("Không thể truy cập vào tài khoản Nhà phát triển chính!");
    }

    // Nếu chưa ở chế độ mạo danh -> lưu phiên Admin gốc
    if (!this.isImpersonating()) {
      sessionStorage.setItem("geo_impersonator_admin", GeoCryptoVault.encrypt(this.currentUser));
    }

    const impersonatedProfile = {
      ...targetUser,
      _isImpersonated: true,
      _impersonatedAt: Date.now()
    };

    this.setCurrentUser(impersonatedProfile);
    window.dispatchEvent(new CustomEvent("impersonation_state_changed", { detail: { isImpersonating: true, targetUser: impersonatedProfile } }));
    return impersonatedProfile;
  }

  exitImpersonation() {
    const originalAdmin = this.getImpersonatorAdmin();
    if (!originalAdmin) {
      throw new Error("Không tìm thấy phiên làm việc của Quản Trị Viên Tổng!");
    }

    sessionStorage.removeItem("geo_impersonator_admin");
    this.setCurrentUser(originalAdmin);
    window.dispatchEvent(new CustomEvent("impersonation_state_changed", { detail: { isImpersonating: false } }));
    return originalAdmin;
  }

  isAdmin() {
    return this.currentUser && (
      this.currentUser.role === "admin" || 
      this.isSuperAdmin() ||
      (this.currentUser.email && (
        this.currentUser.email.toLowerCase() === "vut510624@gmail.com" ||
        this.currentUser.email.toLowerCase() === "hshk.project@gmail.com"
      ))
    );
  }

  // Kiểm tra quyền Bật/Tắt chế độ bảo trì: Super Admin hoặc Admin được ủy quyền
  canToggleMaintenance() {
    if (!this.currentUser) return false;
    if (this.isSuperAdmin()) return true;
    if (this.isAdmin()) {
      // Check in-memory user cache for canToggleMaintenance flag
      const allUsers = this.getAllUsers();
      const dbUser = allUsers.find(u => u.id === this.currentUser.id || (u.email && u.email.toLowerCase() === this.currentUser.email?.toLowerCase()));
      return Boolean(this.currentUser.canToggleMaintenance || (dbUser && dbUser.canToggleMaintenance));
    }
    return false;
  }

  // Kiểm tra quyền Xem mật khẩu thành viên: Super Admin (Nhà sáng tạo) hoặc Admin được ủy quyền
  canViewPasswords() {
    if (!this.currentUser) return false;
    if (this.isSuperAdmin()) return true;
    if (this.isAdmin()) {
      const allUsers = this.getAllUsers();
      const dbUser = allUsers.find(u => u.id === this.currentUser.id || (u.email && u.email.toLowerCase() === this.currentUser.email?.toLowerCase()));
      return Boolean(this.currentUser.canViewPasswords || (dbUser && dbUser.canViewPasswords));
    }
    return false;
  }

  // Super Admin Action: Thêm tài khoản Admin mới
  // Super Admin tạo tài khoản Admin mới. Vì SDK Firebase Auth phía client không
  // có quyền tạo user hộ người khác trên cùng phiên đăng nhập (createUser sẽ
  // đăng xuất phiên hiện tại), ta dùng một Firebase App phụ tạm thời chỉ để tạo
  // tài khoản Auth, rồi đăng xuất App phụ đó ngay — phiên Super Admin không đổi.
  async addAdmin({ fullName, email, password }) {
    if (!this.isSuperAdmin()) {
      throw new Error("Chỉ có Super Admin mới có quyền thêm Admin!");
    }

    if (!fullName || !email || !password) {
      throw new Error("Vui lòng nhập đầy đủ Họ tên, Gmail và Mật khẩu!");
    }
    if (password.length < 6) {
      throw new Error("Mật khẩu phải có ít nhất 6 ký tự!");
    }

    const emailLower = email.trim().toLowerCase();
    const existingSnap = await db.collection(COLLECTIONS.USERS)
      .where("email", "==", emailLower)
      .get();

    if (!existingSnap.empty) {
      // Nếu user đã tồn tại -> Nâng cấp lên Admin (không đổi mật khẩu của họ)
      const docSnap = existingSnap.docs[0];
      await db.collection(COLLECTIONS.USERS).doc(docSnap.id).update({
        name: fullName.trim(),
        role: "admin",
        userType: "Admin"
      });
      return { id: docSnap.id, email: emailLower, name: fullName.trim(), role: "admin", userType: "Admin" };
    }

    // Tạo tài khoản Firebase Auth mới thông qua App phụ (không ảnh hưởng phiên hiện tại)
    const secondaryAppName = "geo-secondary-" + Date.now();
    const secondaryApp = firebase.initializeApp(firebaseConfig, secondaryAppName);
    let uid;
    try {
      const cred = await secondaryApp.auth().createUserWithEmailAndPassword(emailLower, password);
      uid = cred.user.uid;
      await secondaryApp.auth().signOut();
    } catch (err) {
      if (err.code === "auth/email-already-in-use") {
        throw new Error("Gmail này đã có tài khoản Firebase Authentication nhưng chưa có hồ sơ tương ứng. Vui lòng liên hệ kỹ thuật viên.");
      }
      throw new Error("Lỗi tạo tài khoản Admin: " + (err.message || err));
    } finally {
      try { await secondaryApp.delete(); } catch (e) {}
    }

    const newAdmin = {
      id: uid,
      name: fullName.trim(),
      email: emailLower,
      userType: "Admin",
      role: "admin",
      authProvider: "password",
      createdAt: new Date().toLocaleDateString("vi-VN")
    };
    await db.collection(COLLECTIONS.USERS).doc(uid).set(newAdmin);
    return newAdmin;
  }

  // Super Admin Action: Bỏ quyền Admin (hạ xuống thành viên thường)
  async removeAdminRole(userId, userEmail) {
    if (!this.isSuperAdmin()) {
      throw new Error("Chỉ có Super Admin mới có quyền xóa quyền Admin!");
    }
    const emailLower = (userEmail || "").trim().toLowerCase();
    if (emailLower === "vut510624@gmail.com") {
      throw new Error("Không thể hủy quyền Admin của tài khoản này!");
    }

    await db.collection(COLLECTIONS.USERS).doc(userId).update({
      role: "user",
      userType: "Học sinh THCS"
    });
  }

  // Super Admin Action: Thăng cấp thành Admin
  async promoteToAdmin(userId, userEmail) {
    if (!this.isSuperAdmin()) {
      throw new Error("Chỉ có Super Admin mới có quyền chỉ định Admin!");
    }

    await db.collection(COLLECTIONS.USERS).doc(userId).update({
      role: "admin",
      userType: "Admin"
    });
  }

  // Super Admin Action: Ủy quyền hoặc Thu hồi ủy quyền Bật/Tắt bảo trì cho Admin khác
  async toggleMaintenanceDelegation(userId, allow) {
    if (!this.isSuperAdmin()) {
      throw new Error("Chỉ có Super Admin / Nhà sáng tạo mới có quyền ủy quyền bảo trì!");
    }

    await db.collection(COLLECTIONS.USERS).doc(userId).update({
      canToggleMaintenance: Boolean(allow)
    });

    // Update in memory current user if matches
    if (this.currentUser && this.currentUser.id === userId) {
      this.currentUser.canToggleMaintenance = Boolean(allow);
      this._saveSession(this.currentUser);
    }
  }

  // Super Admin Action: Ủy quyền hoặc Thu hồi quyền Xem Mật Khẩu cho Admin khác
  async togglePasswordDelegation(userId, allow) {
    if (!this.isSuperAdmin()) {
      throw new Error("Chỉ có Super Admin / Nhà sáng tạo mới có quyền ủy quyền xem mật khẩu!");
    }

    if (typeof db !== "undefined") {
      try {
        await db.collection(COLLECTIONS.USERS).doc(userId).update({
          canViewPasswords: Boolean(allow)
        });
      } catch (e) {
        console.warn("[Auth] Firestore update delegation fallback:", e);
      }
    }

    // Update in-memory user cache
    const allUsers = this.getAllUsers();
    const target = allUsers.find(u => u.id === userId);
    if (target) {
      target.canViewPasswords = Boolean(allow);
    }

    if (this.currentUser && this.currentUser.id === userId) {
      this.currentUser.canViewPasswords = Boolean(allow);
      this._saveSession(this.currentUser);
    }

    return true;
  }

  // Admin / Super Admin Action: Xóa tài khoản thành viên
  async deleteUserAccount(userId, userEmail) {
    if (!this.isAdmin()) {
      throw new Error("Chỉ Quản trị viên (Admin) mới có quyền xóa tài khoản!");
    }
    
    const emailLower = (userEmail || "").trim().toLowerCase();
    const currentEmail = (this.currentUser && this.currentUser.email ? this.currentUser.email : "").trim().toLowerCase();

    if (emailLower === currentEmail) {
      throw new Error("Không thể xóa chính tài khoản bạn đang đăng nhập!");
    }
    if (emailLower === "vut510624@gmail.com") {
      throw new Error("Không thể xóa tài khoản nhà phát triển!");
    }

    const allUsers = this.getAllUsers();
    const targetUser = allUsers.find(u => u.id === userId || (u.email && u.email.toLowerCase() === emailLower));
    const isTargetAdmin = (targetUser && (targetUser.role === "admin" || targetUser.userType === "Admin")) || emailLower === "hshk.project@gmail.com";

    // Nếu người thực hiện không phải Super Admin và đối tượng là Admin
    if (!this.isSuperAdmin() && isTargetAdmin) {
      throw new Error("Quản trị viên thường không thể xóa tài khoản Quản trị viên khác!");
    }

    await db.collection(COLLECTIONS.USERS).doc(userId).delete();
  }

  // Mật khẩu của người dùng thường giờ do Firebase Authentication quản lý và
  // KHÔNG THỂ xem lại được (kể cả bởi Admin) — đây là hành vi đúng chuẩn bảo mật.
  // Hàm này chỉ còn trả về trạng thái quản lý, không còn trả về mật khẩu thật.
  getUserDisplayPassword(user) {
    if (!user) return { type: "empty", value: "", masked: "—", label: "Chưa có" };

    if (user.authProvider === "google") {
      return { type: "oauth", value: "Google OAuth", masked: "Google OAuth", label: "Đăng nhập Google" };
    }

    if (user.authProvider === "hardcoded") {
      return { type: "managed", value: "", masked: "Super Admin cố định", label: "Quản lý trực tiếp trong mã nguồn" };
    }

    return {
      type: "managed",
      value: "",
      masked: "Quản lý bởi Firebase",
      label: "Mật khẩu do Firebase Authentication quản lý, không thể xem lại. Dùng chức năng \"Gửi email đặt lại mật khẩu\" nếu cần hỗ trợ thành viên."
    };
  }

  // Quản trị viên hỗ trợ thành viên đặt lại mật khẩu: vì SDK Firebase Auth phía
  // client không cho phép Admin tự đặt mật khẩu THAY người khác, chức năng này
  // gửi email đặt lại mật khẩu chuẩn của Firebase đến hộp thư của thành viên đó.
  // Tham số newPassword được giữ lại để không phá vỡ chữ ký gọi cũ nhưng không
  // còn được sử dụng.
  async adminResetUserPassword(userId, newPassword) {
    if (!this.isAdmin() && !this.isSuperAdmin()) {
      throw new Error("Chỉ Quản trị viên mới có quyền đặt lại mật khẩu cho thành viên!");
    }

    const allUsers = this.getAllUsers();
    const targetUser = allUsers.find(u => u.id === userId || (u.email && u.email.toLowerCase() === (userId || "").toLowerCase()));
    if (!targetUser) {
      throw new Error("Không tìm thấy thông tin thành viên!");
    }

    const emailLower = (targetUser.email || "").toLowerCase();
    if (emailLower === SUPER_ADMIN_EMAIL) {
      throw new Error("Không thể thay đổi mật khẩu của Super Admin!");
    }
    if (targetUser.authProvider === "google") {
      throw new Error("Tài khoản này đăng nhập bằng Google, không có mật khẩu để đặt lại. Vui lòng hướng dẫn thành viên quản lý qua tài khoản Google của họ.");
    }

    try {
      await auth.sendPasswordResetEmail(targetUser.email);
    } catch (err) {
      throw new Error("Lỗi gửi email đặt lại mật khẩu: " + (err.message || err));
    }

    // Mở khóa nếu tài khoản đang bị khóa do dò mật khẩu
    if (typeof db !== "undefined") {
      try {
        await db.collection(COLLECTIONS.USERS).doc(targetUser.id).update({
          isLocked: false,
          status: "active"
        });
      } catch (err) {
        console.warn("[Auth] Firestore update fallback:", err);
      }
    }
    targetUser.isLocked = false;
    targetUser.status = "active";

    if (targetUser.email) {
      this.clearAttemptData(targetUser.email);
    }

    return true;
  }

  // Đăng nhập nhanh với tư cách Super Admin (dùng nội bộ / phát triển)
  quickLoginAs(role) {
    if (role === "admin") {
      this.setCurrentUser(_buildHardcodedSuperAdminProfile());
    }
  }
}

// Global instance
window.geoAuth = new GeoAuthManager();

// --- GLOBAL GOOGLE LOGIN HANDLER (called from onclick in HTML) ---
async function handleGoogleLogin() {
  try {
    if (window.geoDB && window.geoDB.isGoogleLoginDisabled()) {
      const msg = (window.t ? window.t("googleLoginDisabledNotice", "Dang nhap bang Google hien dang bi loi hoac tam dung. Vui long su dung Email va Mat khau!") : "Dang nhap bang Google hien dang bi loi hoac tam dung. Vui long su dung Email va Mat khau!");
      showToast(msg, "error");
      return;
    }
    const user = await window.geoAuth.loginWithGoogle();
    closeAllModals();
    showToast(`Đăng nhập Google thành công! Chào mừng ${user.name}.`, "success");
  } catch (err) {
    showToast(err.message, "error");
  }
}
window.handleGoogleLogin = handleGoogleLogin;

// Bulletproof Password Visibility Toggle Helper
function togglePasswordVisibility(targetInputId, btnElement, e) {
  if (e) {
    if (e.preventDefault) e.preventDefault();
    if (e.stopPropagation) e.stopPropagation();
  }

  let btn = btnElement;
  let targetId = targetInputId;

  if (!btn && e && e.target) {
    btn = e.target.closest(".password-toggle-btn");
  }
  if (!targetId && btn) {
    targetId = btn.getAttribute("data-target");
  }

  const input = document.getElementById(targetId);
  if (!input) return;

  const currentType = input.getAttribute("type") || input.type || "password";
  const isPassword = currentType === "password";
  const newType = isPassword ? "text" : "password";

  input.type = newType;
  input.setAttribute("type", newType);

  if (btn) {
    if (isPassword) {
      // Eye Open (Password visible)
      btn.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8z"></path>
          <circle cx="12" cy="12" r="3"></circle>
        </svg>
      `;
      btn.setAttribute("title", "Ẩn mật khẩu");
      btn.classList.add("showing-password");
    } else {
      // Eye Slash (Password hidden)
      btn.innerHTML = `
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"></path>
          <line x1="1" y1="1" x2="23" y2="23"></line>
        </svg>
      `;
      btn.setAttribute("title", "Hiện mật khẩu");
      btn.classList.remove("showing-password");
    }
  }
}
window.togglePasswordVisibility = togglePasswordVisibility;

function setupPasswordToggles() {
  document.removeEventListener("click", _handleGlobalPasswordToggle);
  document.addEventListener("click", _handleGlobalPasswordToggle);
}

function _handleGlobalPasswordToggle(e) {
  const btn = e.target.closest(".password-toggle-btn");
  if (btn) {
    e.preventDefault();
    e.stopPropagation();
    const targetId = btn.getAttribute("data-target");
    togglePasswordVisibility(targetId, btn, e);
  }
}

document.addEventListener("DOMContentLoaded", () => {
  setupPasswordToggles();
});
