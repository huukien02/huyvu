const fs = require('fs');
const path = require('path');

const partialsDir = path.join(__dirname, '../src/partials');
const rootDir = path.join(__dirname, '..');

// Shared chrome included on every page (in this order), plus exactly ONE
// tab-content partial in between. Each output page is a full, independent
// HTML document — there is no more single index.html gộp tất cả các tab.
const SHARED_HEAD = ['01_head.html', '02_auth_gate.html', '03_header_nav.html'];
const SHARED_TAIL = ['10_modals.html', '12_scripts.html'];

// Trang (output file) -> partial nội dung riêng của trang đó
const PAGES = {
  'index.html': '04_tab_home.html',       // Trang chủ
  'tai-lieu.html': '05_tab_docs.html',     // Kho tài liệu
  'luu.html': '06_tab_saved.html',         // Tài liệu đã lưu
  'lien-he.html': '07_tab_contact.html',   // Liên hệ & Confession
  'ai-chat.html': '08_tab_ai_chat.html',   // Hỏi Trợ Lí AI
  'quan-tri.html': '09_tab_admin.html',    // Quản trị Admin
  'dia-cau-3d.html': '11_section_globe.html', // Địa Cầu 3D
};

function readPartial(name) {
  return fs.readFileSync(path.join(partialsDir, name), 'utf-8');
}

console.log('Building pages from partials:');
let totalLines = 0;

for (const [outputName, contentPartial] of Object.entries(PAGES)) {
  const partialList = [...SHARED_HEAD, contentPartial, ...SHARED_TAIL];
  console.log(`\n${outputName}:`);
  const parts = partialList.map(f => {
    console.log(`  + ${f}`);
    return readPartial(f);
  });

  const assembled = parts.join('\n');
  fs.writeFileSync(path.join(rootDir, outputName), assembled, 'utf-8');
  totalLines += assembled.split('\n').length;
}

console.log(`\nSuccessfully assembled ${Object.keys(PAGES).length} pages from partials (${totalLines} total lines).`);
