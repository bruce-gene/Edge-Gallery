/**
 * ==========================================================================================
 * R2 文件管理 Worker - 最终功能版 (已添加上传文件夹功能)
 * 
 * 功能:
 * 1. 密码登录界面，使用安全的 HttpOnly Cookie 进行会话管理。
 * 2. 文件夹/文件层级浏览。
 * 3. 多文件上传。
 * 4. [新增] 文件夹上传 (保留目录结构)。
 * 5. 文件删除。
 * 6. 图片文件在线预览。
 * 
 * 配置要求: (与之前完全相同，无需更改)
 * 在 Worker 的 "设置" -> "变量" -> "Worker 密钥" 中设置以下两个 Secrets:
 * 1. ACCESS_KEY: 您的登录密码
 * 2. JWT_SECRET: 用于签发会话令牌的密钥 (长且随机的字符串)
 * 
 * 在 Worker 的 "设置" -> "变量" -> "R2 存储桶绑定" 中设置:
 * 1. 变量名称: MY_BUCKET, R2 存储桶: 选择您的 R2 存储桶
 * ==========================================================================================
 */

const COOKIE_NAME = 'r2-manager-session';

export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const R2_BUCKET = env.MY_BUCKET;

        if (request.method === 'POST' && url.pathname === '/api/login') {
            try {
                const { password } = await request.json();
                if (password === env.ACCESS_KEY) {
                    const token = await createJwt(env.JWT_SECRET);
                    const headers = new Headers();
                    headers.set('Set-Cookie', `${COOKIE_NAME}=${token}; HttpOnly; Secure; Path=/; SameSite=Strict; Max-Age=86400`);
                    return new Response(JSON.stringify({ success: true }), { headers });
                }
            } catch (e) { /* no-op */ }
            return new Response('Unauthorized', { status: 401 });
        }

        const isAuthenticated = await verifyJwt(env.JWT_SECRET, request.headers.get('Cookie'));
        if (!isAuthenticated) {
            if (url.pathname.startsWith('/api/') || url.pathname.startsWith('/r2/')) {
                return new Response('Unauthorized', { status: 401 });
            }
            return new Response(renderHtml(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
        }

        if (url.pathname.startsWith('/api/')) {
            return handleApiRequest(request, R2_BUCKET);
        }

        if (url.pathname.startsWith('/r2/')) {
            return handleR2Proxy(request, R2_BUCKET);
        }

        return new Response(renderHtml(), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
    },
};

async function handleApiRequest(request, bucket) {
    const url = new URL(request.url);

    // ★★★ 后端修改点: 优化上传接口以支持文件夹上传 ★★★
    // 现在接收 key 和 file，由前端计算好完整路径
    if (request.method === 'POST' && url.pathname === '/api/upload') {
        const form = await request.formData();
        const key = form.get('key');
        const file = form.get('file');
        if (!key || !file) {
            return new Response('Missing key or file in form data', { status: 400 });
        }
        await bucket.put(key, file.stream(), { httpMetadata: { contentType: file.type || 'application/octet-stream' } });
        return new Response('OK');
    }

    if (request.method === 'POST' && url.pathname === '/api/delete') {
        const { key } = await request.json();
        if (!key) return new Response('No key!', { status: 400 });
        await bucket.delete(key);
        return new Response('OK');
    }

    if (request.method === 'POST' && url.pathname === '/api/mkdir') {
        const { folder } = await request.json();
        if (!folder) return new Response('No folder!', { status: 400 });
        const key = folder.replace(/^\/|\/$/g, '') + '/.r2-folder-placeholder';
        await bucket.put(key, new Uint8Array([0]));
        return new Response('OK');
    }

    if (request.method === 'GET' && url.pathname === '/api/list') {
        let prefix = url.searchParams.get('folder') || '';
        if (prefix && !prefix.endsWith('/')) prefix += '/';
        const list = await bucket.list({ prefix, delimiter: '/' });
        const folders = list.delimitedPrefixes.map(s => s.slice(prefix.length).replace(/\/$/, ''));
        const files = list.objects
            .filter(o => !o.key.endsWith('/.r2-folder-placeholder'))
            .map(o => ({
                key: o.key,
                name: o.key.slice(prefix.length),
                size: o.size,
                last_modified: o.uploaded,
                url: '/r2/' + encodeURIComponent(o.key),
            }));
        return Response.json({ folders, files });
    }
    return new Response('API Not Found', { status: 404 });
}

async function handleR2Proxy(request, bucket) {
    const url = new URL(request.url);
    const key = decodeURIComponent(url.pathname.slice(4));
    const obj = await bucket.get(key);
    if (!obj) return new Response('Not found', { status: 404 });
    const headers = new Headers();
    obj.writeHttpMetadata(headers);
    headers.set('etag', obj.httpEtag);
    headers.set('Cache-Control', 'public, max-age=86400');
    return new Response(obj.body, { headers });
}

// --- JWT and Crypto Helpers (No changes) ---
async function createJwt(secret) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const payload = { exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) };
    const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
    const data = base64UrlEncode(JSON.stringify(header)) + '.' + base64UrlEncode(JSON.stringify(payload));
    const signature = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
    return data + '.' + base64UrlEncode(new Uint8Array(signature));
}
async function verifyJwt(secret, cookieHeader) {
    if (!cookieHeader) return false;
    const cookie = cookieHeader.split(';').find(c => c.trim().startsWith(`${COOKIE_NAME}=`));
    if (!cookie) return false;
    const token = cookie.split('=')[1];
    const parts = token.split('.');
    if (parts.length !== 3) return false;
    try {
        const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
        const valid = await crypto.subtle.verify('HMAC', key, base64UrlDecode(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
        if (!valid) return false;
        const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));
        return payload.exp > Math.floor(Date.now() / 1000);
    } catch (e) { return false; }
}
function base64UrlEncode(data) {
    return btoa(data instanceof Uint8Array ? String.fromCharCode(...data) : data)
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) { str += '='; }
    const decoded = atob(str);
    const uint8Array = new Uint8Array(decoded.length);
    for (let i = 0; i < decoded.length; i++) { uint8Array[i] = decoded.charCodeAt(i); }
    return uint8Array;
}


// --- Frontend HTML, CSS, JS ---
function renderHtml() {
    return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>R2 文件管理</title>
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <style>
    :root{--primary-color:#0078d4;--bg-light:#f8f9fa;--bg-white:#fff;--border-color:#dee2e6;--shadow:0 6px 24px rgba(0,0,0,0.06);}
    body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;background:var(--bg-light);}
    .container{max-width:960px;margin:40px auto;padding:24px 20px;background:var(--bg-white);border-radius:12px;box-shadow:var(--shadow);}
    h1{font-size:1.8em;color:var(--primary-color);margin:0 0 20px 0;}
    #breadcrumb{margin-bottom:24px;}
    #breadcrumb a{color:var(--primary-color);text-decoration:none;font-weight:600;}
    #breadcrumb span{color:#888;margin:0 6px;}
    .op-bar{display:flex;flex-wrap:wrap;gap:12px;align-items:center;margin-bottom:24px;}
    .op-bar input[type="text"]{padding:8px 12px;border-radius:6px;border:1px solid var(--border-color);font-size:1em;}
    .op-bar button,.upload-btn{padding:8px 16px;background:var(--primary-color);color:var(--bg-white);border:none;border-radius:6px;cursor:pointer;font-size:1em;transition:opacity .2s;}
    .op-bar button:hover,.upload-btn:hover{opacity:.9;}
    .op-bar .btn-secondary{background:#6c757d;}
    .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:20px;}
    .grid-item{background:#fdfdfd;border:1px solid var(--border-color);border-radius:8px;padding:15px;text-align:center;cursor:pointer;transition:transform .2s,box-shadow .2s;position:relative;word-break:break-word;}
    .grid-item:hover{transform:translateY(-4px);box-shadow:0 4px 12px rgba(0,0,0,0.08);}
    .grid-item svg{width:48px;height:48px;margin-bottom:10px;color:#fdd835;}
    .grid-item img{width:100%;height:90px;object-fit:cover;border-radius:4px;margin-bottom:10px;}
    .grid-item .file-icon{font-size:3em;line-height:90px;height:90px;color:#aeaeae;}
    .delete-btn{position:absolute;top:5px;right:5px;background:rgba(220,53,69,.8);color:white;border:none;border-radius:50%;width:24px;height:24px;cursor:pointer;display:flex;align-items:center;justify-content:center;opacity:0;transition:opacity .2s;font-size:1.2em;}
    .grid-item:hover .delete-btn{opacity:1;}
    input[type="file"]{display:none;}
    #loading,#status{text-align:center;padding:40px;font-size:1.2em;color:#6c757d;}
    #password-cover{position:fixed;z-index:100;top:0;left:0;width:100vw;height:100vh;background:rgba(255,255,255,.9);backdrop-filter:blur(5px);display:flex;align-items:center;justify-content:center;}
    #password-box{background:var(--bg-white);padding:30px 40px;border-radius:12px;box-shadow:var(--shadow);text-align:center;}
    #password-box h2{margin:0 0 20px 0;font-weight:600;}
    #password-box input{font-size:1.1em;padding:10px 14px;border-radius:6px;border:1px solid var(--border-color);width:250px;margin-bottom:15px;}
    #password-error{color:#dc3545;height:20px;margin-bottom:10px;}
    @media (max-width:600px){.container{margin:10px;padding:15px;}.grid{grid-template-columns:repeat(auto-fill,minmax(120px,1fr));}}
  </style>
</head>
<body>
  <div id="password-cover">
    <div id="password-box">
      <h2>请输入访问密码</h2>
      <div id="password-error"></div>
      <input id="password-input" type="password" placeholder="访问密码">
      <button id="password-btn">登录</button>
    </div>
  </div>
  <div id="app-container" style="display:none;">
    <div class="container">
      <h1>R2 文件管理</h1>
      <div id="breadcrumb"></div>
      <div class="op-bar">
        <!-- ★★★ HTML修改点: 增加上传文件夹按钮和对应的隐藏input ★★★ -->
        <label for="file-input" class="upload-btn">上传文件</label>
        <button type="button" id="upload-folder-btn" class="upload-btn">上传文件夹</button>
        <input type="file" id="file-input" multiple>
        <input type="file" id="folder-input" webkitdirectory style="display:none;">

        <form id="mkdir-form" style="display:inline-flex;gap:10px;">
          <input type="text" id="mkdir-input" placeholder="新建文件夹名">
          <button type="submit">创建</button>
        </form>
        <button onclick="gotoParent()" class="btn-secondary" style="margin-left:auto;">返回上级</button>
      </div>
      <div id="status"></div>
      <div id="loading">正在加载...</div>
      <div class="grid" id="folders-grid"></div>
      <hr style="border:none;border-top:1px solid #eee;margin:20px 0;">
      <div class="grid" id="files-grid"></div>
    </div>
  </div>
<script>
let currentFolder = '';

const appEl = document.getElementById('app-container');
const passwordCoverEl = document.getElementById('password-cover');
const passwordInput = document.getElementById('password-input');
const passwordBtn = document.getElementById('password-btn');
const passwordError = document.getElementById('password-error');

const foldersEl = document.getElementById('folders-grid');
const filesEl = document.getElementById('files-grid');
const breadcrumbEl = document.getElementById('breadcrumb');
const loadingEl = document.getElementById('loading');
const statusEl = document.getElementById('status');

// ★★★ JS修改点: 增加对新按钮和新input的引用 ★★★
const fileInput = document.getElementById('file-input');
const folderInput = document.getElementById('folder-input');
const uploadFolderBtn = document.getElementById('upload-folder-btn');

async function checkLogin() {
  const res = await fetch('/api/list');
  if (res.status === 401) {
    passwordCoverEl.style.display = 'flex';
    appEl.style.display = 'none';
  } else {
    passwordCoverEl.style.display = 'none';
    appEl.style.display = 'block';
    loadList('');
  }
}

async function handleLogin() {
  const password = passwordInput.value;
  if (!password) { passwordError.textContent = '密码不能为空'; return; }
  passwordError.textContent = '';
  passwordBtn.disabled = true;
  passwordBtn.textContent = '登录中...';
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password })
    });
    if (res.ok) {
      passwordCoverEl.style.display = 'none';
      appEl.style.display = 'block';
      loadList('');
    } else {
      passwordError.textContent = '密码错误';
    }
  } catch(e) {
    passwordError.textContent = '发生网络错误';
  } finally {
    passwordBtn.disabled = false;
    passwordBtn.textContent = '登录';
    passwordInput.value = '';
  }
}

passwordBtn.addEventListener('click', handleLogin);
passwordInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') handleLogin(); });

async function loadList(folder = '') {
  currentFolder = folder;
  loadingEl.style.display = 'block';
  statusEl.textContent = '';
  foldersEl.innerHTML = '';
  filesEl.innerHTML = '';

  const parts = folder.replace(/^\\/|\\/$/g, '').split('/').filter(p => p);
  let path = '';
  let crumbs = \`<a href="#" onclick="loadList('');return false;">根目录</a>\`;
  for (const part of parts) {
    path += part + '/';
    crumbs += \`<span>/</span><a href="#" onclick="loadList('\${path}');return false;">\${part}</a>\`;
  }
  breadcrumbEl.innerHTML = crumbs;

  try {
    const res = await fetch(\`/api/list?folder=\${encodeURIComponent(folder)}\`);
    if (!res.ok) throw new Error('Failed to fetch list');
    const data = await res.json();
    
    if (data.folders.length === 0 && data.files.length === 0) { statusEl.textContent = '此文件夹为空'; }

    foldersEl.innerHTML = data.folders.map(name => \`
      <div class="grid-item" onclick="loadList('\${(folder ? folder + '/' : '') + name}')">
        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path fill="currentColor" d="M10 4H4c-1.11 0-2 .89-2 2v12c0 1.1.9 2 2 2h16c1.1 0 2-.9 2-2V8c0-1.11-.89-2-2-2h-8l-2-2z"/></svg>
        <div>\${name}</div>
      </div>\`).join('');

    filesEl.innerHTML = data.files.map(f => {
      const isImage = /\\.(jpe?g|png|gif|webp|svg|ico)$/i.test(f.name);
      const thumb = isImage ? \`<img src="\${f.url}" alt="\${f.name}" loading="lazy">\` : \`<div class="file-icon">📄</div>\`;
      return \`<div class="grid-item">
          <button class="delete-btn" title="删除" onclick="deleteFile('\${f.key}');event.stopPropagation();">×</button>
          <a href="\${f.url}" target="_blank" onclick="event.stopPropagation()">\${thumb}</a>
          <div title="\${f.name}">\${f.name}</div>
        </div>\`; }).join('');
  } catch (err) {
    statusEl.textContent = '加载失败，请刷新页面。';
  } finally {
    loadingEl.style.display = 'none';
  }
}

function gotoParent() {
  if (!currentFolder) return;
  const arr = currentFolder.replace(/^\\/|\\/$/g, '').split('/');
  arr.pop();
  loadList(arr.join('/'));
}

async function deleteFile(key) {
  if (!confirm(\`确定要删除文件: \${key} ?\`)) return;
  await fetch('/api/delete', { method: 'POST', body: JSON.stringify({ key }), headers: { 'Content-Type': 'application/json' } });
  loadList(currentFolder);
}

// ★★★ JS修改点: 创建一个通用的上传处理器 ★★★
async function handleUpload(files) {
    if (!files || files.length === 0) return;

    statusEl.textContent = \`准备上传 \${files.length} 个文件...\`;
    let uploadedCount = 0;
    const totalFiles = files.length;

    for (const file of files) {
        // file.webkitRelativePath 存在时，表示是文件夹上传，使用它来构建路径
        const pathSuffix = file.webkitRelativePath || file.name;
        const key = ((currentFolder ? currentFolder.replace(/\\/?$/, '/') : '') + pathSuffix).replace(/\\/\\//g, '/');

        statusEl.textContent = \`(\${uploadedCount + 1}/\${totalFiles}) 正在上传: \${file.name}...\`;
        
        const fd = new FormData();
        fd.append('key', key);
        fd.append('file', file);
        
        try {
            const response = await fetch('/api/upload', { method: 'POST', body: fd });
            if (!response.ok) {
                throw new Error(\`Server responded with \${response.status}\`);
            }
            uploadedCount++;
        } catch (error) {
            statusEl.textContent = \`上传 \${file.name} 失败: \${error.message}。已停止。\`;
            return; // 遇到错误时停止
        }
    }
    statusEl.textContent = \`成功上传 \${uploadedCount} / \${totalFiles} 个文件！\`;
    setTimeout(() => loadList(currentFolder), 1500);
}

// ★★★ JS修改点: 将事件监听器指向新的通用处理器 ★★★
fileInput.onchange = (e) => handleUpload(e.target.files);
folderInput.onchange = (e) => handleUpload(e.target.files);
uploadFolderBtn.onclick = () => folderInput.click();


document.getElementById('mkdir-form').onsubmit = async function(e) {
  e.preventDefault();
  const input = document.getElementById('mkdir-input');
  const folderName = input.value.trim();
  if (!folderName) return;
  const fullPath = (currentFolder ? currentFolder.replace(/\\/?$/, '/') : '') + folderName;
  await fetch('/api/mkdir', { 
      method: 'POST', 
      body: JSON.stringify({ folder: fullPath }), 
      headers: { 'Content-Type': 'application/json' } 
  });
  input.value = '';
  loadList(currentFolder);
}

window.loadList = loadList;
window.deleteFile = deleteFile;
window.gotoParent = gotoParent;

checkLogin();
</script>
</body>
</html>
`;
}
