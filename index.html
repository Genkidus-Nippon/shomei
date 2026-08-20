// ============================================================
//  使い切り PDF 順次署名ツール
//  - PDFをアップロード
//  - 署名者を順番に登録
//  - 1人目にメール送信 → 署名 → 次の人へ … と順繰り
//  - 誰がいつ署名したか記録し、最後に署名済みPDFを生成
// ============================================================

import express from "express";
import multer from "multer";
import nodemailer from "nodemailer";
import { PDFDocument, rgb } from "pdf-lib";
import fontkit from "@pdf-lib/fontkit";
import fs from "fs";
import path from "path";
import crypto from "crypto";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ---------- 設定 ----------
const PORT = process.env.PORT || 3000;
// 署名リンクに使う公開URL。ローカルなら http://localhost:3000
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// メール設定（環境変数で渡す。未設定ならコンソールに擬似送信）
const SMTP = {
  host: process.env.SMTP_HOST || "",
  port: Number(process.env.SMTP_PORT || 587),
  user: process.env.SMTP_USER || "",
  pass: process.env.SMTP_PASS || "",
  from: process.env.SMTP_FROM || process.env.SMTP_USER || "no-reply@example.com",
};

// ---------- 保存ディレクトリ ----------
const DATA_DIR = path.join(__dirname, "data");
const UPLOAD_DIR = path.join(DATA_DIR, "uploads");
const SIGNED_DIR = path.join(DATA_DIR, "signed");
const DB_PATH = path.join(DATA_DIR, "db.json");
for (const d of [DATA_DIR, UPLOAD_DIR, SIGNED_DIR]) {
  if (!fs.existsSync(d)) fs.mkdirSync(d, { recursive: true });
}

// ---------- 簡易DB（JSONファイル） ----------
function loadDB() {
  if (!fs.existsSync(DB_PATH)) return { envelopes: {} };
  try {
    return JSON.parse(fs.readFileSync(DB_PATH, "utf8"));
  } catch {
    return { envelopes: {} };
  }
}
function saveDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
}

// ---------- メール送信 ----------
let transporter = null;
if (SMTP.host && SMTP.user) {
  transporter = nodemailer.createTransport({
    host: SMTP.host,
    port: SMTP.port,
    secure: SMTP.port === 465,
    auth: { user: SMTP.user, pass: SMTP.pass },
  });
}

async function sendMail(to, subject, html) {
  if (!transporter) {
    // SMTP未設定時はコンソールに出力（動作確認用）
    console.log("\n===== [擬似メール送信] =====");
    console.log("To:", to);
    console.log("Subject:", subject);
    console.log("Body(HTML):", html.replace(/<[^>]+>/g, "").trim());
    console.log("============================\n");
    return;
  }
  await transporter.sendMail({ from: SMTP.from, to, subject, html });
  console.log(`メール送信済み → ${to}`);
}

// ---------- ユーティリティ ----------
function newId() {
  return crypto.randomBytes(8).toString("hex");
}
function sha256(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}
function nowISO() {
  return new Date().toISOString();
}

// 次の未署名者にメールを送る
async function notifyNextSigner(env) {
  const next = env.signers.find((s) => s.status === "pending");
  if (!next) return false;
  next.status = "sent";
  next.sentAt = nowISO();
  const link = `${BASE_URL}/sign/${env.id}/${next.token}`;
  const html = `
    <p>${escapeHtml(next.name)} 様</p>
    <p>「${escapeHtml(env.title)}」への署名依頼が届いています。</p>
    <p>下記リンクから内容をご確認のうえ、署名をお願いいたします。</p>
    <p><a href="${link}">${link}</a></p>
    <hr>
    <p style="color:#888;font-size:12px">署名順: ${next.order + 1} / ${env.signers.length}</p>
  `;
  await sendMail(next.email, `【署名依頼】${env.title}`, html);
  return true;
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ---------- Express ----------
const app = express();
app.use(express.json({ limit: "20mb" }));
app.use(express.urlencoded({ extended: true }));

const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOAD_DIR,
    filename: (req, file, cb) => cb(null, `${newId()}.pdf`),
  }),
  limits: { fileSize: 25 * 1024 * 1024 },
});

// トップページ（作成フォーム）
app.get("/", (req, res) => {
  res.send(pageCreate());
});

// エンベロープ作成（PDF＋署名者登録）
app.post("/create", upload.single("pdf"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).send("PDFファイルが必要です");
    const title = (req.body.title || "無題の書類").trim();

    // 署名者リストをパース（name1,email1 / name2,email2 ... の形）
    const names = [].concat(req.body.name || []);
    const emails = [].concat(req.body.email || []);
    const signers = [];
    for (let i = 0; i < emails.length; i++) {
      const email = (emails[i] || "").trim();
      const name = (names[i] || "").trim() || email;
      if (!email) continue;
      signers.push({
        order: signers.length,
        name,
        email,
        token: newId(),
        status: "pending", // pending → sent → signed
        sentAt: null,
        signedAt: null,
        signatureImage: null, // dataURL
        ip: null,
      });
    }
    if (signers.length === 0)
      return res.status(400).send("署名者を1人以上登録してください");

    const pdfBytes = fs.readFileSync(req.file.path);
    const db = loadDB();
    const id = newId();
    db.envelopes[id] = {
      id,
      title,
      originalFile: req.file.filename,
      originalHash: sha256(pdfBytes), // 改ざん検知用の元PDFハッシュ
      createdAt: nowISO(),
      status: "in_progress", // in_progress → completed
      signers,
      auditLog: [
        { time: nowISO(), event: "created", detail: `書類「${title}」を作成、署名者${signers.length}名` },
      ],
    };
    saveDB(db);

    // 1人目に送信
    const env = db.envelopes[id];
    env.auditLog.push({ time: nowISO(), event: "send", detail: `1人目 ${env.signers[0].email} に送信` });
    await notifyNextSigner(env);
    saveDB(db);

    res.send(pageCreated(env));
  } catch (e) {
    console.error(e);
    res.status(500).send("エラー: " + e.message);
  }
});

// 署名ページ表示
app.get("/sign/:envId/:token", (req, res) => {
  const db = loadDB();
  const env = db.envelopes[req.params.envId];
  if (!env) return res.status(404).send("書類が見つかりません");
  const signer = env.signers.find((s) => s.token === req.params.token);
  if (!signer) return res.status(404).send("署名者が見つかりません");

  if (signer.status === "signed")
    return res.send(pageMessage("すでに署名済みです", "この書類にはすでに署名いただいています。ありがとうございました。"));

  // 順番チェック: 自分より前の人が全員署名済みか
  const myTurn = env.signers
    .filter((s) => s.order < signer.order)
    .every((s) => s.status === "signed");
  if (!myTurn)
    return res.send(pageMessage("順番待ちです", "前の署名者の署名がまだ完了していません。順番が来るとメールが届きますので、それまでお待ちください。"));

  res.send(pageSign(env, signer));
});

// PDFプレビュー取得
app.get("/pdf/:envId/:token", (req, res) => {
  const db = loadDB();
  const env = db.envelopes[req.params.envId];
  if (!env) return res.status(404).end();
  const signer = env.signers.find((s) => s.token === req.params.token);
  if (!signer) return res.status(404).end();
  const p = path.join(UPLOAD_DIR, env.originalFile);
  res.setHeader("Content-Type", "application/pdf");
  fs.createReadStream(p).pipe(res);
});

// 署名を送信
app.post("/sign/:envId/:token", async (req, res) => {
  try {
    const db = loadDB();
    const env = db.envelopes[req.params.envId];
    if (!env) return res.status(404).json({ error: "書類が見つかりません" });
    const signer = env.signers.find((s) => s.token === req.params.token);
    if (!signer) return res.status(404).json({ error: "署名者が見つかりません" });
    if (signer.status === "signed")
      return res.status(400).json({ error: "すでに署名済みです" });

    const myTurn = env.signers
      .filter((s) => s.order < signer.order)
      .every((s) => s.status === "signed");
    if (!myTurn) return res.status(400).json({ error: "まだ順番ではありません" });

    const { signatureImage } = req.body; // dataURL (png)
    if (!signatureImage || !signatureImage.startsWith("data:image/"))
      return res.status(400).json({ error: "署名画像がありません" });

    signer.status = "signed";
    signer.signedAt = nowISO();
    signer.signatureImage = signatureImage;
    signer.ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
    env.auditLog.push({
      time: signer.signedAt,
      event: "signed",
      detail: `${signer.name} <${signer.email}> が署名 (IP: ${signer.ip})`,
    });

    // 次の人へ or 完了処理
    const hasNext = env.signers.some((s) => s.status === "pending");
    if (hasNext) {
      await notifyNextSigner(env);
      env.auditLog.push({ time: nowISO(), event: "send", detail: "次の署名者に送信" });
    } else {
      env.status = "completed";
      env.completedAt = nowISO();
      await finalizePDF(env); // 署名焼き込み＋証明書ページ
      env.auditLog.push({ time: nowISO(), event: "completed", detail: "全員署名完了、署名済みPDFを生成" });
    }
    saveDB(db);
    res.json({ ok: true, completed: env.status === "completed" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// 管理画面（進捗確認）
app.get("/status/:envId", (req, res) => {
  const db = loadDB();
  const env = db.envelopes[req.params.envId];
  if (!env) return res.status(404).send("書類が見つかりません");
  res.send(pageStatus(env));
});

// 署名済みPDFダウンロード
app.get("/download/:envId", (req, res) => {
  const db = loadDB();
  const env = db.envelopes[req.params.envId];
  if (!env) return res.status(404).send("書類が見つかりません");
  const p = path.join(SIGNED_DIR, `${env.id}.pdf`);
  if (!fs.existsSync(p)) return res.status(404).send("署名済みPDFはまだありません（全員の署名完了後に生成されます）");
  res.download(p, `${env.title}_signed.pdf`);
});

// ---------- 署名済みPDFの生成 ----------
const FONT_PATH = path.join(__dirname, "fonts", "JapaneseGothic.ttf");
const FONT_BYTES = fs.existsSync(FONT_PATH) ? fs.readFileSync(FONT_PATH) : null;

async function finalizePDF(env) {
  const srcBytes = fs.readFileSync(path.join(UPLOAD_DIR, env.originalFile));
  const pdfDoc = await PDFDocument.load(srcBytes);
  pdfDoc.registerFontkit(fontkit);
  // 日本語対応フォントを埋め込む（サブセットでサイズ削減）
  const font = FONT_BYTES
    ? await pdfDoc.embedFont(FONT_BYTES, { subset: true })
    : await pdfDoc.embedFont((await import("pdf-lib")).StandardFonts.Helvetica);

  // 最終ページの下部に署名スタンプ（小さく）を並べる
  const pages = pdfDoc.getPages();
  const last = pages[pages.length - 1];
  const { width } = last.getSize();

  // 各署名者の署名画像を最終ページ下部に配置
  let x = 40;
  const y = 40;
  for (const s of env.signers) {
    if (s.signatureImage) {
      try {
        const png = await pdfDoc.embedPng(s.signatureImage);
        const w = 120;
        const h = (png.height / png.width) * w;
        last.drawImage(png, { x, y, width: w, height: h });
        last.drawText(`${s.name}`, { x, y: y - 10, size: 7, font, color: rgb(0.3, 0.3, 0.3) });
        x += w + 20;
        if (x > width - 140) x = 40;
      } catch {}
    }
  }

  // 署名証明書ページを追加（監査ログ）
  const certPage = pdfDoc.addPage();
  const { height: ch } = certPage.getSize();
  let cy = ch - 50;
  const line = (text, size = 10, color = rgb(0, 0, 0)) => {
    certPage.drawText(text, { x: 40, y: cy, size, font, color });
    cy -= size + 6;
  };
  line("Signature Certificate / 署名証明書", 16);
  cy -= 6;
  line(`Document Title: ${env.title}`, 10);
  line(`Envelope ID: ${env.id}`, 9, rgb(0.4, 0.4, 0.4));
  line(`Original PDF SHA-256: ${env.originalHash}`, 8, rgb(0.4, 0.4, 0.4));
  line(`Created: ${env.createdAt}`, 9);
  line(`Completed: ${env.completedAt}`, 9);
  cy -= 6;
  line("--- Signers (in order) ---", 11);
  for (const s of env.signers) {
    line(`#${s.order + 1}  ${s.name} <${s.email}>`, 10);
    line(`      Sent: ${s.sentAt || "-"}`, 8, rgb(0.4, 0.4, 0.4));
    line(`      Signed: ${s.signedAt || "-"}  IP: ${s.ip || "-"}`, 8, rgb(0.4, 0.4, 0.4));
    cy -= 2;
  }
  cy -= 6;
  line("--- Audit Log ---", 11);
  for (const a of env.auditLog) {
    line(`${a.time}  [${a.event}] ${a.detail}`, 7, rgb(0.3, 0.3, 0.3));
  }

  const out = await pdfDoc.save();
  fs.writeFileSync(path.join(SIGNED_DIR, `${env.id}.pdf`), out);
}

// ============================================================
//  HTML ページ（テンプレート）
// ============================================================
const baseStyle = `
  <style>
    * { box-sizing: border-box; }
    body { font-family: -apple-system, "Segoe UI", "Hiragino Sans", Meiryo, sans-serif;
           max-width: 820px; margin: 0 auto; padding: 24px; color: #1a2b3c; background:#f3f4f7; }
    h1 { color:#037EF3; font-size: 22px; }
    h2 { font-size: 16px; margin-top: 24px; }
    .card { background:#fff; border-radius:12px; padding:24px; box-shadow:0 2px 8px rgba(0,0,0,.06); margin-bottom:16px; }
    label { display:block; font-size:13px; font-weight:600; margin:12px 0 4px; }
    input[type=text], input[type=email], input[type=file] {
      width:100%; padding:10px; border:1px solid #d5dae2; border-radius:8px; font-size:14px; }
    button { background:#037EF3; color:#fff; border:0; border-radius:8px; padding:12px 20px;
             font-size:15px; font-weight:600; cursor:pointer; }
    button:hover { background:#0268c9; }
    .btn-sec { background:#e8edf3; color:#037EF3; }
    .signer-row { display:flex; gap:8px; margin-bottom:8px; align-items:center; }
    .signer-row input { flex:1; }
    .order-badge { background:#037EF3; color:#fff; width:26px;height:26px;border-radius:50%;
                   display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700; flex-shrink:0;}
    .muted { color:#7a8794; font-size:13px; }
    .status-badge { display:inline-block; padding:2px 10px; border-radius:12px; font-size:12px; font-weight:600; }
    .s-pending { background:#eceff3; color:#7a8794; }
    .s-sent { background:#fff3d6; color:#b8860b; }
    .s-signed { background:#d6f5e0; color:#1a8f4a; }
    canvas { border:1px dashed #b5c0cd; border-radius:8px; width:100%; touch-action:none; background:#fff; }
    iframe { width:100%; height:480px; border:1px solid #d5dae2; border-radius:8px; }
    code { background:#eceff3; padding:2px 6px; border-radius:4px; font-size:12px; }
    a { color:#037EF3; }
  </style>
`;

function pageCreate() {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>PDF署名ツール</title>${baseStyle}</head><body>
  <h1>PDF 順次署名ツール</h1>
  <p class="muted">PDFをアップロードし、署名者を順番に登録します。1人目から順にメールで署名依頼が届きます。</p>
  <form class="card" action="/create" method="post" enctype="multipart/form-data">
    <label>書類タイトル</label>
    <input type="text" name="title" placeholder="例: 業務委託契約書" required>
    <label>PDFファイル</label>
    <input type="file" name="pdf" accept="application/pdf" required>
    <h2>署名者（上から順番に署名依頼が送られます）</h2>
    <div id="signers">
      <div class="signer-row">
        <span class="order-badge">1</span>
        <input type="text" name="name" placeholder="氏名">
        <input type="email" name="email" placeholder="メールアドレス" required>
      </div>
    </div>
    <button type="button" class="btn-sec" onclick="addSigner()">＋ 署名者を追加</button>
    <div style="margin-top:20px"><button type="submit">作成して1人目に送信</button></div>
  </form>
  <script>
    let count = 1;
    function addSigner(){
      count++;
      const div = document.createElement('div');
      div.className='signer-row';
      div.innerHTML = '<span class="order-badge">'+count+'</span>'+
        '<input type="text" name="name" placeholder="氏名">'+
        '<input type="email" name="email" placeholder="メールアドレス" required>';
      document.getElementById('signers').appendChild(div);
    }
  </script>
  </body></html>`;
}

function pageCreated(env) {
  const statusUrl = `${BASE_URL}/status/${env.id}`;
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1"><title>作成完了</title>${baseStyle}</head><body>
  <h1>作成しました</h1>
  <div class="card">
    <p>「<strong>${escapeHtml(env.title)}</strong>」を作成し、1人目の <strong>${escapeHtml(env.signers[0].email)}</strong> に署名依頼を送信しました。</p>
    <p>進捗はこちらのページで確認できます（ブックマーク推奨）:</p>
    <p><a href="${statusUrl}">${statusUrl}</a></p>
  </div>
  <a href="/">← 新しい書類を作成</a>
  </body></html>`;
}

function pageSign(env, signer) {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1"><title>署名</title>${baseStyle}</head><body>
  <h1>署名のお願い</h1>
  <div class="card">
    <p><strong>${escapeHtml(signer.name)}</strong> 様、「<strong>${escapeHtml(env.title)}</strong>」の内容をご確認ください。</p>
    <iframe src="/pdf/${env.id}/${signer.token}"></iframe>
  </div>
  <div class="card">
    <h2>下の枠内に署名してください</h2>
    <canvas id="pad" height="160"></canvas>
    <div style="margin-top:10px; display:flex; gap:8px;">
      <button type="button" class="btn-sec" onclick="clearPad()">消す</button>
      <button type="button" onclick="submitSig()">この内容に署名して送信</button>
    </div>
    <p class="muted" id="msg"></p>
  </div>
  <script>
    const canvas = document.getElementById('pad');
    const ctx = canvas.getContext('2d');
    function resize(){ canvas.width = canvas.offsetWidth; ctx.lineWidth=2; ctx.lineCap='round'; ctx.strokeStyle='#0a2540'; }
    resize(); window.addEventListener('resize', resize);
    let drawing=false, hasInk=false;
    function pos(e){ const r=canvas.getBoundingClientRect(); const t=e.touches?e.touches[0]:e; return {x:t.clientX-r.left, y:t.clientY-r.top}; }
    function start(e){ drawing=true; const p=pos(e); ctx.beginPath(); ctx.moveTo(p.x,p.y); e.preventDefault(); }
    function move(e){ if(!drawing)return; const p=pos(e); ctx.lineTo(p.x,p.y); ctx.stroke(); hasInk=true; e.preventDefault(); }
    function end(){ drawing=false; }
    canvas.addEventListener('mousedown',start); canvas.addEventListener('mousemove',move);
    window.addEventListener('mouseup',end);
    canvas.addEventListener('touchstart',start); canvas.addEventListener('touchmove',move);
    canvas.addEventListener('touchend',end);
    function clearPad(){ ctx.clearRect(0,0,canvas.width,canvas.height); hasInk=false; }
    async function submitSig(){
      if(!hasInk){ document.getElementById('msg').textContent='署名を書いてください'; return; }
      const dataURL = canvas.toDataURL('image/png');
      document.getElementById('msg').textContent='送信中...';
      const r = await fetch(location.pathname, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({signatureImage:dataURL})});
      const j = await r.json();
      if(j.ok){
        document.body.innerHTML = '<h1>署名が完了しました</h1><div class="card"><p>ご署名ありがとうございました。'+
          (j.completed?'全員の署名が完了しました。':'次の署名者に依頼が送られます。')+'</p></div>';
      } else {
        document.getElementById('msg').textContent = 'エラー: '+(j.error||'不明');
      }
    }
  </script>
  </body></html>`;
}

function pageStatus(env) {
  const rows = env.signers.map((s) => {
    const cls = s.status === "signed" ? "s-signed" : s.status === "sent" ? "s-sent" : "s-pending";
    const label = s.status === "signed" ? "署名済み" : s.status === "sent" ? "送信済み（署名待ち）" : "未送信";
    return `<tr>
      <td>${s.order + 1}</td>
      <td>${escapeHtml(s.name)}<br><span class="muted">${escapeHtml(s.email)}</span></td>
      <td><span class="status-badge ${cls}">${label}</span></td>
      <td class="muted">${s.signedAt ? new Date(s.signedAt).toLocaleString("ja-JP") : "-"}</td>
    </tr>`;
  }).join("");

  const done = env.status === "completed";
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1"><title>進捗</title>${baseStyle}
  <meta http-equiv="refresh" content="15"></head><body>
  <h1>進捗: ${escapeHtml(env.title)}</h1>
  <div class="card">
    <p>状態: <strong>${done ? "全員署名完了 ✅" : "署名進行中…"}</strong></p>
    <table style="width:100%; border-collapse:collapse;">
      <thead><tr style="text-align:left; border-bottom:2px solid #e8edf3;">
        <th>順</th><th>署名者</th><th>状態</th><th>署名日時</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    ${done ? `<div style="margin-top:20px"><a href="/download/${env.id}"><button>署名済みPDFをダウンロード</button></a></div>` : `<p class="muted" style="margin-top:16px">※このページは15秒ごとに自動更新されます</p>`}
  </div>
  <h2>監査ログ</h2>
  <div class="card">
    ${env.auditLog.map((a) => `<div class="muted" style="font-size:12px; padding:2px 0;">${new Date(a.time).toLocaleString("ja-JP")} — [${a.event}] ${escapeHtml(a.detail)}</div>`).join("")}
  </div>
  <a href="/">← トップ</a>
  </body></html>`;
}

function pageMessage(title, body) {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title>${baseStyle}</head><body>
  <h1>${escapeHtml(title)}</h1><div class="card"><p>${escapeHtml(body)}</p></div></body></html>`;
}

app.listen(PORT, () => {
  console.log(`\n署名ツール起動: ${BASE_URL}`);
  console.log(transporter ? "SMTP: 設定済み（実際にメール送信します）" : "SMTP: 未設定（メールはコンソールに擬似表示）");
});
