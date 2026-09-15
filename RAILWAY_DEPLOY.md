# Railway'e Deploy — Adım Adım

Bu adımları kendi bilgisayarınızda / Railway hesabınızda takip edin. Bir adımda
hata alırsanız tam mesajı bana gönderin, birlikte çözeriz.

## 1. GitHub'a yükleyin (Railway genelde buradan çeker)
```bash
cd alpeptide-backend
git init
git add .
git commit -m "İlk backend sürümü"
```
GitHub'da yeni, **boş** bir repo oluşturun (README eklemeden), sonra:
```bash
git remote add origin https://github.com/KULLANICI_ADINIZ/alpeptide-backend.git
git branch -M main
git push -u origin main
```

## 2. Railway'de proje oluşturun
1. railway.app adresine gidip GitHub hesabınızla giriş yapın
2. "New Project" → "Deploy from GitHub repo" → `alpeptide-backend` reposunu seçin
3. Railway otomatik olarak Node.js projesi olduğunu algılayıp `npm install` +
   `npm start` çalıştırmayı deneyecek

## 3. PostgreSQL ekleyin
1. Aynı projede "New" → "Database" → "Add PostgreSQL"
2. Railway otomatik bir `DATABASE_URL` değişkeni oluşturur — bunu backend
   servisinize bağlamak için: backend servisinizin "Variables" sekmesinde
   "New Variable" → "Add Reference" → Postgres'in `DATABASE_URL`'ini seçin

## 4. Diğer ortam değişkenlerini girin
Backend servisinizin **Variables** sekmesinde, `.env.example` dosyasındaki
her satırı tek tek ekleyin (gerçek değerlerle):
- `JWT_SECRET` → örnek üretmek için: `openssl rand -base64 48`
- `FRONTEND_URL` → Netlify sitenizin adresi
- `RECAPTCHA_SITE_KEY` / `RECAPTCHA_SECRET_KEY`
- `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `MAIL_FROM`
- `TRONGRID_API_KEY` / `TRON_WALLET_ADDRESS`
- `NODE_ENV=production`

## 5. Veritabanı şemasını uygulayın
Railway'in verdiği "Connect" bilgisiyle (veya `railway run` komutuyla) bir kere:
```bash
railway run npm run db:migrate
```
(Railway CLI kurulu değilse: `npm install -g @railway/cli` ve `railway login`)

## 6. Deploy'u kontrol edin
Railway size bir public URL verecek (örn. `alpeptide-backend.up.railway.app`).
Tarayıcıda şunu açın:
```
https://alpeptide-backend.up.railway.app/api/health
```
`{"ok": true}` görüyorsanız, backend gerçekten çalışıyor demektir. 🎉

## 7. Bana bildirin
Bu URL'yi bana verin — frontend'i buna bağlamaya, ve gerçek kayıt/giriş akışını
test etmeye birlikte başlayalım.
