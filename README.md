# Alpeptide Backend

Bu klasör, frontend'de simüle ettiğimiz her şeyin **gerçek** karşılığı: kayıt/giriş,
e-posta doğrulama, Google Authenticator, brute-force ban merdiveni, ve **otomatik
kripto ödeme onayı**.

## 1. Yerel kurulum

```bash
cd alpeptide-backend
npm install
cp .env.example .env   # sonra .env dosyasını gerçek bilgilerle doldurun
```

### Gerekli hesaplar / anahtarlar
| Ne için | Nereden alınır |
|---|---|
| Veritabanı | Herhangi bir PostgreSQL (yerelde Postgres.app, veya Railway/Supabase gibi hazır bir servis) |
| reCAPTCHA | google.com/recaptcha/admin |
| Mail gönderimi | Resend, SendGrid veya benzeri (geliştirme sırasında mail konsola yazılır, gerçek gönderim yapılmaz) |
| TronGrid (USDT-TRC20 takibi) | trongrid.io — ücretsiz API anahtarı |

### Veritabanını kur
```bash
npm run db:migrate
```

### Sunucuyu çalıştır
```bash
npm run dev
```

## 2. Frontend'i buna bağlamak

Şu anki React kodu (`AlpeptideHomeV39.jsx`) tüm state'i tarayıcıda tutuyor. Gerçek
backend'e geçince şunlar değişecek:

- `AuthModal` içindeki `handleRegisterSubmit`, `handleLoginSubmit` vb. fonksiyonlar,
  artık yerel state güncellemek yerine `fetch("/api/auth/register", {...})` gibi
  gerçek API çağrıları yapacak.
- Giriş başarılı olunca dönen `token`, `localStorage`'a kaydedilip sonraki her
  istekte `Authorization: Bearer <token>` header'ı olarak gönderilecek.
- `FAKE_ORDERS`, `FAKE_TICKETS` gibi sabit veriler kalkacak, yerine `/api/orders`
  gibi endpoint'lerden gelen gerçek veri kullanılacak.

Bu geçişi birlikte, sayfa sayfa yapabiliriz — önce kayıt/giriş, sonra siparişler,
sonra ticket sistemi gibi.

## 3. Kripto ödeme otomasyonu nasıl çalışıyor

1. Kullanıcı "Sepeti Tamamla" dediğinde, backend **benzersiz bir tutar** üretir
   (örn. 150 TL karşılığı 150.284917 USDT).
2. Kullanıcıya bu tam tutarı gönderin denir.
3. `src/services/cryptoWatcher.js`, arka planda her 2 dakikada bir (ayarlanabilir)
   cüzdanımıza gelen işlemleri TronGrid'den kontrol eder.
4. Tutar eşleşirse ve **minimum onay sayısına** (varsayılan 19) ulaşılmışsa,
   sipariş otomatik olarak "ödeme onaylandı" durumuna geçer.
5. Onay sayısı henüz yetersizse, sipariş "ödeme onaylama aşamasında" olarak
   işaretlenir ve bir sonraki taramada tekrar kontrol edilir.
6. Eşleşen bir sipariş bulunamazsa (yanlış tutar, bilinmeyen gönderim), hiçbir şey
   otomatik onaylanmaz — loglanır, gerekirse admin panelinden manuel incelenir.

**Neden minimum onay sayısı bekliyoruz?** Bir blok zincirinde işlem "görülür
görülmez" kesin değildir; birkaç blok sonra geçersiz hale gelebilir ("chain
reorg"). 19 onay TRON ağı için pratikte güvenli kabul edilen bir eşiktir.
Bunu düşürüp süreci hızlandırabilirsiniz ama çift harcama riskini de artırırsınız.

**Ethereum/Bitcoin için de otomasyon istersen** aynı mantığı Etherscan veya
Blockstream API'siyle kurabiliriz — `cryptoWatcher.js` içindeki `fetchIncomingTransactions`
fonksiyonu o ağa göre değişir, mimarinin geri kalanı aynı kalır.

## 4. Deploy etmek (barındırma)

- **Backend**: Railway, Render veya bir VPS (DigitalOcean/Hetzner) — Node.js
  destekleyen herhangi biri.
- **Veritabanı**: Railway/Render'ın kendi Postgres eklentisi veya Supabase.
- **Frontend**: Zaten Netlify'da; backend'in URL'sini frontend'de bir ortam
  değişkeni olarak tanımlarız (`VITE_API_URL` gibi).

## 5. Sırada ne var

Bu iskelet; kayıt, giriş, 2FA, ban sistemi ve kripto otomasyonunun **çalışan bir
temelini** kuruyor. Eksik/ileride eklenecekler:
- Adresler, ticket mesajları için CRUD endpoint'leri (şemada tablolar hazır,
  route'ları henüz yazmadık)
- Admin paneli route'ları (sipariş durumu değiştirme, ticket yanıtlama)
- Gerçek dosya/görsel yükleme (ticket ekleri için — S3 veya Cloudinary gibi bir
  servis gerekir)

Bu parçaları da aynı ciddiyetle, birer birer yazabiliriz.
