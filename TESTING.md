# Test Protokolü — Tüm Turların Özeti

## ✅ Gerçekten çalıştırıp doğruladıklarım (bu ortamda, internet olmadan)

| Test | Sonuç |
|---|---|
| 23 dosyanın tamamının sözdizimi kontrolü (`node --check`) | ✅ Hepsi geçti |
| Her `import`'un `package.json`'da karşılığı var mı | ✅ Hepsi eşleşti |
| WAF filtresi — 5 gerçek saldırı örneği (SQLi, XSS, path traversal) | ✅ Hepsi engellendi |
| WAF filtresi — 5 meşru girdi (Türkçe karakter, sipariş no, fiyat vb.) | ✅ Hiçbiri yanlışlıkla engellenmedi |
| AES-256-GCM şifreleme — gerçek şifrele/çöz turu | ✅ Round-trip başarılı, her seferinde farklı çıktı (rastgele IV) |
| E-posta/metin doğrulama fonksiyonları — 7 senaryo | ✅ Hepsi doğru sonuç verdi |
| Veritabanı şemasındaki TÜM yabancı anahtar ilişkileri (cascade zinciri) | ✅ Elle, tek tek izlendi — çakışma yok |
| `token_version` mantığı — hangi SELECT'in neyi döndürdüğü, hangi response'un neyi içerdiği | ✅ Kod okuması ile izlendi — hassas alan hiçbir yanıtta sızmıyor |

## ⚠️ Bu ortamda test EDEMEDİĞİM (internet erişimim yok)

- `sanitize-html`, `file-type`, `jsonwebtoken` paketleri npm'den
  kurulamadığı için gerçek çalışmalarını burada göremedim (mantıkları
  doğru, ama çalışma zamanı testi Railway'de yapılmalı)
- Cloudinary'ye gerçek dosya yükleme
- PostgreSQL'e gerçek bağlantı, migration'ın çalışması
- TronGrid'den gerçek blockchain verisi çekme
- Gerçek e-posta gönderimi (SMTP)

## 🔴 Bulduğum ve düzelttiğim gerçek sorunlar (kronolojik)

1. **KRİTİK — sipariş tutarı istemciye güveniyordu.** `POST /orders`,
   `subtotal`'ı doğrudan isteğin gövdesinden okuyordu — bir kullanıcı
   isteği değiştirip gerçek fiyatın yerine 1 kuruş gönderebilirdi. Artık
   her ürün `productId` ile veritabanından tek tek doğrulanıyor, gerçek
   fiyat/stok sunucuda okunuyor, tutar sıfırdan hesaplanıyor. Kupon da
   sunucu tarafında doğrulanıp uygulanıyor.
2. **Dosya yükleme sadece istemcinin beyan ettiği türe bakıyordu.** Artık
   dosyanın gerçek baytları (`file-type`) okunuyor. Kabul edilen türler
   isteğiniz gibi sadece PDF, PNG, JPEG'e indirildi.
3. **XSS için hiçbir temizleme yoktu.** Tüm serbest metin alanları artık
   veritabanına yazılmadan önce HTML/script içeriğinden temizleniyor.
4. **"Ad Soyad" ve "E-posta" değiştirme akışlarının backend'i hiç yoktu.**
   `/api/account/*` altında tam çalışan, e-posta onaylı endpoint'ler var.
5. **`/2fa/verify-totp` hiç korumasızdı.** Artık ban merdivenine bağlı.
6. **Giriş yapmış kullanıcı için şifre değiştirme endpoint'i yoktu.**
   `/api/account/change-password` eklendi.
7. **Gerçek bir "güvenli çıkış" yoktu.** JWT'ler durum tutmaz — üretildikten
   sonra süresi dolana kadar geçerli kalır, "çıkış" dense bile. Kullanıcılar
   tablosuna `token_version` eklendi: her istekte veritabanındaki güncel
   değerle karşılaştırılıyor. Çıkış yapınca veya şifre değişince bu sayaç
   artıyor ve o ana kadar üretilmiş TÜM eski token'lar anında işe yaramaz
   hale geliyor.
8. **Kendi kendimi test ederken bir tasarım hatası yakaladım**: WAF
   filtresini önce istek gövdesine de uygulayacaktım, ama bunun `--` içeren
   geçerli şifreleri yanlışlıkla engelleyeceğini fark ettim. Kapsamı sadece
   query/path parametrelerine indirdim.

## Sıradaki adım

Railway'e deploy ettiğinizde, "test edemediğim" listesini birlikte, gerçek
verilerle test edelim — özellikle dosya yükleme, e-posta gönderimi ve
giriş/çıkış (token_version) akışını ilk denediğimizde dikkatli izleyelim.
