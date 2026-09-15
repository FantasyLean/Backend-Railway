import sanitizeHtml from "sanitize-html";

/**
 * Kullanıcıdan gelen serbest metni (isim, ticket mesajı, ürün açıklaması vb.)
 * veritabanına yazmadan önce temizler. HİÇBİR HTML etiketine izin verilmez —
 * bu bir zengin metin editörü değil, düz metin alanlarıdır. Bu sayede, bu veri
 * daha sonra herhangi bir yerde (admin panelinde, bir e-postada, vs.) render
 * edilse bile saklı (stored) XSS riski oluşmaz.
 */
export function sanitizeText(input) {
  if (typeof input !== "string") return input;
  return sanitizeHtml(input, { allowedTags: [], allowedAttributes: {} }).trim();
}
