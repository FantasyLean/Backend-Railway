import axios from "axios";

/** Google'a token'ı gönderip gerçekten doğrulanmış mı diye sorar. */
export async function verifyRecaptcha(token) {
  if (!token) return false;
  try {
    const { data } = await axios.post("https://www.google.com/recaptcha/api/siteverify", null, {
      params: { secret: process.env.RECAPTCHA_SECRET_KEY, response: token },
    });
    return data.success === true;
  } catch (err) {
    console.error("[recaptcha] Doğrulama hatası:", err.message);
    return false;
  }
}
