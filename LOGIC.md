# 🔒 Sentiric SBC Service - Mantık Mimarisi (Final)

**Rol:** Gümrük Kapısı. İlk temas noktası ve Güvenlik Duvarı.

## 1. Paket İşleme Hattı (Pipeline)

UDP 5060 portuna gelen her paket şu filtreden geçer:

1.  **Güvenlik (Sanitization):**
    *   `User-Agent` kontrolü (SipVicious, FriendlyScanner engelleme).
    *   `Max-Forwards` kontrolü (Döngü engelleme).

2.  **NAT Düzeltme (Traversal Fix):**
    *   Gelen paketin `Via` başlığına `rport` ve `received` parametrelerini ekler. (Böylece Proxy cevabı nereye döneceğini bilir).
    *   Kendi Public IP'sini `Record-Route` olarak ekler.

3.  **Yönlendirme (Next Hop):**
    *   Temizlenmiş paketi iç ağdaki `proxy-service`'e iletir.

## 2. Kritik Kural

SBC asla **Business Logic** (Veritabanı sorgusu, Kullanıcı kontrolü) yapmaz. Sadece paketin "Teknik Olarak" düzgün ve güvenli olup olmadığına bakar.