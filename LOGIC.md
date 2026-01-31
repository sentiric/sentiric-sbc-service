# 🔒 Sentiric SBC Service - Mantık Mimarisi (Nihai)

**Rol:** Gümrük Kapısı. İlk temas noktası ve Medya Köprüsü (Relay).

## 1. Kritik Mimari Kural: "Sticky Media Session"
SBC, sinyalleşme (SIP) seviyesinde hafif görünse de, Medya (RTP) seviyesinde **Diyalog Duyarlı (Dialog-Aware)** olmak zorundadır.

*   **VARSAYIM HATASI:** "SBC stateless çalışır" varsayımı yanlıştır.
*   **GERÇEK:** SBC bir Medya Aracısı (Relay) olduğu için, aynı `Call-ID` ile gelen tüm paketleri (INVITE, 200 OK, ACK) hafızasında tuttuğu **aynı RTP Portu** üzerinden eşleştirmelidir. Aksi takdirde "Port Split" (Port Ayrışması) oluşur ve ses iletilemez.

## 2. Paket İşleme Hattı (Pipeline)

1.  **Medya Sabitleme (Sticky Port Allocation):**
    *   Gelen pakette SDP varsa `Call-ID` kontrol edilir.
    *   Bu çağrı için daha önce bir port ayrılmışsa o kullanılır, yoksa yeni bir port tahsis edilir.
    *   Bu eşleşme çağrı bitene (BYE) kadar korunur.

2.  **Güvenlik (Sanitization):**
    *   `User-Agent` kontrolü (SipVicious vb. engelleme).
    *   `Max-Forwards` kontrolü.

3.  **NAT Düzeltme (Traversal Fix):**
    *   `Via` başlığına `rport` ve `received` eklenir.
    *   SDP içindeki IP/Port bilgisi, sabitlenen Relay Portu ile değiştirilir (Rewrite).

4.  **Yönlendirme (Next Hop):**
    *   Paket `proxy-service`'e iletilir.