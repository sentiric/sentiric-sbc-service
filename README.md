# 🔒 Sentiric Sip SBC Service

[![Status](https://img.shields.io/badge/status-vision-lightgrey.svg)]()
[![Language](https://img.shields.io/badge/language-Rust-orange.svg)]()
[![Protocol](https://img.shields.io/badge/protocol-gRPC_&_SIP-green.svg)]()

**Sentiric SBC (Session Border Controller) Service**, SIP Gateway'den gelen ham sinyalleşme trafiğini işlemek ve yönlendirme kararı vermek için kullanılan katmandır. Bu servis, SIP paketlerini derinlemesine analiz eder ve bir dizi güvenlik ve trafik kontrol kuralına göre trafiği `sentiric-sip-proxy-service`'e iletmek veya reddetmekten sorumludur.

Bu servis, ağ sınırında (Edge) çalışmak üzere tasarlanmıştır.

## 🎯 Temel Sorumluluklar

1.  **Güvenlik Kontrolü:** İstenmeyen SIP trafiğini (SIP Flood, hatalı formatlanmış paketler) engeller.
2.  **Yönlendirme Kararı:** Hangi Next-Hop'a (sonraki atlama noktası) gidileceğine dair kararı verir (`GetRoute` RPC'si).
3.  **Protokol Normaleştirme:** Farklı SIP sağlayıcılarından gelen standart dışı mesajları platformun iç SIP formatına dönüştürür.
4.  **Trafik Kontrolü:** Belirli IP'lerden veya kullanıcı kimliklerinden gelen trafiği kısıtlama veya önceliklendirme.

## 🛠️ Teknoloji Yığını

*   **Dil:** Rust (Yüksek performanslı ağ I/O ve düşük gecikme için)
*   **Ağ:** Tokio UDP Listener
*   **Servisler Arası İletişim:** gRPC (Tonic)

## 🔌 API Etkileşimleri

*   **Gelen (Sunucu):**
    *   `sentiric-sip-gateway-service` (gRPC): Sinyalleşme kararını almak için çağrılır.
    *   Harici SIP Ağları (UDP/TCP): Ham SIP trafiği (Doğrudan `sip-gateway` tarafından alınır, ancak SBC bu paketi analiz eder).
*   **Giden (İstemci):**
    *   `sentiric-proxy-service` (gRPC): İzin verilen ve normalize edilen trafiği iletmek için.

---
## 🏛️ Anayasal Konum

Bu servis, [Sentiric Anayasası'nın](https://github.com/sentiric/sentiric-governance) **Core Logic Layer**'ında yer alan yeni SIP Protokol Yönetimi bileşenidir.