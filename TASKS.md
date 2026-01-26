# 🔒 Sentiric SBC Service - Görev Listesi

Bu servisin mevcut ve gelecekteki tüm geliştirme görevleri, platformun merkezi görev yönetimi reposu olan **`sentiric-tasks`**'ta yönetilmektedir.

➡️ **[Aktif Görev Panosuna Git](https://github.com/sentiric/sentiric-tasks/blob/main/TASKS.md)**

---

 **Verification Steps:**
    1.  `cargo check` komutunu çalıştırarak kodun hatasız derlendiğini doğrulayın.
    2.  Ortam değişkenini `RUST_LOG=debug` olarak ayarlayın.
    3.  `docker-compose up` ile servisi başlatın.
    4.  Bir SIP paketi gönderin.
    5.  `sbc-service`'in log çıktısını inceleyin. Aşağıdaki gibi detaylı bir log görmelisiniz:
        ```json
        {
          "timestamp": "...",
          "level": "DEBUG",
          "fields": {
            "message": "Gelen SIP paketi işleniyor",
            "source": "192.168.1.10:45678",
            "sip.request_uri": "sip:test@proxy-service",
            "sip.from": "\"Alice\" <sip:alice@example.com>",
            "sip.to": "<sip:bob@example.com>",
            "sip.cseq": "1 INVITE",
            "sip.method": "INVITE",
            "sip.call_id": "some-unique-call-id-12345"
          },
          "target": "sentiric_sbc_service::sip::server"
        }
        ```