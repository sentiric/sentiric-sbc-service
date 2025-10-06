# 🔒 Sentiric SBC Service - Görev Listesi

Bu servisin mevcut ve gelecekteki tüm geliştirme görevleri, platformun merkezi görev yönetimi reposu olan **`sentiric-tasks`**'ta yönetilmektedir.

➡️ **[Aktif Görev Panosuna Git](https://github.com/sentiric/sentiric-tasks/blob/main/TASKS.md)**

---
Bu belge, servise özel, çok küçük ve acil görevler için geçici bir not defteri olarak kullanılabilir.

## Faz 1: Minimal İşlevsellik (INFRA-02)
- [x] Temel Rust projesi ve Dockerfile oluşturuldu.
- [x] gRPC sunucusu iskeleti (`UnimplementedSbcService`) hazırlandı.
- [ ] Proxy Service'e gRPC istemcisi eklenecek. (INFRA-03)
- [ ] Temel SIP başlık ayrıştırma ve loglama mantığı. (ORCH-01)