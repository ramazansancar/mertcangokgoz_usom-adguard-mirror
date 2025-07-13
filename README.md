# usom-adguard-mirror

Bu repo USOM'un [Malware URL](https://www.usom.gov.tr/adres) listesini AdGuard için uyarlamak amacıyla oluşturulmuştur.

Üç saatte bir kez olmak üzere güncellenmektedir. Duplike edilen URL'ler ve yorum satırları otomatik olarak kaldırılmaktadır.

## Kurulum

1. AdGuard kontrol paneline gidin.
2. "Ayarlar" sekmesine tıklayın.
3. DNS Engel listeleri bölümüne gidin.
4. "Engel listesi ekle" düğmesine tıklayın. "Özel liste ekle" seçeneğini seçin.
5. Ad "USOM Malware URL" girin. URL girin:
   ```
   https://raw.githubusercontent.com/mertcangokgoz/usom-adguard-mirror/refs/heads/main/usom_adguard_blacklist.txt
    ```
6. "Kaydet" düğmesine tıklayın.

## LICENSE

Bu proje MIT lisansı altında lisanslanmıştır. Lütfen [LICENSE](LICENSE) dosyasını inceleyin.