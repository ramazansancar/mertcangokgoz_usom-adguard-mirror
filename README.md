# usom-adguard-mirror

Bu repo USOM'un [Malware URL](https://www.usom.gov.tr/adres) listesini farklı reklam engelleyiciler ve DNS filtreleme araçları için uyarlamak amacıyla oluşturulmuştur.

Üç saatte bir kez olmak üzere güncellenmektedir. Duplike edilen URL'ler ve yorum satırları otomatik olarak kaldırılmaktadır.

## Kullanılabilir Listeler

Projede iki farklı format bulunmaktadır:

- **AdGuard/uBlock Format**: `usom_adguard_blacklist.txt` - AdGuard ve uBlock Origin için optimize edilmiş
- **Hosts Format**: `usom_hosts_blacklist.txt` - PiHole ve AdGuard Home için optimize edilmiş

## Kurulum Talimatları

### AdGuard (Masaüstü/Mobil)

1. AdGuard kontrol paneline gidin.
2. "Ayarlar" sekmesine tıklayın.
3. DNS Engel listeleri bölümüne gidin.
4. "Engel listesi ekle" düğmesine tıklayın ve "Özel liste ekle" seçeneğini seçin.
5. Liste adını "USOM Malware URL" olarak girin ve URL'yi ekleyin:

    ```
    https://raw.githubusercontent.com/mertcangokgoz/usom-adguard-mirror/main/usom_adguard_blacklist.txt
    ```

6. "Kaydet" düğmesine tıklayın.

### uBlock Origin

1. uBlock Origin ayarlarına gidin (eklenti simgesine tıklayın ve ayarlar simgesini seçin).
2. "Filter lists" sekmesine gidin.
3. "Import..." düğmesine tıklayın.
4. URL'yi girin:

    ```
    https://raw.githubusercontent.com/mertcangokgoz/usom-adguard-mirror/main/usom_adguard_blacklist.txt
    ```

5. "Apply changes" düğmesine tıklayın.

### AdGuard Home

1. AdGuard Home yönetici paneline gidin.
2. "Filters" → "DNS blocklists" sekmesine gidin.
3. "Add blocklist" düğmesine tıklayın.
4. Liste adını "USOM Malware URL" olarak girin ve URL'yi ekleyin:

    ```
    https://raw.githubusercontent.com/mertcangokgoz/usom-adguard-mirror/main/usom_hosts_blacklist.txt
    ```

5. "Save" düğmesine tıklayın.

### Pi-hole

1. Pi-hole yönetici paneline gidin.
2. "Group Management" → "Lists" sekmesine gidin.
3. "Address" alanına URL'yi girin:

    ```
    https://raw.githubusercontent.com/mertcangokgoz/usom-adguard-mirror/main/usom_hosts_blacklist.txt
    ```

4. "Comment" alanına "USOM Malware URL" yazın.
5. "Add Blacklist" düğmesine tıklayın.
6. "Tools" → "Update Gravity" sekmesine gidip "Update" düğmesine tıklayarak listeyi güncelleyin.

## LICENSE

Bu proje MIT lisansı altında lisanslanmıştır. Lütfen [LICENSE](LICENSE) dosyasını inceleyin.
