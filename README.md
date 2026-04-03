# DNS Builds

DNS | Hosts (Raw) | Cloaking Rules (Raw) |
--- | --- | --- |
Comss | [Comss.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/hosts/Comss.txt) | [Comss.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/cr/Comss.txt) |
IMalware | [IMalware.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/hosts/IMalware.txt) | [IMalware.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/cr/IMalware.txt) |
Mafioznik | [Mafioznik.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/hosts/Mafioznik.txt) | [Mafioznik.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/cr/Mafioznik.txt) |
Mafioznik 2 | [Mafioznik_2.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/hosts/Mafioznik_2.txt) | [Mafioznik_2.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/cr/Mafioznik_2.txt) |
AstraCat | [AstraCat.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/hosts/AstraCat.txt) | [AstraCat.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/cr/AstraCat.txt) |
XboxDNS | [XboxDNS.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/hosts/XboxDNS.txt) | [XboxDNS.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/cr/XboxDNS.txt) |
GeoHide | [GeoHide.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/hosts/GeoHide.txt) | [GeoHide.txt](https://raw.githubusercontent.com/sevcator/dnscrypt-proxy-stuff/main/cr/GeoHide.txt) |

## Debug в консоли (dnscrypt-proxy)

Чтобы видеть ошибки и подробный debug прямо в консоли:

1. В `dnscrypt-proxy.toml` установите:

```toml
log_level = 0
log_file = ''
```

2. Запускайте `dnscrypt-proxy` в foreground (без демонизации), тогда логи пойдут в stdout/stderr.

> `log_level = 0` включает максимальную детализацию (debug), поэтому в консоли будут и ошибки, и диагностические сообщения.
