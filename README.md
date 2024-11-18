# Projekt - DNS Monitor

## Autor
**Jméno:** Jakub Fukala
**Login:** xfukal01
**Datum vytvoření:** 26.10. 2024

## Popis programu

Program **dns-monitor** je nástroj pro monitorování DNS komunikace na zvoleném síťovém rozhraní nebo pro zpracování DNS zpráv z existujícího záznamu komunikace ve formátu PCAP.

Program zpracovává zprávy protokolu DNS a vypisuje informace z nich získané. Dále je schopen zjišťovat doménová jména, která se objevila v DNS zprávách, a také překlady doménových jmen na IPv4/6 adresy.

### Rozšíření

Program byl proti původnímu zadání rozšířen o podporu záznamů typu **PTR** (Pointer Record), které se používají pro reverzní DNS záznamy.

### Omezení

- Program podporuje pouze protokol UDP pro DNS komunikaci.
- Nepodporuje jiné typy záznamů než uvedené (A, AAAA, NS, MX, SOA, CNAME, SRV, PTR).

### Překlad 

Pro přeložení programu je možné využít přiložený `Makefile` v kořenovém adresáři:
```bash
make
```

Pro přeložení a spuštění testů je možné použít příkaz:
```bash
make test
```

**Pozor!** je však nutné mít na zařízení dostupnou knihovnu CUnit.
Pro Ubuntu:
```bash
sudo apt install libcunit1 libcunit1-doc libcunit1-dev
```

Pro Arch linux:
```bash
sudo pacman -S cunit
```

## Příklad spuštění

Usage: dns-monitor (-i <interface> | -p <pcapfile>) [FLAGS]\n\n
            "Switchers:\n"
`-d <domains_file>`      Zapíná funkci ukládání doménových jmen do zvoleného souboru.
`-t <translations_file>` Zapíná funkci pro ukládání překladů doménových jmen
`-v`                     Zapíná rozšířený výpis programu
`-g`                     Režim ladění

Monitorování na síťovém rozhraní `eth0` s výpisem doménových jmen a překladů:

```bash
dns-monitor -i eth0 -d domains.txt -t translations.txt
```

Skenování dat z existujícího záznamu v souboru `file.pcap` ve formátu PCAP:

```bash
dns-monitor -p file.pcap -d domains.txt -t translations.txt
```

## Seznam odevzdaných souborů

### Struktura repozitáře
```.
├── src
│   ├── dns_monitor.c   # Obsahuje hlavní vstup programu
│   ├── dns_monitor.h   # Hlavičkový soubor určen pro sdílení funkcí mezi soubory
│   ├── dns_parser.c    # Obsahuje implementaci funkcí pro zpracování zpráv DNS
│   ├── arg_parser.c    # Obsahuje implementaci pro zpracovaní argumentů příkazové řádky
│   ├── linked_list.c   # Obsahuje implementaci jednosměrně vázaných seznamů
│   ├── linked_list.h   # Hlavičkový soubor určen pro sdílení funkcí pro prací se seznamy
├── tests
│   ├── test_main.c     # Soubor obsahujíci základní testy programu 
├── Makefile
├── README.md
```


