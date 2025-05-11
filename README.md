# Diophante - HackMyVM (Hard)

![Diophante.png](Diophante.png)

## Übersicht

*   **VM:** Diophante
*   **Plattform:** [HackMyVM](https://hackmyvm.eu/machines/machine.php?vm=Diophante)
*   **Schwierigkeit:** Hard
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 14. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Diophante_HackMyVM_Hard/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser "Hard"-Challenge war es, Root-Zugriff auf der Maschine "Diophante" zu erlangen. Die Enumeration deckte einen Webserver (Apache) und einen gefilterten SMTP-Port auf. Eine Notiz auf dem Webserver (`/note.txt`) enthielt eine Port-Knocking-Sequenz (7000, 8000, 9000), die den SMTP-Port öffnete. Im WordPress-Blog (`/blog/`) wurde durch `wpscan` eine LFI-Schwachstelle im "Site Editor"-Plugin (CVE-2018-7422) identifiziert. Mittels Mail-Poisoning (Senden einer PHP-Webshell via SMTP an einen lokalen Benutzer und anschließendes Einbinden der Maildatei über LFI) wurde RCE als `www-data` erreicht. Eine `doas`-Regel erlaubte `www-data` das Ausführen von `setsid` als `sabine`, was für Lateral Movement genutzt wurde. Als `sabine` erlaubte eine weitere `doas`-Regel das Ausführen von `mutt` als `leonard`. Durch einen Shell-Escape in `mutt` wurde eine Shell als `leonard` erlangt. Schließlich wurde eine `sudo`-Regel für `leonard` gefunden, die `LD_PRELOAD` nicht bereinigte. Durch Erstellen einer bösartigen Shared Library und Aufrufen eines beliebigen `sudo`-Befehls mit gesetztem `LD_PRELOAD` wurde Root-Zugriff erlangt.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `nmap`
*   `gobuster`
*   `curl`
*   `hping3`
*   `knock`
*   `telnet`
*   `wpscan`
*   `searchsploit`
*   `nc` (netcat)
*   `doas` (auf Zielsystem)
*   `setsid` (auf Zielsystem)
*   `ssh`
*   `mutt` (als Exploit-Vektor)
*   `sudo` (auf Zielsystem)
*   `gcc`
*   Standard Linux-Befehle (`vi`, `cat`, `bash`, `find`, `echo`, `id`, `cd`, `ls`, `unsetenv`, `setgid`, `setuid`, `system`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "Diophante" gliederte sich in folgende Phasen:

1.  **Reconnaissance & Port Knocking:**
    *   IP-Findung mittels `arp-scan` (Ziel: `192.168.2.147`, Hostname `dio.vm`).
    *   `nmap`-Scan identifizierte SSH (22/tcp), Apache (80/tcp) und einen gefilterten SMTP-Port (25/tcp).
    *   `gobuster` fand auf Port 80 `/blog/` (WordPress) und `/note.txt`.
    *   `/note.txt` enthielt die Port-Knocking-Sequenz `7000 8000 9000`.
    *   Mittels `knock dio.vm 7000 8000 9000` wurde Port 25/SMTP geöffnet.

2.  **Web Enumeration & LFI (WordPress):**
    *   `wpscan` auf `/blog/` identifizierte das anfällige Plugin "Site Editor" <= 1.1.1 (CVE-2018-7422, LFI).
    *   Der Exploit-Pfad für die LFI wurde über `searchsploit` gefunden: `/blog/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=[FILEPATH]`.
    *   Mittels LFI wurde `/etc/passwd` gelesen und die Benutzer `sabine` und `leonard` identifiziert.

3.  **Initial Access (RCE als `www-data` via Mail Poisoning & LFI):**
    *   Eine Telnet-Verbindung zum SMTP-Server (Port 25) wurde hergestellt.
    *   Eine E-Mail mit einer PHP-Webshell (`system($_GET["cmd"]); ?>`) im Body wurde von `leonard` an `sabine` gesendet.
    *   Die Maildatei von `sabine` (`/var/mail/sabine`) wurde über die LFI-Schwachstelle eingebunden und der `cmd`-Parameter genutzt, um eine Bash-Reverse-Shell zu starten (`curl 'http://...ajax_path=/var/mail/sabine&cmd=[payload]'`).
    *   Erfolgreicher Shell-Zugriff als `www-data`.

4.  **Privilege Escalation (von `www-data` zu `sabine` zu `leonard`):**
    *   Als `www-data` wurde (vermutlich durch `linpeas.sh` oder manuelle Prüfung von `/etc/doas.conf`) eine `doas`-Regel gefunden: `permit nopass www-data as sabine cmd /usr/bin/setsid`.
    *   Mittels `doas -u sabine /usr/bin/setsid bash` wurde eine Shell als `sabine` erlangt.
    *   Als `sabine` wurde eine weitere `doas`-Regel gefunden: `permit nopass sabine as leonard cmd /usr/bin/mutt`.
    *   `doas -u leonard /usr/bin/mutt` wurde ausgeführt. Innerhalb von `mutt` wurde durch Drücken von `!` und Eingabe von `/bin/bash` eine Shell als `leonard` erlangt.

5.  **Privilege Escalation (von `leonard` zu `root` via Sudo/LD_PRELOAD):**
    *   Als `leonard` wurde die User-Flag gelesen. `sudo -l` zeigte, dass keine spezifischen Befehle erlaubt waren, aber die Umgebungsvariable `LD_PRELOAD` in `env_keep` beibehalten wurde.
    *   Ein C-Code (`shell.c`) wurde erstellt, der `setuid(0)`, `setgid(0)` aufruft und `/bin/sh` startet. Dieser wurde als Shared Library (`/tmp/shell.so`) kompiliert.
    *   Der Befehl `sudo LD_PRELOAD=/tmp/shell.so ping` (oder ein anderer via `sudo` aufrufbarer Befehl, der `LD_PRELOAD` nicht löscht) wurde ausgeführt.
    *   Die geladene `shell.so` führte den Payload aus und startete eine Shell als `root`. Die Root-Flag wurde gelesen.

## Wichtige Schwachstellen und Konzepte

*   **Port Knocking:** Verwendet, um den SMTP-Dienst freizuschalten.
*   **Local File Inclusion (LFI):** Im WordPress-Plugin "Site Editor" (CVE-2018-7422).
*   **Mail Poisoning / Log Poisoning via SMTP & LFI:** Eine PHP-Webshell wurde per E-Mail gesendet und dann über LFI zur RCE ausgeführt.
*   **Unsichere `doas`-Regeln:** Mehrstufige Privilegieneskalation durch falsch konfigurierte `doas`-Berechtigungen (`setsid`, `mutt`).
*   **Shell Escape in `mutt`:** Ermöglichte die Übernahme des Benutzerkontexts.
*   **Unsichere `sudo`-Konfiguration (`env_keep+=LD_PRELOAD`):** Erlaubte Root-Eskalation durch Laden einer bösartigen Shared Library.
*   **LD_PRELOAD Exploit:** Klassische Methode zur Privilegieneskalation unter Linux.

## Flags

*   **User Flag (`/home/leonard/user.txt`):** `Thonirburarnlog`
*   **Root Flag (`/root/root.txt`):** `Culcelborlus`

## Tags

`HackMyVM`, `Diophante`, `Hard`, `Port Knocking`, `WordPress`, `LFI`, `CVE-2018-7422`, `Mail Poisoning`, `SMTP`, `RCE`, `doas`, `mutt`, `Shell Escape`, `sudo`, `LD_PRELOAD`, `Privilege Escalation`, `Linux`
