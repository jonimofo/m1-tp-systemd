# GIRALT Benjamin - M1 Infra Cloud - TP systemd

## I.1. First steps

### Vérifier que la version de systemd est > 241
```
[root@fedora31-2 ~]$ systemctl --version

systemd 243 (v243.4-1.fc31)
+PAM +AUDIT +SELINUX +IMA -APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD +IDN2 -IDN +PCRE2 default-hierarchy=unified
```

*TODO : se documenter + décrire brièvement les autres processus système !! Attention : ne sont pas des kernels process, ces derniers sont listés entre []*


# TODO le reste de la question (a été update par Léo)








## I.2. Gestion du temps
```
[root@fedora31-2 ~]$ timedatectl

               Local time: Fri 2019-11-29 09:54:48 UTC
           Universal time: Fri 2019-11-29 09:54:48 UTC
                 RTC time: Fri 2019-11-29 09:54:47
                Time zone: Etc/UTC (UTC, +0000)
System **clock** synchronized: yes
              NTP service: active
          RTC in local TZ: no
```

### Différence entre Local Time, Universal Time, RTC Time
* **Local Time :** correspond à l'heure du fuseau horaire selectionné (ici UTC+00)
* **UTC (Universal Time Coordinate) :** anciennement GMT, échelle de temps adptée comme base du temps civil internation par la majorité des pays du globe. Elle est comprise entre le *Temps Atomique International (TAI)*, déconnecté des rotations de la terre et donc absolument invariable, et le *Temps Universel (UT)*, lié aux rotations de la Terre, légèrement variable à cause de la vitesse variable de la Terre et de ses courbes elliptiques. Cette échelle de temps permet donc de rester à l'heure exacte malgré les rotations de la Terre et ainsi s'adpater aux secondes intercalaraires/additionnelles relevées dans l'UT.
* **RTC Time (Real Time Clock) :** horloge matérielle intégrée, ultra précise (à la nano-seconde), généralement alimentée par une pile pour permettre de rester à l'heure une fois l'ordinateur éteint, en vue de déclencher des alarmes ou autres...


### Pourquoi utiliser le RTC time ?
L'horloge RTC permet de conserver l'heure sur un appareil qui subirait une par exemple une coupure d'alimentation et ne pourrait se connecter à son réseau après redémarrage. Cela permettrait donc de conserver l'heure du serveur sans même devoir se connecter à un serveur NTP. Particulièrement utile pour la cohérence des logs de la machine...


### Changer de timezone pour un autre fuseau horaire européen + vérification
```
[root@fedora31-2 jonimofo]# timedatectl list-timezones | grep Tokyo
Asia/Tokyo

[root@fedora31-2 jonimofo]# timedatectl set-timezone Asia/Tokyo

[root@fedora31-2 jonimofo]# timedatectl
               Local time: Wed 2019-12-04 06:42:26 JST
           Universal time: Tue 2019-12-03 21:42:26 UTC
                 RTC time: Tue 2019-12-03 21:42:25
                Time zone: Asia/Tokyo (JST, +0900)
System clock synchronized: yes
              NTP service: inactive
          RTC in local TZ: no
```
On peut donc voir que le temps a bien été changé. Le choix de la timezone Asia/Tokyo n'a pas été fait au hasard : le Japon ça déchire. Et aussi TOkyo = RIP Nujabes :(


### Désactiver le service lié à la synchronisation du temps avec cette commande et vérifier à la main qu'il a été coupé
```
[root@fedora31-2 jonimofo]# timedatectl set-ntp false

[root@fedora31-2 jonimofo]# timedatectl  | grep NTP
              NTP service: inactive
```





## I.3. Gestion des noms

[Doc Redhat gestion des hostnames](https://access.redhat.com/documentation/fr-fr/red_hat_enterprise_linux/7/html/networking_guide/sec_configuring_host_names_using_hostnamectl)

### Changer nom de la machine
```
[jonimofo@fedora31-2 ~]$ sudo hostnamectl set-hostname "mofo's laptop" --pretty

[root@fedora31-2 jonimofo]# hostnamectl
   Static hostname: fedora31-2
   Pretty hostname: mofo's laptop
         Icon name: computer-vm
```
Ici on peut voir que l'apostrophe (caractère spécial) a bien été prise en compte dans le nom et figure dans le "Pretty hostname".

`--static` hostname "traditionnel", sélectionné par l'utilisateur et stocké dans le */etc/hostname*
`--transient` hostname éphémère (littéralement !). C'est un nom d'hôte dynamique maintenu par le kernel. Il peut être changé par DHCP ou autre.
`--pretty` Rend le hostname plus facilement lisible pour un humain. Peut être combiné avec les option --static ou --transient. Si l'option est spécifiée, les espaces seront remplacés par des « - » et les caractères spéciaux seront supprimés. 

Il parait bien plus pertinent d'utiliser le --static en prod : au moins on est sûr que les noms ne changeront pas. Ceci pour empêcher/prévenir tout dysfonctionnement potentiel lié à un nom d'hôte qui aurait changé.


```
[root@fedora31-2 jonimofo]# hostnamectl set-deployment maxiprod

[root@fedora31-2 jonimofo]# hostnamectl | grep Deployment
        Deployment: maxiprod

[root@fedora31-2 jonimofo]# hostnamectl
   Static hostname: fedora31-2
   Pretty hostname: mofo's laptop
         Icon name: computer-vm
           Chassis: vm
        Deployment: maxiprod
        Machine ID: a9d2e4b267f8418b9b2f07262c9bdc02
           Boot ID: 8c986aaceb4a4477b3b0c61ae6c1d307
    Virtualization: kvm
  Operating System: Fedora 31 (Cloud Edition)
       CPE OS Name: cpe:/o:fedoraproject:fedora:31
            Kernel: Linux 5.3.12-300.fc31.x86_64
      Architecture: x86-64
```
Comme le dit ce bon vieux Léo dans le TP, on recueille ici avec cette commande tout un tas d'infos super importantes (et très utile dans un inventaire disons-le !).

#### TODO/LATER : creuser davantage cette histoire de set-deployment et voir comment s'en servir efficacement dans un SI.


## I.4. Gestion du réseau (et résolution de noms)

### Lister les interfaces actives
```
[root@fedora31-2 jonimofo]# nmcli con show --active
NAME                UUID                                  TYPE      DEVICE
Wired connection 1  53cd0305-efdd-337b-aae4-d33377568ee1  ethernet  ens3
```

### Récupération des informations DHCP récupérées par NetworkManager
```
[root@fedora31-2 jonimofo]# nmcli con show 'Wired connection 1' | grep DHCP

DHCP4.OPTION[1]:                        broadcast_address = 192.168.5.255
DHCP4.OPTION[2]:                        dhcp_lease_time = 3600
DHCP4.OPTION[3]:                        dhcp_rebinding_time = 3150
DHCP4.OPTION[4]:                        dhcp_renewal_time = 1800
DHCP4.OPTION[5]:                        dhcp_server_identifier = 192.168.5.1
DHCP4.OPTION[6]:                        domain_name = private
DHCP4.OPTION[7]:                        domain_name_servers = 192.168.5.1
DHCP4.OPTION[8]:                        expiry = 1575029201
DHCP4.OPTION[9]:                        host_name = fedora31-2
DHCP4.OPTION[10]:                       ip_address = 192.168.5.252
DHCP4.OPTION[11]:                       next_server = 192.168.5.1
DHCP4.OPTION[12]:                       requested_broadcast_address = 1
DHCP4.OPTION[13]:                       requested_dhcp_server_identifier = 1
DHCP4.OPTION[14]:                       requested_domain_name = 1
DHCP4.OPTION[15]:                       requested_domain_name_servers = 1
DHCP4.OPTION[16]:                       requested_domain_search = 1
DHCP4.OPTION[17]:                       requested_host_name = 1
DHCP4.OPTION[18]:                       requested_interface_mtu = 1
DHCP4.OPTION[19]:                       requested_ms_classless_static_routes = 1
DHCP4.OPTION[20]:                       requested_nis_domain = 1
DHCP4.OPTION[21]:                       requested_nis_servers = 1
DHCP4.OPTION[22]:                       requested_ntp_servers = 1
DHCP4.OPTION[23]:                       requested_rfc3442_classless_static_routes = 1
DHCP4.OPTION[24]:                       requested_root_path = 1
DHCP4.OPTION[25]:                       requested_routers = 1
DHCP4.OPTION[26]:                       requested_static_routes = 1
DHCP4.OPTION[27]:                       requested_subnet_mask = 1
DHCP4.OPTION[28]:                       requested_time_offset = 1
DHCP4.OPTION[29]:                       requested_wpad = 1
DHCP4.OPTION[30]:                       routers = 192.168.5.1
DHCP4.OPTION[31]:                       subnet_mask = 255.255.255.0
```


### systemd-networkd

### Stopper NetworkManager
```
[root@fedora31-2 jonimofo]# systemctl stop NetworkManager
```
### Désactiver NetworkManager
```
[root@fedora31-2 jonimofo]# systemctl disable NetworkManager
Removed /etc/systemd/system/network-online.target.wants/NetworkManager-wait-online.service.
Removed /etc/systemd/system/multi-user.target.wants/NetworkManager.service.
Removed /etc/systemd/system/dbus-org.freedesktop.nm-dispatcher.service.
```
### Vérification
```
[root@fedora31-2 jonimofo]# systemctl status NetworkManager
● NetworkManager.service - Network Manager
   Loaded: loaded (/usr/lib/systemd/system/NetworkManager.service; disabled; vendor >
   Active: inactive (dead) since Fri 2019-11-29 11:18:42 UTC; 23s ago
     Docs: man:NetworkManager(8)
 Main PID: 792 (code=exited, status=0/SUCCESS)
```

### Activer systemd-networkd
```
[root@fedora31-2 jonimofo]# systemctl enable systemd-networkd
Created symlink /etc/systemd/system/dbus-org.freedesktop.network1.service → /usr/lib/systemd/system/systemd-networkd.service.
Created symlink /etc/systemd/system/multi-user.target.wants/systemd-networkd.service → /usr/lib/systemd/system/systemd-networkd.service.
Created symlink /etc/systemd/system/sockets.target.wants/systemd-networkd.socket → /usr/lib/systemd/system/systemd-networkd.socket.
Created symlink /etc/systemd/system/network-online.target.wants/systemd-networkd-wait-online.service → /usr/lib/systemd/system/systemd-networkd-wait-online.service.
```
### Démarrer systemd-networkd
```
[root@fedora31-2 jonimofo]# systemctl start systemd-networkd
```
### Vérification
```
[root@fedora31-2 jonimofo]# systemctl status systemd-networkd
● systemd-networkd.service - Network Service
   Loaded: loaded (/usr/lib/systemd/system/systemd-networkd.service; enabled; vendor>
   Active: active (running) since Fri 2019-11-29 11:21:22 UTC; 4s ago
     Docs: man:systemd-networkd.service(8)
 Main PID: 1351 (systemd-network)
   Status: "Processing requests..."
    Tasks: 1 (limit: 4685)
   Memory: 2.2M
   CGroup: /system.slice/systemd-networkd.service
           └─1351 /usr/lib/systemd/systemd-networkd
```



*Pour tester le bon fonctionnement de systemd-networkd, je crée une interface pointe sur "rien", histoire de ne pas me retrouver bloqué hors de ma vm*

### Création d'une interface

TODO
 ```

 ```




### systemd-resolved


### Activer le service de résolution de nom (maintenant ET au boot)
```
[root@fedora31-2 network]# systemctl enable systemd-resolved

Created symlink /etc/systemd/system/dbus-org.freedesktop.resolve1.service → /usr/lib/systemd/system/systemd-resolved.service.
Created symlink /etc/systemd/system/multi-user.target.wants/systemd-resolved.service → /usr/lib/systemd/system/systemd-resolved.service.

[root@fedora31-2 network]# systemctl start systemd-resolved
```

### Vérification du bon lancement du service
```
[root@fedora31-2 network]# systemctl status systemd-resolved

● systemd-resolved.service - Network Name Resolution
   Loaded: loaded (/usr/lib/systemd/system/systemd-resolved.service; enabled; vendor>
   Active: active (running) since Fri 2019-11-29 13:33:28 UTC; 2s ago
     Docs: man:systemd-resolved.service(8)
           https://www.freedesktop.org/wiki/Software/systemd/resolved
           https://www.freedesktop.org/wiki/Software/systemd/writing-network-configu>
           https://www.freedesktop.org/wiki/Software/systemd/writing-resolver-clients
 Main PID: 1937 (systemd-resolve)
   Status: "Processing requests..."
    Tasks: 1 (limit: 4685)
   Memory: 9.8M
   CGroup: /system.slice/systemd-resolved.service
           └─1937 /usr/lib/systemd/systemd-resolved
```

### Vérifier qu'un serveur DNS tourne localement et écoute sur un port de l'interface
```
[root@fedora31-2 network]# ss -laput | grep resolve

udp    UNCONN  0       0                 0.0.0.0:hostmon         0.0.0.0:*       users:(("systemd-resolve",pid=1937,fd=12))
udp    UNCONN  0       0           127.0.0.53%lo:domain          0.0.0.0:*       users:(("systemd-resolve",pid=1937,fd=18))
udp    UNCONN  0       0                    [::]:hostmon            [::]:*       users:(("systemd-resolve",pid=1937,fd=14))
tcp    LISTEN  0       128         127.0.0.53%lo:domain          0.0.0.0:*       users:(("systemd-resolve",pid=1937,fd=19))
tcp    LISTEN  0       128               0.0.0.0:hostmon         0.0.0.0:*       users:(("systemd-resolve",pid=1937,fd=13))
tcp    LISTEN  0       128                  [::]:hostmon            [::]:*       users:(("systemd-resolve",pid=1937,fd=15))
```
On remarque bien ici les adresses de loopback, avec le DNS écoutant sur le port 53 : 127.0.0.53%lo:domain.

### Quels sont les DNS utilisé par systemd-resolved ?
```
[root@fedora31-2 network]# resolvectl | grep "Current DNS"

  Current DNS Server:   
  Current DNS Server: 192.168.5.1
```
Le premier résultat correspond au DNS global, le deuxième au DNS per-link de "ens3", mon interface eth0.


Requête en utilisant spécifiquement le dns de systemd-resolved
```
[root@fedora31-2 network]# dig @192.168.5.1 +short lemonde.fr

151.101.194.217
```

Effectuer une requête DNS avec systemd-resolve
```
[root@fedora31-2 network]# systemd-resolve lemonde.fr

lemonde.fr: 151.101.194.217                    -- link: ens3

-- Information acquired via protocol DNS in 30.7ms.
-- Data is authenticated: no
```
On remarque ici que systemd-resolve affiche même le nom de l'interface liée. systemd-resolve permet donc de pouvoir attribuer un DNS à une interface donnée. Pratique.


### Remplacer /etc/resolv.conf par un lien symbolique pointant vers /run/systemd/resolve/stub-resolv.conf
```
[root@fedora31-2 network]# ls -la /etc/resolv.conf
-rw-r--r-- 1 root root 68 Nov 29 11:06 /etc/resolv.conf

[root@fedora31-2 network]# rm /etc/resolv.conf

[root@fedora31-2 network]# ln -s /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf

[root@fedora31-2 systemd]# cat $_ | grep -v '#'

nameserver 127.0.0.53
options edns0
```

### Modifier la configuration de systemd-resolved
Ici j'ajoute l'adresse de DNS 100.100.100.100 (une adresse bidon), simplement pour tester la bonne application des paramètres. 
```
[root@fedora31-2 network]# cat /etc/systemd/resolved.conf | grep -v "#" | grep DNS=

DNS=100.100.100.100
```


Je vérifie la bonne application.
```
[root@fedora31-2 network]# resolvectl | grep "DNS Servers"

         DNS Servers: 100.100.100.100
Fallback DNS Servers: 1.1.1.1
         DNS Servers: 192.168.5.1
```

### Mise en place de DNS over TLS

Avantages du DNS over TLS
* Chiffrement du trafic sur le port 853 (en DNS normal le trafic passe en clair)
* On reste en UDP, augmentant ainsi les performances réseau

#### TODO/LATER recenser les différences DNS/TLS et DNS/HTTPS + creuser la proposition de navigateur web DNS/HTTPS par Mozilla et autres.

On spécifie un DNS qui supporte le DNS over TLS 
```
[root@fedora31-2 network]# cat /etc/systemd/resolved.conf | grep -v '#'

[Resolve]
DNS=1.1.1.1
```


### Vérifier si le trafic DNS est bien over TLS (donc par le port 853)
```
[root@fedora31-2 network]# tcpdump -i ens3 -n -nn port 853

dropped privs to tcpdump
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on ens3, link-type EN10MB (Ethernet), capture size 262144 bytes
16:19:25.140199 IP 192.168.5.2.47782 > 1.1.1.1.853: Flags [S], seq 2910307107, win 64240, options [mss 1460,sackOK,TS val 1185824534 ecr 0,nop,wscale 7,exp-tfo cookiereq], length 0
16:19:25.141835 IP 1.1.1.1.853 > 192.168.5.2.47782: Flags [S.], seq 1196171328, ack 2910307108, win 29200, options [mss 1460,nop,nop,sackOK,nop,wscale 10], length 0
16:19:25.141877 IP 192.168.5.2.47782 > 1.1.1.1.853: Flags [.], ack 1, win 502, length 0
16:19:25.142252 IP 192.168.5.2.39288 > 192.168.5.1.853: Flags [S], seq 1017330122, win 64240, options [mss 1460,sackOK,TS val 864417411 ecr 0,nop,wscale 7,tfo  cookiereq,nop,nop], length 0
16:19:25.142362 IP 192.168.5.1.853 > 192.168.5.2.39288: Flags [R.], seq 0, ack 1017330123, win 0, length 0
16:19:25.142559 IP 192.168.5.2.47782 > 1.1.1.1.853: Flags [P.], seq 1:558, ack 1, win 502, length 557
```

**Ne pas oublier de flush le cache !**
`resolvectl flush-caches`
`resolvectl query google.com` ou `dig google.com @127.0.0.53`


#### Activer l'utilisation de DNSSEC

Le DNSSEC :

```
[root@fedora31-2 systemd]# resolvectl | grep DNSSEC

      DNSSEC setting: allow-downgrade
    DNSSEC supported: yes
          DNSSEC NTA: 10.in-addr.arpa
      DNSSEC setting: allow-downgrade
    DNSSEC supported: yes
```

#### TODO/LATER : quels tools utiliser pour vérifier que DNSSEC appliqué ? (à l'image de TCPDUMP pour le DNS over TLS)



## I.5. Gestion de sessions logind

Utilitaire qui permet d'envoyer des commandes de contrôle ou de requêter le login manager.

Permet de base de lister les sessions actives et leurs utilisateurs
```
[root@fedora31-2 jonimofo]# loginctl
SESSION  UID USER     SEAT TTY
     15 1000 fedora        pts/1
     17 1001 jonimofo      pts/0

2 sessions listed.
```

Permet également d'obtenir des informations détaillées à proposer du statut d'un utilisateur par exemple
```
[root@fedora31-2 jonimofo]# loginctl user-status jonimofo

jonimofo (1001)
           Since: Tue 2019-12-03 21:20:32 CET; 1h 44min ago
           State: active
        Sessions: *17
          Linger: no
            Unit: user-1001.slice
                  ├─session-17.scope
                  │ ├─10798 sshd: jonimofo [priv]
                  │ ├─10808 sshd: jonimofo@pts/0
                  │ ├─10809 -bash
                  │ ├─10902 sudo su
                  │ ├─10903 su
                  │ ├─10904 bash
                  │ ├─11057 loginctl user-status jonimofo
                  │ └─11058 less
                  └─user@1001.service
                    └─init.scope
                      ├─10801 /usr/lib/systemd/systemd --user
                      └─10803 (sd-pam)

Dec 03 21:20:32 fedora31-2 systemd[10801]: Reached target Basic System.
Dec 03 21:20:32 fedora31-2 systemd[10801]: Reached target Main User Target.
Dec 03 21:20:32 fedora31-2 systemd[10801]: Startup finished in 80ms.
Dec 03 21:22:37 fedora31-2 systemd[10801]: Starting Mark boot as successful...
Dec 03 21:22:37 fedora31-2 systemd[10801]: grub-boot-success.service: Succeeded.
Dec 03 21:22:37 fedora31-2 systemd[10801]: Started Mark boot as successful.
Dec 03 22:13:05 fedora31-2 sudo[10902]: jonimofo : TTY=pts/0 ; PWD=/home/jonimofo ; USER=root ; COMMAND=/usr/bin/su
Dec 03 22:13:05 fedora31-2 sudo[10902]: pam_unix(sudo:session): session opened for user root by jonimofo(uid=0)
Dec 03 22:13:05 fedora31-2 su[10903]: (to root) jonimofo on pts/0
Dec 03 22:13:05 fedora31-2 su[10903]: pam_unix(su:session): session opened for user root by jonimofo(uid=0)
```
On voit même ici la séquence d'ouverture de la session pour l'user jonimofo. Unix c'est chouette quand même !


Permet également de récupérer des informations sur un utilisateur qui a lancé une session
```
[root@fedora31-2 jonimofo]# loginctl show-user jonimofo

UID=1001
GID=1002
Name=jonimofo
Timestamp=Tue 2019-12-03 21:20:32 CET
TimestampMonotonic=198341719192
RuntimePath=/run/user/1001
Service=user@1001.service
Slice=user-1001.slice
Display=17
State=active
Sessions=17
IdleHint=no
IdleSinceHint=1575410729219983
IdleSinceHintMonotonic=204638933225
Linger=no
```
Ici encore des infos assez importantes concernant l'utilisateur : UID, GID, ID du Slice, etc...


### TODO/LATER me forcer à utiliser plus souvent cette commande pour récolter des infos.





## I.6. Gestion d'unit basique (services)*

`/usr/lib/systemd/system` contient tout un tas de services systemd mais pas que !
En fouillant un peu j'ai trouvé par exemple : 
```
[root@fedora31-2 jonimofo]# cat /usr/lib/systemd/system/ctrl-alt-del.target

[Unit]
Description=Reboot
Documentation=man:systemd.special(7)
DefaultDependencies=no
Requires=systemd-reboot.service
After=systemd-reboot.service
AllowIsolate=yes
JobTimeoutSec=30min
JobTimeoutAction=reboot-force

[Install]
Alias=ctrl-alt-del.target
```
Décidément, en effet sur Unix, TOUT est fichier !


Trouver l'unité associée au processus `chronyd`
```
[root@fedora31-2 jonimofo]# pidof chronyd

11228
```
*Merci à toi Léo de nous le faire désactiver juste avant et par là-même de me faire chercher (à une heure bien trop tardive) le pid d'uns service qui ne tournait plus. J'ai même réussi à me demander si un service qui était inactive pouvait quand même avoir un PID.*

#### TODO/LATER vérifier si un process prendra forcément le même PID à chaque fois. Si oui, pourquoi ? Si non, pourquoi ?

## II. Boot et Logs

Graphe de la séquence de boot

