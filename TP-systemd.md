# TP Systemd

## I.1. First steps

### Vérifier version de systemd
```
[root@fedora31-2 ~]$ systemctl --version

systemd 243 (v243.4-1.fc31)
+PAM +AUDIT +SELINUX +IMA -APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD +IDN2 -IDN +PCRE2 default-hierarchy=unified
```
 TODO : décrire brièvement les autres processus système !! Attention : ne sont pas des kernels process, ces derniers sont listés entre []


## I.2. Gestion du temps
```
[root@fedora31-2 ~]$ timedatectl
               Local time: Fri 2019-11-29 09:54:48 UTC
           Universal time: Fri 2019-11-29 09:54:48 UTC
                 RTC time: Fri 2019-11-29 09:54:47
                Time zone: Etc/UTC (UTC, +0000)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no
```

### Différence entre Local Time, Universal Time, RTC Time
* Local Time
* Universal Time
* RTC Time

TODO


## I.3. Gestion des noms

[Doc Redhat gestion des hostnames](https://access.redhat.com/documentation/fr-fr/red_hat_enterprise_linux/7/html/networking_guide/sec_configuring_host_names_using_hostnamectl)

`--static`
`--transient`
`--pretty` Les espaces seront remplacés par des « - » et les caractères spéciaux seront supprimés.


```
[jonimofo@fedora31-2 ~]$ sudo hostnamectl set-hostname "mofo's laptop" --pretty

[root@fedora31-2 jonimofo]# hostnamectl
   Static hostname: fedora31-2
   Pretty hostname: mofo's laptop
         Icon name: computer-vm
```
TODO


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

TODO : comment vérifier que c'est bien appliqué ?



### 
```
```