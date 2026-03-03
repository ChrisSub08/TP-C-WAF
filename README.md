# TP dirigé de C - Préparation à l'examen - WAF middleware

## Objectifs

Les objectifs de ce TP sont multiples:

1. Préparer les étudiants à l'examen.
    1. Ouverture et lecture de fichier.
    2. Analyse d'une syntaxe simple.
    3. Création et utilisation de listes chainées.
2. Apprendre aux étudiants quelques concepts de sécurité.
    > Ce projet a été créé dans le cadre du projet CyberSkills.
3. Développement d'un outil pour créer des TPs de cybersécurité.
4. Développement d'un outil utilisable en production pour protéger des applicatifs à faible coûts.

## Sujet

L'exercice consiste à créer un WAF middleware sous forme de DLL/SharedObject pour protéger des applicatifs web.

> L'exercice est dirigé: organisé pour que les étudiants aient de l'aide au développement. L'aide doit leurs permettrent de trouver par eux même les solutions pour identifier et conceptualiser les méthodes qui répondent au sujet.

## Définitions

### **1. WAF (Web Application Firewall)**

Un **WAF**, ou **pare-feu d’application web**, est un dispositif de sécurité qui protège les applications web contre diverses attaques malveillantes. Contrairement à un pare-feu classique qui filtre le trafic réseau général, le WAF se concentre sur les **requêtes HTTP et HTTPS**.

**Fonctionnement :**

* Le WAF analyse chaque requête envoyée à l’application web et filtre les contenus suspects.
* Il peut bloquer ou signaler des attaques comme : injection SQL, cross-site scripting (XSS), falsification de requêtes côté serveur (CSRF), et autres vulnérabilités web courantes.
* Il peut être déployé en tant que **logiciel**, **appliance matérielle**, ou **service cloud**.

**Intérêt :**

* Protège l’application sans modifier son code.
* Permet de réagir rapidement face à de nouvelles menaces grâce à des règles de filtrage adaptatives.
* Améliore la sécurité globale tout en offrant des rapports détaillés sur les attaques bloquées.

---

### **2. Middleware**

Un **middleware** est un logiciel intermédiaire qui agit comme **interface entre deux systèmes ou applications**. Dans le contexte du développement web ou des architectures logicielles, il sert à **traiter les requêtes et réponses** avant qu’elles n’atteignent l’application principale ou après qu’elles en sortent.

**Fonctionnement :**

* Dans une application web, chaque requête HTTP peut passer par plusieurs middlewares avant d’atteindre la logique métier.
* Chaque middleware peut **modifier la requête ou la réponse**, gérer l’authentification, logger les informations, ou encore gérer les erreurs.

**Exemple concret :**

* Authentification : vérifier si l’utilisateur est connecté avant de lui donner accès à certaines routes.
* Logging : enregistrer toutes les requêtes entrantes pour analyse.
* Compression : compresser les réponses HTTP pour réduire la bande passante.

**Intérêt :**

* Modularité : on peut ajouter ou retirer des fonctionnalités sans toucher à l’application principale.
* Réutilisabilité : le même middleware peut servir pour plusieurs routes ou projets.
* Centralisation de certaines fonctions : sécurité, journalisation, traitement des erreurs, etc.

### **3. DLL / Shared Object (Bibliothèques Dynamiques)**

Une **DLL (Dynamic Link Library)** sur Windows ou un **Shared Object (.so)** sur Linux est un fichier contenant du code et des ressources **réutilisables par plusieurs programmes** sans avoir à les inclure directement dans chaque application.

**Fonctionnement :**

* Au lieu de compiler tout le code dans un exécutable, certaines fonctions ou modules sont stockés dans ces bibliothèques.
* Lors de l’exécution, le système charge ces bibliothèques en mémoire et les programmes peuvent **appeler leurs fonctions** comme si elles faisaient partie du code principal.
* Les bibliothèques peuvent être partagées par plusieurs applications simultanément, ce qui réduit l’espace disque et la mémoire utilisés.

**Exemple concret :**

* Les systèmes d’exploitation fournissent des DLL/.so pour gérer des tâches courantes : accès aux fichiers, manipulation d’images, communication réseau, etc.
* Un jeu vidéo peut utiliser une DLL pour le moteur physique afin que plusieurs jeux puissent utiliser le même moteur sans le réécrire.

**Avantages :**

* **Réutilisabilité** : un même module peut être utilisé par plusieurs programmes.
* **Modularité** : on peut mettre à jour la bibliothèque sans recompiler l’ensemble de l’application.
* **Économie de ressources** : plusieurs programmes peuvent partager une seule copie en mémoire.

**Inconvénients / précautions :**

* Si la DLL/.so est manquante ou incompatible, le programme peut ne pas fonctionner (problème de “DLL Hell”).
* Nécessite de bien gérer les versions pour éviter des conflits entre applications.

## Consignes

> Les consignes sont reprisent du sujet d'examen.

Aucun document n'est autorisé à l'exception de ceux fournis avec cet énoncé sous forme
électronique:
1. Consignes préliminaires pour effectuer cet examen: *consignesEleves-amont.pdf*. Nous vous recommandons de suivre strictement les recommandations de ce document.
2. Rappels de la syntaxe du langage C: *CheatSheet-LangageC.pdf*.

## Conseils pour réussir cet exercice

 - N'hésitez pas à utiliser la commande `man` qui donne les documentations d'utilisation des éléments externes à vos développements.
 - Bien lire et comprendre le sujet.

## Fichiers fournis

La totalité des fichiers du projet à rendre se trouvent dans le fichier `tar.gz` ci-joint.

 - Le fichier `Makefile` sert à gérer la construction du projet. Il contient les règles et les dépendances pour compiler vos fichiers sources et générer l'exécutable. Il permet de produire le fichier exécutable `./main` ainsi que la bibliothèque `./libwaf.so`. Le fichier `Makefile` est *pour lecture seule*. **Il ne doit pas être modifié !**
 - Le fichier d'entête `waf.h` contient la déclaration des fonctions à écrire, les macros et les définitions partagées par les différents fichiers C. Ce fichier est également *pour lecture seule*. **Il ne doit pas être modifié !**
 - Le fichier `main.c` contient le code pour lancer et tester le bon fonctionnement du projet. Ce fichier est également *pour lecture seule*. **Il ne doit pas être modifié !**
 - Le fichier `rule.conf` contient des règles de détection pour configurer le WAF. Il permet au projet de pouvoir utiliser votre code dans un contexte plus réaliste avec des résultats d'opérations différenciables. Ce fichier est également *pour lecture seule*. **Il ne doit pas être modifié !**
 - Il est demandé d'écrire votre code dans le fichier `waf.c`. Il s'agit de l'implémentation des fonctions pré-déclarées dans le fichier `waf.c`. Certaines fonctions sont fournis vides (signature seule sans implémentation). Il vous est demandé de modifier ces fonctions pour réaliser le projet.

Pour rappel, **seul le fichier `waf.c` doit être modifié**. Le `Makefile` et le fichier de header `waf.h` doivent être conservés *en lecture seule* afin de garantir l'intégrité du projet.

## Sujet de l'exercice

Pour cet exercice, il vous est demandé d'implémenter les fonctions qui sont détaillées dans le fichier de code `waf.c`. Vous y trouverez notamment la spécification des entrées et des sorties de chacune des fonctions attendues.

## Outils

 - `man`
 - `ls`
 - `cd`
 - `tar`
 - `mv`
 - `gedit`
 - `make`
 - `gcc`
 - `curl`
 - `wget`

## Compilation et lancement

```
┌──(kali㉿kali)-[/mnt/kali]
└─$ make
gcc -Wall -O2 -fPIC -pthread -c waf.c -o waf.o
waf.c:43:13: warning: ‘print_rule’ defined but not used [-Wunused-function]
   43 | static void print_rule(Rule* rule) {
      |             ^~~~~~~~~~
gcc -shared -o libwaf.so waf.o
gcc -Wall -O2 -fPIC -pthread -c main.c -o main.o
gcc -o main main.o -L. -lwaf

┌──(kali㉿kali)-[/mnt/kali]
└─$ make run
Test 1: POST /admin, SQL injection, local address
 -> Score: 0
 -> Action: ALLOW

Test 2: GET /public, public address
 -> Score: 0
 -> Action: ALLOW

Test 3: POST /login, public address
 -> Score: 0
 -> Action: ALLOW

Test 4: POST /admin, public address
 -> Score: 20
 -> Action: BLOCK

Test 5: GET /index.php, public address
 -> Score: 0
 -> Action: ALLOW

Test 6: POST /login, host localhost, public address
 -> Score: 12
 -> Action: BLOCK

Test 7: POST /admin, localhost
 -> Score: 0
 -> Action: ALLOW

Test 8: POST /xmlrpc.php, public address
 -> Score: 15
 -> Action: BLOCK

Test 9: GET /default.aspx, public address
 -> Score: 5
 -> Action: ALERT

Test 10: GET /style.css, public address
 -> Score: 0
 -> Action: ALLOW

Test 11: GET /image.jpg, public address
 -> Score: 0
 -> Action: ALLOW

Test 12: POST /login, query XSS, public address
 -> Score: 10
 -> Action: BLOCK

Test 13: POST /login, body SQLi, public address
 -> Score: 15
 -> Action: BLOCK

Test 14: POST /cmd, body command injection, public address
 -> Score: 15
 -> Action: BLOCK

Test 15: POST /webshell.php, body PHP webshell, public address
 -> Score: 20
 -> Action: BLOCK

Test 16: POST /login, SQLMap User-Agent, public address
 -> Score: 15
 -> Action: BLOCK

Test 17: POST /login, Nikto User-Agent, public address
 -> Score: 10
 -> Action: BLOCK

Test 16: POST /login, Metasploit User-Agent, public address
 -> Score: 15
 -> Action: BLOCK


┌──(kali㉿kali)-[/mnt/kali]
└─$ 
```

## Credits

Auteur: Christophe SUBLET  
Organisation: Esisar  
Sponsors: CyberSkills
