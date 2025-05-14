# README — ICMP C2 Framework furtif (Agent + Serveur)

Ce projet est une preuve de concept (PoC) de Command & Control (**C2**) furtif basé sur le protocole **ICMP** (ping), écrit en **C#**. Il permet de :

* Effectuer du **beaconing** discret
* Envoyer dynamiquement des **modules chiffrés RC4**
* Exécuter les modules **en mémoire** (sans écriture disque)
* Retourner les résultats à l’attaquant via ICMP

Ce projet peut être l’étape 2 d’une attaque Red Team, après compromission initiale (via phishing, vulnérabilité, etc.)

> ⚠️ Utilisation uniquement en environnement LAB contrôlé, à des fins de recherche ou red teaming autorisé.

---
📁 RedTeamC2/
├── HttpC2Agent.cs       ⇨ L'agent à déployer sur la machine cible (beacon + loader)
├── HttpC2Server.cs      ⇨ Le serveur C2 (réception des beacons + envoi de modules)
├── ModuleBuilder.cs     ⇨ Générateur de module (compile et chiffre avec RC4)
├── Module1.cs           ⇨ Exemple de module offensif à personnaliser (méthode Run)
├── module.enc           ⇨ Module chiffré généré par ModuleBuilder.cs (servi par le C2)
├── README.md            ⇨ Instructions d’utilisation, compilation, exécution

## Fonctionnement

1. **L'agent** (à déployer sur une cible) envoie périodiquement un **Echo Request ICMP** contenant le mot-clé `BEACON`
2. **Le serveur C2** répond avec un module .NET chiffré RC4 dans l'Echo Reply
3. L'agent **charge le module en mémoire**, exécute la méthode `Run()`
4. L'output (200 premiers caractères) est envoyé au C2 dans un nouveau ping ICMP

---

## Compilation

Requiert : Visual Studio / dotnet CLI / .NET Framework 4.7+ ou .NET 6+

### Projet 1 : Agent (ICMPAgent.cs)

```bash
csc /out:ICMPAgent.exe ICMPAgent.cs
```

* Modifier `<C2_IP_HERE>` par l'IP du serveur dans le code

### Projet 2 : Serveur (ICMPC2Server.cs)

```bash
csc /out:ICMPC2Server.exe ICMPC2Server.cs
```

* ⚠️ Exécutez **en administrateur** (raw socket requis)

---

##  Génération d'un module

Exemple simple :

```csharp
// Module1.cs
public class Module1 {
    public static void Run() {
        Console.WriteLine(System.Environment.UserName);
    }
}
```

Compilez en DLL :

```bash
csc /target:library /out:Module1.dll Module1.cs
```

Chiffrez avec RC4 :

```csharp
byte[] raw = File.ReadAllBytes("Module1.dll");
byte[] encrypted = RC4(raw, Encoding.ASCII.GetBytes("MySecretKey123"));
File.WriteAllBytes("module.enc", encrypted);
```

Placez `module.enc` dans le dossier du serveur.

---

## Clés partagées / Configuration

* **RC4 Key** : `MySecretKey123`
* **Ping timeout** : 4000ms
* **Beacon interval** : 30 secondes
* **Payload max** : 200 caractères en retour

---

## Améliorations possibles

* [ ] Ajout d'un chiffrement plus fort (AES, ECC)
* [ ] Gestion multiple agents (UUID par beacon)
* [ ] Compression des payloads (Gzip, LZ4)
* [ ] Encodage custom des paquets (base64, binaire)
* [ ] Modules polymorphes / in-memory plugin loader

---

## Exemple de flux (Wireshark)

* `Echo Request`: `BEACON`
* `Echo Reply`: payload RC4 chiffré
* `Echo Request`: output de Run()

Filtre Wireshark :

```wireshark
icmp && ip.src == [agent IP]
```

---

## ⚡ Attention juridique

Ce projet est à but éducatif. Toute utilisation sur des systèmes sans autorisation explicite est **illégale**.


---

## Limitations

* ICMP ne traverse pas toujours les réseaux NAT ou proxys
* Peut être bloqué par des firewalls ou antivirus
* Paquets ICMP limités en taille (512-1024 bytes typique)

### Alternative recommandée : passer à HTTP/HTTPS C2

* Routable sur tous les réseaux (même NATés)
* Discret si mimique du trafic légitime
* Compatible avec beaconing + transfert de modules
* Possibilité d’utiliser `User-Agent` personnalisés, headers falsifiés, etc.

Voir future version HTTP C2 du projet

---

## Prochaine évolution ?

* [ ] Intégrer ce loader dans ton agent furtif StealthRedTeamTool
* [ ] Passer à une infra HTTP over DNS
* [ ] Ajouter un chiffrement asymétrique (RSA handshake)
