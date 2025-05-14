// Module1.cs
// Exemple de module à charger dynamiquement

using System;

public class Module1
{
    public static void Run()
    {
        Console.WriteLine("[+] Module exécuté !");
        Console.WriteLine("Utilisateur : " + Environment.UserName);
        Console.WriteLine("Machine : " + Environment.MachineName);
    }
}
