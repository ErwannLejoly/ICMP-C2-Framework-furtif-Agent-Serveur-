// ModuleBuilder.cs
// Compile Module1.cs en DLL, chiffre avec RC4, sort module.enc

using System;
using System.Diagnostics;
using System.IO;
using System.Text;

class ModuleBuilder
{
    static void Main()
    {
        string src = "Module1.cs";
        string dll = "Module1.dll";
        string outFile = "module.enc";
        string key = "MySecretKey123";

        Console.WriteLine("[+] Compilation en cours...");
        Process.Start("csc", $"/target:library /out:{dll} {src}")?.WaitForExit();

        if (!File.Exists(dll))
        {
            Console.WriteLine("[-] Compilation échouée.");
            return;
        }

        Console.WriteLine("[+] Chiffrement RC4...");
        byte[] raw = File.ReadAllBytes(dll);
        byte[] enc = RC4(raw, Encoding.ASCII.GetBytes(key));
        File.WriteAllBytes(outFile, enc);
        Console.WriteLine($"[+] {outFile} prêt pour le C2.");
    }

    static byte[] RC4(byte[] data, byte[] key)
    {
        byte[] s = new byte[256];
        for (int i = 0; i < 256; i++) s[i] = (byte)i;
        int j = 0;
        for (int i = 0; i < 256; i++)
        {
            j = (j + s[i] + key[i % key.Length]) & 255;
            (s[i], s[j]) = (s[j], s[i]);
        }
        int a = 0, b = 0;
        byte[] result = new byte[data.Length];
        for (int k = 0; k < data.Length; k++)
        {
            a = (a + 1) & 255;
            b = (b + s[a]) & 255;
            (s[a], s[b]) = (s[b], s[a]);
            result[k] = (byte)(data[k] ^ s[(s[a] + s[b]) & 255]);
        }
        return result;
    }
}
