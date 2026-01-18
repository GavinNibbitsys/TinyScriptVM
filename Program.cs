using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Net.Http;
using System.Net.NetworkInformation;

namespace TinyCS_VM
{
    public enum OpCode : byte
    {
        HALT = 0, LOAD = 1, ADD = 2, SUB = 3, STORE = 4, JMP = 5, JIF = 6, JZ = 7,
        PRINT_VAL = 16, PRINT_CHAR = 17, PRINT_STR = 19, INPUT_STR = 20, INPUT_INT = 25,
        SET_BUF = 29, CMD_CHECK = 30,
        FILE_LIST = 40, FILE_CREATE = 41, FILE_DELETE = 42, FILE_READ = 43, FILE_EXEC = 44,
        MAKE_NOTE = 45, SCRAMBLE_FILE = 46, SYS_INFO = 50, CLEAR_SCR = 60,
        NET_PING = 70, NET_GET = 71
    }

    public class VirtualMachine
    {
        private byte[] _memory = new byte[65536]; // 64KB Memory
        private int[] _registers = new int[4];
        private int _ip = 0;
        public string StringBuffer = "";
        public bool ShouldLoadNewProgram = false;
        
        // STORAGE: Strictly uses "Vhdd" folder for data
        private string VhddPath = Path.Combine(Directory.GetCurrentDirectory(), "Vhdd");
        private Random _rng = new Random();
        private static readonly HttpClient _httpClient = new HttpClient();

        public VirtualMachine()
        {
            if (!Directory.Exists(VhddPath)) Directory.CreateDirectory(VhddPath);
        }

        // --- SECURITY HELPER: THE SANDBOX ---
        private bool GetSafePath(string filename, out string fullPath)
        {
            fullPath = null;
            if (string.IsNullOrWhiteSpace(filename)) return false;

            // 1. Resolve the absolute path
            string potentialPath = Path.Combine(VhddPath, filename);
            string resolvedPath = Path.GetFullPath(potentialPath);

            // 2. Ensure it starts with the Vhdd folder path
            string vhddAbs = Path.GetFullPath(VhddPath);
            
            if (resolvedPath.StartsWith(vhddAbs, StringComparison.OrdinalIgnoreCase))
            {
                fullPath = resolvedPath;
                return true;
            }

            return false; // Access Denied
        }

        public void Run(byte[] program)
        {
            Array.Clear(_memory, 0, _memory.Length);
            Array.Clear(_registers, 0, _registers.Length);
            if (program.Length == 0) return;

            Array.Copy(program, _memory, program.Length);
            _ip = 0;
            bool running = true;
            ShouldLoadNewProgram = false;

            try
            {
                while (running && _ip < _memory.Length)
                {
                    byte instruction = _memory[_ip++];
                    switch ((OpCode)instruction)
                    {
                        case OpCode.HALT: running = false; break;
                        case OpCode.LOAD: int rL = ReadReg(); _registers[rL] = _memory[_ip++]; break;
                        case OpCode.ADD: int rA = ReadReg(); _registers[rA] += _registers[ReadReg()]; break;
                        case OpCode.SUB: int rS = ReadReg(); _registers[rS] -= _registers[ReadReg()]; break;
                        case OpCode.STORE:
                            int addrReg = ReadReg(); int valReg = ReadReg(); int targetAddress = _registers[addrReg];
                            if (targetAddress < 0 || targetAddress >= _memory.Length) throw new Exception($"SegFault: {targetAddress}");
                            _memory[targetAddress] = (byte)_registers[valReg]; break;
                        case OpCode.JMP: _ip = ReadAddress(); break;
                        case OpCode.JIF: { int t = ReadAddress(); if (_registers[0] > 0) _ip = t; } break;
                        case OpCode.JZ: { int t = ReadAddress(); if (_registers[0] == 0) _ip = t; } break;
                        
                        case OpCode.PRINT_VAL: Console.Write(_registers[ReadReg()]); break;
                        case OpCode.PRINT_CHAR: Console.Write((char)_registers[ReadReg()]); break;
                        case OpCode.PRINT_STR: Console.Write(StringBuffer); break;
                        case OpCode.INPUT_STR: StringBuffer = Console.ReadLine() ?? ""; break;
                        case OpCode.SET_BUF:
                            int sLen = _memory[_ip++]; string sVal = "";
                            for (int i = 0; i < sLen; i++) sVal += (char)_memory[_ip++];
                            StringBuffer = sVal; break;
                        case OpCode.INPUT_INT:
                            int rInt = ReadReg();
                            string rawInput = Console.ReadLine() ?? "";
                            if (int.TryParse(rawInput, out int parsedInt)) 
                                _registers[rInt] = parsedInt;
                            else 
                                _registers[rInt] = 0; 
                            break;
                        
                        case OpCode.CMD_CHECK:
                            int strLen = _memory[_ip++]; string cmd = "";
                            for (int i = 0; i < strLen; i++) cmd += (char)_memory[_ip++];
                            int jumpTarget = ReadAddress();
                            string input = StringBuffer.Trim();
                            // Case-insensitive check, handles arguments (e.g. "cat file.txt")
                            if (input.Equals(cmd, StringComparison.OrdinalIgnoreCase) || input.StartsWith(cmd + " ", StringComparison.OrdinalIgnoreCase))
                            {
                                if (input.Length > cmd.Length) StringBuffer = input.Substring(cmd.Length).Trim(); else StringBuffer = "";
                                _ip = jumpTarget;
                            }
                            break;

                        // --- DISK OPERATIONS (SECURED) ---
                        case OpCode.FILE_LIST:
                            Console.WriteLine("\n--- VHDD STORAGE ---");
                            foreach (var f in Directory.GetFiles(VhddPath)) Console.WriteLine($" [DATA] {Path.GetFileName(f)}");
                            Console.WriteLine("--------------------"); break;

                        case OpCode.FILE_CREATE:
                            if (!string.IsNullOrEmpty(StringBuffer)) 
                            {
                                if (GetSafePath(StringBuffer, out string pathCreate))
                                    File.WriteAllText(pathCreate, "Empty Object");
                                else
                                    Console.WriteLine("[SEC_ERR] Access Denied: Path outside sandbox.");
                            }
                            break;

                        case OpCode.FILE_DELETE:
                            if (GetSafePath(StringBuffer, out string pathDel) && File.Exists(pathDel))
                            {
                                File.Delete(pathDel); 
                                Console.WriteLine($"[SYSTEM]: Deleted {StringBuffer}");
                            }
                            else
                            {
                                Console.WriteLine("[SEC_ERR] File not found or Access Denied.");
                            }
                            break;

                        case OpCode.FILE_READ:
                            if (GetSafePath(StringBuffer, out string pathRead) && File.Exists(pathRead))
                                StringBuffer = File.ReadAllText(pathRead);
                            else 
                                StringBuffer = "Error: File not found or Access Denied."; 
                            break;
                        
                        // EXEC: Stops VM so Main can load a new script
                        case OpCode.FILE_EXEC:
                            running = false; ShouldLoadNewProgram = true; break;

                        case OpCode.MAKE_NOTE:
                            Console.WriteLine("\n--- NOTE CREATOR ---"); 
                            Console.Write("Filename: ");
                            string name = Console.ReadLine(); 
                            Console.Write("Content: "); 
                            string content = Console.ReadLine();
                            
                            if (GetSafePath(name, out string safeNotePath)) { 
                                File.WriteAllText(safeNotePath, content); 
                                Console.WriteLine("Saved to Vhdd."); 
                            } 
                            else {
                                Console.WriteLine("[SEC_ERR] Invalid filename.");
                            }
                            break;

                        case OpCode.SYS_INFO: StringBuffer = $"Host: TinyVM | OS: RevertOS | Mem: {_memory.Length}b | Secure: YES"; break;
                        
                        case OpCode.SCRAMBLE_FILE:
                            string target = StringBuffer.Trim();
                            if (target == "(ALL)")
                            {
                                var files = Directory.GetFiles(VhddPath);
                                foreach (var f in files) { CorruptFile(f); Console.WriteLine($" -> Corrupted: {Path.GetFileName(f)}"); }
                            }
                            else
                            {
                                if (GetSafePath(target, out string safeScramblePath) && File.Exists(safeScramblePath)) {
                                    CorruptFile(safeScramblePath); 
                                    Console.WriteLine($" -> Corrupted: {target}");
                                }
                                else {
                                    Console.WriteLine("[SEC_ERR] File not found or Access Denied.");
                                }
                            }
                            break;

                        case OpCode.CLEAR_SCR: Console.Clear(); break;

                        // --- NETWORK (FIXED) ---
                        case OpCode.NET_PING:
                            if (string.IsNullOrWhiteSpace(StringBuffer)) { Console.WriteLine("Ping Error: No host."); break; }
                            try 
                            { 
                                using (Ping p = new Ping()) {
                                    Console.Write($"Pinging {StringBuffer}... "); 
                                    PingReply reply = p.Send(StringBuffer, 2000); // 2s Timeout
                                    if (reply.Status == IPStatus.Success) Console.WriteLine($"[ONLINE] {reply.RoundtripTime}ms"); 
                                    else Console.WriteLine($"[OFFLINE] ({reply.Status})"); 
                                }
                            } 
                            catch { Console.WriteLine("[ERROR] Host Unreachable"); } 
                            break;

                        case OpCode.NET_GET:
                            try 
                            { 
                                Console.WriteLine($"Downloading from {StringBuffer}..."); 
                                // Basic cleanup to ensure protocol exists
                                string url = StringBuffer.StartsWith("http") ? StringBuffer : "http://" + StringBuffer;
                                string webContent = _httpClient.GetStringAsync(url).GetAwaiter().GetResult(); 
                                if (webContent.Length > 4000) webContent = webContent.Substring(0, 4000) + "\n...[TRUNCATED]"; 
                                StringBuffer = webContent; 
                                Console.WriteLine("Download Complete."); 
                            } 
                            catch (Exception ex) { Console.WriteLine($"[NET ERROR]: {ex.Message}"); StringBuffer = "Error"; } 
                            break;

                        default: throw new Exception($"Illegal OpCode {_memory[_ip - 1]}");
                    }
                }
            }
            catch (Exception ex) { Console.ForegroundColor = ConsoleColor.Red; Console.WriteLine($"\n[KERNEL PANIC]: {ex.Message}"); Console.ResetColor(); Console.ReadLine(); }
        }

        private void CorruptFile(string path) { string garbage = ""; for (int i = 0; i < 100; i++) garbage += (char)_rng.Next(33, 126); File.WriteAllText(path, garbage + "\n[CORRUPTED]"); }
        private int ReadReg() { byte r = _memory[_ip++]; if (r >= _registers.Length) throw new Exception("Reg Error"); return r; }
        private int ReadAddress() { byte high = _memory[_ip++]; byte low = _memory[_ip++]; return (high << 8) | low; }
    }

    public static class Compiler
    {
        public static byte[] Compile(string path)
        {
            if (!File.Exists(path)) return new byte[0];
            string[] source = File.ReadAllLines(path);
            List<byte> bytecode = new List<byte>();
            Dictionary<string, int> labels = new Dictionary<string, int>();
            Dictionary<int, string> jumpFixups = new Dictionary<int, string>();
            int ParseReg(string s) => int.Parse(s.ToUpper().Replace("R", "").Trim());
            void AddJumpPlaceholder(string label) { jumpFixups[bytecode.Count] = label; bytecode.Add(0); bytecode.Add(0); }

            foreach (string line in source)
            {
                string clean = line.Split(new[] { "//" }, StringSplitOptions.None)[0].Trim();
                if (string.IsNullOrEmpty(clean)) continue;
                if (clean.EndsWith(":")) { labels[clean.TrimEnd(':')] = bytecode.Count; continue; }
                var parts = Regex.Matches(clean, @"[\""].+?[\""]|[^ ]+").Cast<Match>().Select(m => m.Value).ToArray();
                string cmd = parts[0].ToUpper();

                try
                {
                    if (cmd == "PRINT") { string text = parts[1].Trim('"'); foreach (char c in text) { bytecode.Add((byte)OpCode.LOAD); bytecode.Add(3); bytecode.Add((byte)c); bytecode.Add((byte)OpCode.PRINT_CHAR); bytecode.Add(3); } }
                    else if (cmd == "PRINT_LINE") { bytecode.Add((byte)OpCode.LOAD); bytecode.Add(3); bytecode.Add(10); bytecode.Add((byte)OpCode.PRINT_CHAR); bytecode.Add(3); }
                    else if (cmd == "SET") { bytecode.Add((byte)OpCode.LOAD); bytecode.Add((byte)ParseReg(parts[1])); bytecode.Add(byte.Parse(parts[2])); }
                    else if (cmd == "GOTO") { bytecode.Add((byte)OpCode.JMP); AddJumpPlaceholder(parts[1]); }
                    else if (cmd == "CMD") { bytecode.Add((byte)OpCode.CMD_CHECK); string val = parts[1].Trim('"'); bytecode.Add((byte)val.Length); foreach (char c in val) bytecode.Add((byte)c); AddJumpPlaceholder(parts[2]); }
                    else if (cmd == "EXIT") { bytecode.Add((byte)OpCode.HALT); }
                    else if (cmd == "INPUT_STRING") { bytecode.Add((byte)OpCode.INPUT_STR); }
                    else if (cmd == "VIEW") bytecode.Add((byte)OpCode.FILE_LIST);
                    else if (cmd == "VOID") bytecode.Add((byte)OpCode.FILE_DELETE);
                    else if (cmd == "REVEAL") bytecode.Add((byte)OpCode.FILE_READ);
                    else if (cmd == "EXEC") bytecode.Add((byte)OpCode.FILE_EXEC);
                    else if (cmd == "IDENTITY") bytecode.Add((byte)OpCode.SYS_INFO);
                    else if (cmd == "PRINT_BUF") bytecode.Add((byte)OpCode.PRINT_STR);
                    else if (cmd == "INPUT_NUM") { bytecode.Add((byte)OpCode.INPUT_INT); bytecode.Add((byte)ParseReg(parts[1])); }
                    else if (cmd == "WRITE_NOTE") { bytecode.Add((byte)OpCode.MAKE_NOTE); }
                    else if (cmd == "SUB") { bytecode.Add((byte)OpCode.SUB); bytecode.Add((byte)ParseReg(parts[1])); bytecode.Add((byte)ParseReg(parts[2])); }
                    else if (cmd == "ADD") { bytecode.Add((byte)OpCode.ADD); bytecode.Add((byte)ParseReg(parts[1])); bytecode.Add((byte)ParseReg(parts[2])); }
                    else if (cmd == "STRING") { bytecode.Add((byte)OpCode.SET_BUF); string val = parts[1].Trim('"'); bytecode.Add((byte)val.Length); foreach (char c in val) bytecode.Add((byte)c); }
                    else if (cmd == "RAM_WRITE") { bytecode.Add((byte)OpCode.STORE); bytecode.Add((byte)ParseReg(parts[1])); bytecode.Add((byte)ParseReg(parts[2])); }
                    else if (cmd == "SCRAMBLE") { bytecode.Add((byte)OpCode.SCRAMBLE_FILE); }
                    else if (cmd == "CLS") { bytecode.Add((byte)OpCode.CLEAR_SCR); }
                    else if (cmd == "PRINT_REG") { bytecode.Add((byte)OpCode.PRINT_VAL); bytecode.Add((byte)ParseReg(parts[1])); }
                    else if (cmd == "PING") { bytecode.Add((byte)OpCode.NET_PING); }
                    else if (cmd == "DOWNLOAD") { bytecode.Add((byte)OpCode.NET_GET); }
                }
                catch { return new byte[0]; }
            }
            foreach (var fix in jumpFixups) { if (labels.ContainsKey(fix.Value)) { int target = labels[fix.Value]; bytecode[fix.Key] = (byte)(target >> 8); bytecode[fix.Key + 1] = (byte)(target & 0xFF); } }
            return bytecode.ToArray();
        }
    }

    class Program
    {
        static void Main(string[] args)
        {
            string rootDir = Directory.GetCurrentDirectory();
            string vhddDir = Path.Combine(rootDir, "Vhdd");

            if (!Directory.Exists(vhddDir)) Directory.CreateDirectory(vhddDir);

            VirtualMachine vm = new VirtualMachine();
            string currentProgram = "";

            // --- BOOTLOADER: Look for OS in Root only ---
            // Prioritizes "neos.tiny", then "os.tiny", then anything else.
            if (File.Exists(Path.Combine(rootDir, "neos.tiny"))) currentProgram = Path.Combine(rootDir, "neos.tiny");
            else if (File.Exists(Path.Combine(rootDir, "os.tiny"))) currentProgram = Path.Combine(rootDir, "os.tiny");
            else 
            {
                string[] osFiles = Directory.GetFiles(rootDir, "*.tiny");
                if (osFiles.Length > 0) currentProgram = osFiles[0];
                else { Console.WriteLine("[Boot Error]: No .tiny file found in Root."); return; }
            }

            while (true)
            {
                vm.Run(Compiler.Compile(currentProgram));

                // --- EXEC COMMAND HANDLER ---
                if (vm.ShouldLoadNewProgram)
                {
                    string requestedFile = vm.StringBuffer.Trim(); 
                    if (requestedFile.ToLower() == "exit") break;

                    string pathRoot = Path.Combine(rootDir, requestedFile);
                    string pathVhdd = Path.Combine(vhddDir, requestedFile);

                    // Note: This logic allows loading scripts from Root (System Files) or Vhdd (User Files)
                    if (File.Exists(pathRoot)) { currentProgram = pathRoot; Console.Clear(); }
                    else if (File.Exists(pathVhdd)) { currentProgram = pathVhdd; Console.Clear(); }
                    else
                    {
                        Console.WriteLine($"\n[System Error]: File '{requestedFile}' not found.");
                        Console.WriteLine("Press any key to return to OS...");
                        Console.ReadKey();
                        // Loop continues, reloading the last valid 'currentProgram'
                    }
                }
                else
                {
                    break;
                }
            }
        }
    }
}
