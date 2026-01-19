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
        MUL = 8, DIV = 9, 
        PRINT_VAL = 16, PRINT_CHAR = 17, PRINT_STR = 19, INPUT_STR = 20, INPUT_INT = 25,
        SET_BUF = 29, CMD_CHECK = 30,
        FILE_LIST = 40, FILE_CREATE = 41, FILE_DELETE = 42, FILE_READ = 43, FILE_EXEC = 44,
        MAKE_NOTE = 45, SCRAMBLE_FILE = 46, FILE_WRITE = 47,
        
        // --- CLIPBOARD OPCODES ---
        BUF_COPY = 21,    
        FILE_SAVE_AS = 48,

        SYS_INFO = 50, CLEAR_SCR = 60,
        NET_PING = 70, NET_GET = 71
    }

    public class VirtualMachine
    {
        private byte[] _memory = new byte[65536]; 
        private int[] _registers = new int[4];
        private int _ip = 0;
        public string StringBuffer = "";
        
        // Internal Clipboard
        private string _clipboard = ""; 
        
        public bool ShouldLoadNewProgram = false;
        private string VhddPath = Path.Combine(Directory.GetCurrentDirectory(), "Vhdd");
        private Random _rng = new Random();
        private static readonly HttpClient _httpClient = new HttpClient();

        public VirtualMachine()
        {
            if (!Directory.Exists(VhddPath)) Directory.CreateDirectory(VhddPath);
        }

        // --- UPDATED SECURITY SANDBOX ---
        private bool GetSafePath(string filename, out string fullPath)
        {
            fullPath = string.Empty;
            if (string.IsNullOrWhiteSpace(filename)) return false;

            try 
            {
                // 1. EXTENSION WHITELIST CHECK
                // Only allow specific safe file types.
                string ext = Path.GetExtension(filename).ToLower();
                string[] allowedExtensions = { ".json", ".txt", ".tiny" };

                if (!allowedExtensions.Contains(ext))
                {
                    // Console.WriteLine($"[SEC_BLOCK] File type '{ext}' is not allowed.");
                    return false;
                }

                // 2. PATH TRAVERSAL CHECK
                string potentialPath = Path.Combine(VhddPath, filename);
                string resolvedPath = Path.GetFullPath(potentialPath);
                string vhddAbs = Path.GetFullPath(VhddPath);
                
                // Ensure the path is actually inside the Vhdd folder
                if (resolvedPath.StartsWith(vhddAbs, StringComparison.OrdinalIgnoreCase)) {
                    fullPath = resolvedPath; 
                    return true;
                }
            }
            catch { return false; }
            return false;
        }

        public void Run(byte[] program)
        {
            Array.Clear(_memory, 0, _memory.Length);
            Array.Clear(_registers, 0, _registers.Length);
            _clipboard = ""; 
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
                        case OpCode.MUL: int rM = ReadReg(); _registers[rM] *= _registers[ReadReg()]; break;
                        case OpCode.DIV: int rD = ReadReg(); int div = _registers[ReadReg()]; if (div != 0) _registers[rD] /= div; else Console.WriteLine("Div/0 Error"); break;
                        case OpCode.STORE: int aR = ReadReg(); int vR = ReadReg(); _memory[_registers[aR]] = (byte)_registers[vR]; break;
                        case OpCode.JMP: _ip = ReadAddress(); break;
                        case OpCode.JIF: { int t = ReadAddress(); if (_registers[0] > 0) _ip = t; } break;
                        case OpCode.JZ: { int t = ReadAddress(); if (_registers[0] == 0) _ip = t; } break;
                        case OpCode.PRINT_VAL: Console.Write(_registers[ReadReg()]); break;
                        case OpCode.PRINT_CHAR: Console.Write((char)_registers[ReadReg()]); break;
                        case OpCode.PRINT_STR: Console.Write(StringBuffer); break;
                        case OpCode.INPUT_STR: StringBuffer = Console.ReadLine() ?? ""; break;
                        
                        case OpCode.SET_BUF: 
                            int sLenH = _memory[_ip++]; int sLenL = _memory[_ip++]; int sLen = (sLenH << 8) | sLenL;
                            string sVal = ""; for (int i = 0; i < sLen; i++) sVal += (char)_memory[_ip++]; 
                            StringBuffer = sVal; break;

                        case OpCode.INPUT_INT: int rI = ReadReg(); if (int.TryParse(Console.ReadLine(), out int pI)) _registers[rI] = pI; else _registers[rI] = 0; break;
                        case OpCode.CMD_CHECK: int cLen = _memory[_ip++]; string cmd = ""; for (int i = 0; i < cLen; i++) cmd += (char)_memory[_ip++]; int jT = ReadAddress(); string inp = StringBuffer.Trim(); if (inp.Equals(cmd, StringComparison.OrdinalIgnoreCase) || inp.StartsWith(cmd + " ", StringComparison.OrdinalIgnoreCase)) { if (inp.Length > cmd.Length) StringBuffer = inp.Substring(cmd.Length).Trim(); else StringBuffer = ""; _ip = jT; } break;
                        
                        // --- FILE IO ---
                        case OpCode.FILE_LIST: Console.WriteLine("\n--- VHDD ---"); foreach (var f in Directory.GetFiles(VhddPath)) Console.WriteLine($" {Path.GetFileName(f)}"); Console.WriteLine("------------"); break;
                        
                        case OpCode.FILE_CREATE: if (!string.IsNullOrEmpty(StringBuffer) && GetSafePath(StringBuffer, out string pC)) File.WriteAllText(pC, "Empty"); break;
                        
                        case OpCode.FILE_DELETE: if (GetSafePath(StringBuffer, out string pD)) File.Delete(pD); break;
                        
                        case OpCode.FILE_READ: if (GetSafePath(StringBuffer, out string pR) && File.Exists(pR)) StringBuffer = File.ReadAllText(pR); else StringBuffer = "Error"; break;
                        
                        case OpCode.FILE_WRITE: 
                            int fNL = _memory[_ip++]; string fN = ""; for (int i = 0; i < fNL; i++) fN += (char)_memory[_ip++]; 
                            // GetSafePath now checks extensions (json, txt, tiny)
                            if (GetSafePath(fN, out string pW)) File.WriteAllText(pW, StringBuffer); else Console.WriteLine($"Access Denied: {fN}"); break;
                        
                        // --- CLIPBOARD FEATURES ---
                        case OpCode.BUF_COPY: 
                            _clipboard = StringBuffer; 
                            break;

                        case OpCode.FILE_SAVE_AS:
                            // Saves _clipboard content to the filename currently in StringBuffer
                            if (GetSafePath(StringBuffer, out string pSave)) {
                                File.WriteAllText(pSave, _clipboard);
                                Console.WriteLine($"[SYSTEM] Saved clipboard to {StringBuffer}");
                            } else {
                                Console.WriteLine($"[SEC_ERR] Access Denied: {StringBuffer}");
                            }
                            break;

                        case OpCode.FILE_EXEC: running = false; ShouldLoadNewProgram = true; break;
                        case OpCode.MAKE_NOTE: Console.Write("File: "); string n = Console.ReadLine() ?? ""; Console.Write("Data: "); string c = Console.ReadLine() ?? ""; if (GetSafePath(n, out string pN)) File.WriteAllText(pN, c); break;
                        case OpCode.SYS_INFO: StringBuffer = "Host: TinyVM | OS: MOS v2.3 | SecureExt: YES"; break;
                        case OpCode.SCRAMBLE_FILE: string scT = StringBuffer.Trim(); if (GetSafePath(scT, out string pS) && File.Exists(pS)) CorruptFile(pS); break;
                        case OpCode.CLEAR_SCR: Console.Clear(); break;
                        case OpCode.NET_PING: if (!string.IsNullOrEmpty(StringBuffer)) { try { new Ping().Send(StringBuffer, 1000); Console.WriteLine("Ping OK"); } catch { Console.WriteLine("Ping Fail"); } } break;
                        
                        // --- FIXED NET_GET ---
                        case OpCode.NET_GET: 
                            try { 
                                string url = StringBuffer;
                                if (!url.StartsWith("http")) url = "https://" + url;
                                Console.Write("Downloading... ");
                                string webContent = _httpClient.GetStringAsync(url).GetAwaiter().GetResult(); 
                                if (webContent.Length > 8000) webContent = webContent.Substring(0, 8000) + "\n...[TRUNCATED]";
                                StringBuffer = webContent;
                                Console.WriteLine("Done.");
                            } catch (Exception ex) { 
                                Console.WriteLine($"Err: {ex.Message}"); 
                                StringBuffer = "Download Error"; 
                            } 
                            break;

                        default: throw new Exception($"Illegal OpCode {_memory[_ip - 1]}");
                    }
                }
            }
            catch (Exception ex) { Console.WriteLine($"[CPU ERROR]: {ex.Message}"); Console.ReadLine(); }
        }

        private void CorruptFile(string path) { File.WriteAllText(path, "CORRUPTED"); }
        private int ReadReg() { return _memory[_ip++]; }
        private int ReadAddress() { return (_memory[_ip++] << 8) | _memory[_ip++]; }
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
                    else if (cmd == "ADD") { bytecode.Add((byte)OpCode.ADD); bytecode.Add((byte)ParseReg(parts[1])); bytecode.Add((byte)ParseReg(parts[2])); }
                    else if (cmd == "SUB") { bytecode.Add((byte)OpCode.SUB); bytecode.Add((byte)ParseReg(parts[1])); bytecode.Add((byte)ParseReg(parts[2])); }
                    else if (cmd == "MUL") { bytecode.Add((byte)OpCode.MUL); bytecode.Add((byte)ParseReg(parts[1])); bytecode.Add((byte)ParseReg(parts[2])); }
                    else if (cmd == "DIV") { bytecode.Add((byte)OpCode.DIV); bytecode.Add((byte)ParseReg(parts[1])); bytecode.Add((byte)ParseReg(parts[2])); }
                    else if (cmd == "STRING") { bytecode.Add((byte)OpCode.SET_BUF); string val = parts[1].Trim('"'); int len = val.Length; bytecode.Add((byte)(len >> 8)); bytecode.Add((byte)(len & 0xFF)); foreach (char c in val) bytecode.Add((byte)c); }
                    else if (cmd == "WRITE") { bytecode.Add((byte)OpCode.FILE_WRITE); string val = parts[1].Trim('"'); bytecode.Add((byte)val.Length); foreach (char c in val) bytecode.Add((byte)c); }
                    else if (cmd == "SCRAMBLE") { bytecode.Add((byte)OpCode.SCRAMBLE_FILE); }
                    else if (cmd == "CLS") { bytecode.Add((byte)OpCode.CLEAR_SCR); }
                    else if (cmd == "PRINT_REG") { bytecode.Add((byte)OpCode.PRINT_VAL); bytecode.Add((byte)ParseReg(parts[1])); }
                    else if (cmd == "PING") { bytecode.Add((byte)OpCode.NET_PING); }
                    else if (cmd == "DOWNLOAD") { bytecode.Add((byte)OpCode.NET_GET); }
                    
                    // --- NEW COMMANDS ---
                    else if (cmd == "COPY") { bytecode.Add((byte)OpCode.BUF_COPY); }
                    else if (cmd == "SAVE_AS") { bytecode.Add((byte)OpCode.FILE_SAVE_AS); }
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
            
            if (File.Exists(Path.Combine(rootDir, "MOS.tiny"))) currentProgram = Path.Combine(rootDir, "MOS.tiny");
            else { string[] osFiles = Directory.GetFiles(rootDir, "*.tiny"); if (osFiles.Length > 0) currentProgram = osFiles[0]; }
            
            while (true) { 
                vm.Run(Compiler.Compile(currentProgram)); 
                if (vm.ShouldLoadNewProgram) { 
                    string f = vm.StringBuffer.Trim(); 
                    if (f == "exit") break;
                    if (File.Exists(Path.Combine(rootDir, f))) currentProgram = Path.Combine(rootDir, f);
                    else if (File.Exists(Path.Combine(vhddDir, f))) currentProgram = Path.Combine(vhddDir, f);
                } else break; 
            }
        }
    }
}
