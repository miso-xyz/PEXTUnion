using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Win32;
using System.Windows.Forms;
using dnlib.DotNet;
using dnlib.DotNet.Emit;
using dnlib.DotNet.Writer;

namespace PEUnionUnpacker_
{
    class Program
    {

        static void PrintRenamedText(string from, string to, string type, string className = "")
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.Write("[Renamed]: '" + from + "' -> '" + to + "'!");
            Console.ForegroundColor = ConsoleColor.Cyan;
            if (className == "")
            {
                Console.WriteLine(" (" + type + ")");
            }
            else
            {
                Console.WriteLine(" (" + type + ", " + className + ")");
            }
        }

        static void Main(string[] args)
        {
            Console.Title = "PEXTUnion";
            Console.WriteLine("PEXTUnion by misonothx | sinister.ly <3");
            Console.WriteLine(" |- https://github.com/miso-xyz/PEXTUnion");
            Console.WriteLine(" |- https://github.com/bytecode77/pe-union");
            var asm = ModuleDefMD.Load(args[0]);
            var rawBytes = new List<byte[]>();
            bool isEncrypted = false;
            bool isCompressed = false;
            bool fixStrings = !args.Contains("-dontfixStrings");
            string nestedMethodName = "";
            string peuTypeName = "";
            int stringFixCount = 0;
            int methodRenameCount = 0;
            int classRenameCount = 0;
            int fieldRenameCount = 0;
            bool hasApp = false;
            var resName = new List<string>();
            //string mainTypeName = asm.EntryPoint.DeclaringType.Name;
            Console.WriteLine();
            asm.EntryPoint.DeclaringType.Name = "Main";
            foreach (var t_ in asm.Types)
            {
                if (t_.Name == asm.EntryPoint.Body.Instructions[79].Operand.ToString())
                {
                    PrintRenamedText(t_.Name, "PackedFilesVariables", "class");
                    t_.Name = "PackedFilesVariables";
                    classRenameCount++;
                }
                else if (t_.Name == asm.EntryPoint.Body.Instructions[139].Operand.ToString())
                {
                    PrintRenamedText(t_.Name, "URLDownloadVariables", "class");
                    t_.Name = "URLDownloadVariables";
                    classRenameCount++;
                }
                else if (t_.Name == asm.EntryPoint.Body.Instructions[187].Operand.ToString())
                {
                    PrintRenamedText(t_.Name, "MessageBoxVariables", "class");
                    t_.Name = "MessageBoxVariables";
                    classRenameCount++;
                }
                switch (t_.Name)
                {
                    case "PackedFilesVariables":
                        foreach (var fields in t_.Fields)
                        {
                            string oldFieldName = fields.Name;
                            if (asm.EntryPoint.Body.Instructions[85].Operand.ToString().Contains(fields.Name)) { fields.Name = "antiSandboxie"; };
                            if (asm.EntryPoint.Body.Instructions[91].Operand.ToString().Contains(fields.Name)) { fields.Name = "antiWireshark"; };
                            if (asm.EntryPoint.Body.Instructions[97].Operand.ToString().Contains(fields.Name)) { fields.Name = "antiProcessMonitor"; };
                            if (asm.EntryPoint.Body.Instructions[103].Operand.ToString().Contains(fields.Name)) { fields.Name = "antiEmulator"; };
                            if (asm.EntryPoint.Body.Instructions[109].Operand.ToString().Contains(fields.Name)) { fields.Name = "sourceApp"; };
                            if (asm.EntryPoint.Body.Instructions[112].Operand.ToString().Contains(fields.Name)) { fields.Name = "isAppEncrypted"; };
                            if (asm.EntryPoint.Body.Instructions[118].Operand.ToString().Contains(fields.Name)) { fields.Name = "isAppCompressed"; };
                            if (asm.EntryPoint.Body.Instructions[124].Operand.ToString().Contains(fields.Name)) { fields.Name = "appName"; };
                            if (asm.EntryPoint.Body.Instructions[126].Operand.ToString().Contains(fields.Name)) { fields.Name = "appParameters"; };
                            if (asm.EntryPoint.Body.Instructions[128].Operand.ToString().Contains(fields.Name)) { fields.Name = "pathType"; };
                            if (asm.EntryPoint.Body.Instructions[130].Operand.ToString().Contains(fields.Name)) { fields.Name = "executionParams"; };
                            if (asm.EntryPoint.Body.Instructions[132].Operand.ToString().Contains(fields.Name)) { fields.Name = "useRunas"; };
                            if (asm.EntryPoint.Body.Instructions[134].Operand.ToString().Contains(fields.Name)) { fields.Name = "args"; };
                            PrintRenamedText(oldFieldName, fields.Name, "field", t_.Name);
                            fieldRenameCount++;
                        }
                        break;
                    case "URLDownloadVariables":
                        foreach (var fields in t_.Fields)
                        {
                            string oldFieldName = fields.Name;
                            if (asm.EntryPoint.Body.Instructions[145].Operand.ToString().Contains(fields.Name)) { fields.Name = "antiSandboxie"; };
                            if (asm.EntryPoint.Body.Instructions[151].Operand.ToString().Contains(fields.Name)) { fields.Name = "antiWireshark"; };
                            if (asm.EntryPoint.Body.Instructions[157].Operand.ToString().Contains(fields.Name)) { fields.Name = "antiProcessMonitor"; };
                            if (asm.EntryPoint.Body.Instructions[163].Operand.ToString().Contains(fields.Name)) { fields.Name = "antiEmulator"; };
                            if (asm.EntryPoint.Body.Instructions[169].Operand.ToString().Contains(fields.Name)) { fields.Name = "appName"; };
                            if (asm.EntryPoint.Body.Instructions[171].Operand.ToString().Contains(fields.Name)) { fields.Name = "appParams"; };
                            if (asm.EntryPoint.Body.Instructions[173].Operand.ToString().Contains(fields.Name)) { fields.Name = "pathType"; };
                            if (asm.EntryPoint.Body.Instructions[175].Operand.ToString().Contains(fields.Name)) { fields.Name = "executionParams"; };
                            if (asm.EntryPoint.Body.Instructions[177].Operand.ToString().Contains(fields.Name)) { fields.Name = "useRunas"; };
                            if (asm.EntryPoint.Body.Instructions[179].Operand.ToString().Contains(fields.Name)) { fields.Name = "args"; };
                            if (asm.EntryPoint.Body.Instructions[182].Operand.ToString().Contains(fields.Name)) { fields.Name = "URLDownload"; };
                            PrintRenamedText(oldFieldName, fields.Name, "field", t_.Name);
                            fieldRenameCount++;
                        }
                        break;
                    case "MessageBoxVariables":
                        foreach (var fields in t_.Fields)
                        {
                            string oldFieldName = fields.Name;
                            if (asm.EntryPoint.Body.Instructions[193].Operand.ToString().Contains(fields.Name)) { fields.Name = "MessageBoxText"; };
                            if (asm.EntryPoint.Body.Instructions[195].Operand.ToString().Contains(fields.Name)) { fields.Name = "MessageBoxTitle"; };
                            if (asm.EntryPoint.Body.Instructions[197].Operand.ToString().Contains(fields.Name)) { fields.Name = "MessageBoxButtons"; };
                            if (asm.EntryPoint.Body.Instructions[199].Operand.ToString().Contains(fields.Name)) { fields.Name = "MessageBoxIcon"; };
                            PrintRenamedText(oldFieldName, fields.Name, "field", t_.Name);
                            fieldRenameCount++;
                        }
                        break;
                }
            }
            foreach (var t_ in asm.Types)
            {
                if (t_.Name.Contains("PrivateImplementationDetails"))
                {
                    foreach (var fields in t_.Fields)
                    {
                        Console.ForegroundColor = ConsoleColor.Cyan;
                        Console.WriteLine("[Raw Bytes]: Found '" + fields.Name + "'");
                        rawBytes.Add(fields.InitialValue);
                    }
                    Console.WriteLine();
                }
                else if (t_.HasNestedTypes)
                {
                    if (t_.NestedTypes[0].Name.Contains("DisplayClass"))
                    {
                        nestedMethodName = t_.NestedTypes[0].Methods[1].Name.ToString().Substring(1, t_.NestedTypes[0].Methods[1].Name.ToString().IndexOf(">")-1);
                        Console.ForegroundColor = ConsoleColor.Yellow;
                        Console.WriteLine("[Nested Class]: Found '" + nestedMethodName + "'");
                        Console.WriteLine();
                    }
                }
                foreach (var methods in t_.Methods)
                {
                    if (methods.HasImplMap)
                    {
                        methods.Name = Path.GetFileNameWithoutExtension(methods.ImplMap.Module.Name) + "." + methods.ImplMap.Name;
                        methodRenameCount++;
                    }
                    if (methods.HasParams())
                    {
                        if (methods.Parameters.Count == 7)
                        {
                            PrintRenamedText(methods.Name, "PathTranslator", "method");
                            methods.Name = "PathTranslator";
                            methodRenameCount++;
                        }
                        else if (methods.Parameters.Count == 1 && methods.HasBody && methods.Name != nestedMethodName)
                        {
                            if (methods.Body.Instructions[0].OpCode.Equals(OpCodes.Newobj))
                            {
                                if (methods.Body.Instructions[0].Operand.ToString().Contains("MemoryStream"))
                                {
                                    PrintRenamedText(methods.Name, "Decompress", "method");
                                    methods.Name = "Decompress";
                                    methodRenameCount++;
                                }
                            }
                            else if (methods.Body.Instructions[9].Operand != null)
                            {
                                if (methods.Body.Instructions[9].Operand.ToString().Contains("Rijndael"))
                                {
                                    PrintRenamedText(methods.Name, "DecryptBytes", "method");
                                    methods.Name = "DecryptBytes";
                                    methodRenameCount++;
                                }
                            }
                        }
                        foreach (var methodArgs in methods.Parameters)
                        {
                            methodArgs.Name = methodArgs.Type.ElementType.ToString().ToLower();
                        }
                    }
                    if (methods.HasBody)
                    {
                        string callName = asm.EntryPoint.Body.Instructions[112].Operand.ToString();
                        if (callName.Substring(callName.IndexOf("::")).Contains(methods.Name))
                        {
                            methods.Name = "ByteDecryptionAlgorithm";
                            PrintRenamedText(methods.Name, "ByteDecryptionAlgorithm", "method");
                            methodRenameCount++;
                        }
                        if (methods.Name == ".cctor" && t_.Methods.Count == 11)
                        {
                            resName.Add(DecryptString(methods.Body.Instructions[8].Operand.ToString()));
                            peuTypeName = methods.Body.Instructions[5].Operand.ToString();
                            hasApp = true;
                            foreach (var fields in t_.Fields)
                            {
                                if (methods.Body.Instructions[55].Operand.ToString().Contains(fields.Name)) { PrintRenamedText(fields.Name, "PEUVar", "field"); fields.Name = "PEUVar"; };
                            }
                            var peuVars = new List<bool>();
                            for (int x = 0; x < methods.Body.Instructions.Count; x++)
                            {
                                Instruction inst = methods.Body.Instructions[x];
                                if (inst.OpCode.Equals(OpCodes.Newarr))
                                {
                                    hasApp = true;
                                }
                                if (inst.OpCode.ToString().StartsWith("ldc.i4."))
                                {
                                    bool temp_ = Convert.ToBoolean(Convert.ToInt32(inst.OpCode.ToString().Replace("ldc.i4.", null)));
                                    if (methods.Body.Instructions[x + 1].OpCode.Equals(OpCodes.Stfld))
                                    {
                                        peuVars.Add(temp_);
                                    }
                                }
                            }
                            isCompressed = peuVars[1];
                            isEncrypted = peuVars[2];
                            //Console.WriteLine(isCompressed + "," + isEncrypted);
                        }
                        else if (nestedMethodName.Contains(methods.Name))
                        {
                            PrintRenamedText(methods.Name, "StringDecryptionAlgorithm", "method");
                            methods.Name = "StringDecryptionAlgorithm";
                        }
                        for (int x = 0; x < methods.Body.Instructions.Count; x++)
                        {
                            Instruction inst = methods.Body.Instructions[x];
                            if (inst.OpCode.Equals(OpCodes.Ldstr) && fixStrings)
                            {
                                string bef_ = inst.Operand.ToString();
                                try
                                {
                                    methods.Body.Instructions[x].Operand = DecryptString(inst.Operand.ToString());
                                    methods.Body.Instructions.RemoveAt(x + 1);
                                    Console.ForegroundColor = ConsoleColor.Green;
                                    Console.Write("[String Fixed]: ");
                                    Console.ForegroundColor = ConsoleColor.Magenta;
                                    Console.WriteLine("'" + bef_ + "' -> '" + methods.Body.Instructions[x].Operand.ToString() + "'");
                                    stringFixCount++;
                                }
                                catch (Exception)
                                {
                                    Console.ForegroundColor = ConsoleColor.Red;
                                    Console.WriteLine("Failed to decrypt string! ('" + bef_ + "')");
                                }
                            }
                        }
                    }
                }
            }
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("#########################################");
            Console.ForegroundColor = ConsoleColor.DarkMagenta;
            Console.WriteLine("  " + classRenameCount + " Class Renamed");
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("  " + methodRenameCount + " Methods Renamed");
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("  " + fieldRenameCount + " Fields Renamed");
            Console.WriteLine();
            Console.ForegroundColor = ConsoleColor.Magenta;
            Console.WriteLine("  " + stringFixCount + " Strings Decrypted");
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("#########################################");
            Console.WriteLine();
            if (hasApp)
            {
                Directory.CreateDirectory("PEUnionUnpacker+\\" + Path.GetFileNameWithoutExtension(args[0]));
                for (int x = 0; x < rawBytes.Count; x++)
                {
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.Write("Saving '" + x + ".bin'...");
                    try
                    {
                        if (isEncrypted)
                        {
                            if (isCompressed)
                            {
                                Console.WriteLine(" (Encrypted & Compressed)");
                                File.WriteAllBytes("PEUnionUnpacker+\\" + Path.GetFileNameWithoutExtension(args[0]) + "\\" + x + ".bin", Decompress(DecryptBytes(rawBytes[x])));
                            }
                            else
                            {
                                Console.WriteLine(" (Encrypted)");
                                File.WriteAllBytes("PEUnionUnpacker+\\" + Path.GetFileNameWithoutExtension(args[0]) + "\\" + x + ".bin", DecryptBytes(rawBytes[x]));
                            }
                        }
                        else
                        {
                            Console.WriteLine(" (Not protected)");
                            File.WriteAllBytes("PEUnionUnpacker+\\" + Path.GetFileNameWithoutExtension(args[0]) + "\\" + x + ".bin", rawBytes[x]);
                        }
                        Console.ForegroundColor = ConsoleColor.Green;
                        Console.WriteLine("File '" + x + ".bin' saved!");
                    }
                    catch (Exception)
                    {
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("Failed to save '" + x + ".bin'!");
                    }
                }
            }
            else
            {
                Console.ForegroundColor = ConsoleColor.Yellow;
                Console.WriteLine("The application does not have any source apps, this probably means it downloads the payload from a URL.");
            }
            if (fixStrings)
            {
                ModuleWriterOptions moduleWriterOptions = new ModuleWriterOptions(asm);
                moduleWriterOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
                moduleWriterOptions.Logger = DummyLogger.NoThrowInstance;
                NativeModuleWriterOptions nativeModuleWriterOptions = new NativeModuleWriterOptions(asm, true);
                nativeModuleWriterOptions.MetadataOptions.Flags |= MetadataFlags.PreserveAll;
                nativeModuleWriterOptions.Logger = DummyLogger.NoThrowInstance;
                try
                {
                    Console.WriteLine();
                    Console.ForegroundColor = ConsoleColor.Yellow;
                    Console.WriteLine("Saving '" + Path.GetFileNameWithoutExtension(args[0]) + "-PEXTCleaned" + Path.GetExtension(args[0]) + "'...");
                    asm.Write(Path.GetFileNameWithoutExtension(args[0]) + "-PEXTCleaned" + Path.GetExtension(args[0]));
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine("'" + Path.GetFileNameWithoutExtension(args[0]) + "-PEXTCleaned" + Path.GetExtension(args[0]) + "' successfully saved!");
                }
                catch (Exception ex)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine("Failed to save '" + Path.GetFileNameWithoutExtension(args[0]) + "-PEXTCleaned" + Path.GetExtension(args[0]) + "'! (" + ex.Message + ")");
                }
            }
            Console.ResetColor();
            Console.WriteLine("Press any key to exit...");
            Console.ReadKey();
        }

        public string GetPathFromType(int type)
        {
            switch (type)
            {
                case 1:
                    return Path.GetTempPath();
                case 2: // Downloads folder
                    return Convert.ToString(Registry.GetValue("HKEY_C", "{374DE290-123F-4565-9164-39C4925E467B}", null));
                case 3:
                    return Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                case 4:
                    return Environment.GetFolderPath(Environment.SpecialFolder.Personal);
                case 5:
                    return AppDomain.CurrentDomain.BaseDirectory;
                default:
                    return "<Unknown>";
            }
        }
        public static string DecryptString(string data)
        {
            return new string((
                from c in data.Substring(1)
                select (char)(Convert.ToInt32(c) ^ ((byte)Convert.ToInt32(data[0])))).ToArray());
        }

        public static byte[] DecryptBytes(byte[] data)
        {
            byte[] array = new byte[16];
            Buffer.BlockCopy(data, 0, array, 0, 16);
            Rijndael rijndael = Rijndael.Create();
            SymmetricAlgorithm symmetricAlgorithm = rijndael;
            SymmetricAlgorithm symmetricAlgorithm2 = rijndael;
            byte[] array2 = array;
            byte[] iv = array2;
            symmetricAlgorithm2.Key = array2;
            symmetricAlgorithm.IV = iv;
            MemoryStream memoryStream = new MemoryStream();
            CryptoStream cryptoStream = new CryptoStream(memoryStream, rijndael.CreateDecryptor(), CryptoStreamMode.Write);
            cryptoStream.Write(data, 16, data.Length - 16);
            cryptoStream.Close();
            return memoryStream.ToArray();
        }

        public static byte[] Decompress(byte[] data)
        {
            MemoryStream memoryStream = new MemoryStream();
            int num = BitConverter.ToInt32(data, 0);
            memoryStream.Write(data, 4, data.Length - 4);
            byte[] array = new byte[num];
            memoryStream.Position = 0L;
            (new System.IO.Compression.GZipStream(memoryStream, System.IO.Compression.CompressionMode.Decompress)).Read(array, 0, array.Length);
            return array;
        }
    }
}
