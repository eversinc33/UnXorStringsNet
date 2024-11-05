using System.Reflection.Metadata;
using System.Text;
using AsmResolver.DotNet;
using AsmResolver.PE.DotNet.Cil;
using AsmResolver.PE.File;
using MethodDefinition = AsmResolver.DotNet.MethodDefinition;
using ModuleDefinition = AsmResolver.DotNet.ModuleDefinition;
using FieldDefinition  = AsmResolver.DotNet.FieldDefinition;
using TypeDefinition = AsmResolver.DotNet.TypeDefinition;

namespace SimpleStringEncryption;

public class Program
{
    private ModuleDefinition? _module;
    private FileStream? _fileStream;
    private PEFile? _pefile;
    private FieldDefinition _arrayPtrField = null!;
    private MethodDefinition _decryptionMethod = null!;
    private MethodDefinition _placeholderMethod = null!;
    private ulong _fileOffset;

    private byte[] RXOR(byte[] data, byte[] key_data, int length)
    {
        // RXOR Cipher: reverse array order and decrypt byte by byte using single XOR
        int n = length - 1;

        for (int i = 0; i < n; i++, n--)
        {
            data[i] ^= data[n];
            data[n] ^= (byte)(data[i] ^ key_data[0]); // BUG <- only one byte is used
            data[i] ^= data[n];
        }

        if (length % 2 != 0)
            data[length >> 1] ^= key_data[0]; // x >> 1 == x / 2

        return data;
    }

    internal byte[] ReadEncryptedData(ulong offset, int length)
    {
        offset = offset + _fileOffset;

        byte[] buffer = new byte[length];

        _fileStream.Seek((long)offset, SeekOrigin.Begin);
        int bytesRead = _fileStream.Read(buffer, 0, length);

        if (bytesRead < length)
        {
            Array.Resize(ref buffer, bytesRead); // Resize the buffer if fewer bytes were read
        }

        return buffer;
    }

    static bool IsValidUuid(string input)
    {
        return Guid.TryParse(input, out _);
    }

    public static int Main(string[] args)
    {
        if (!File.Exists(args[0]))
        {
            Console.WriteLine($"[!] File not found: {args[0]}");
            Console.ReadKey();
            return 1;
        }

        Program p = new Program();
        return p.Run(args[0]);
    }

    private int Run(string filename)
    { 
        _module = ModuleDefinition.FromFile(filename);
        _pefile = PEFile.FromFile(filename);
        _fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read);

        // ----------------------------------------------------------------------------------------------------------------------------

        Console.WriteLine("[*] Locating decryption values");

        Console.WriteLine("    Looking for UUID named type in module types indicating encryption type...");
        MethodDefinition? encryptionMethod = null;
        TypeDefinition? encryptionType = null;

        foreach (var type in _module.GetAllTypes())
        {
            if (IsValidUuid(type.FullName))
            {
                Console.WriteLine($"    Found potential encryption type: {type.FullName}");
                encryptionType = type;
                Console.WriteLine($"    Looking for UUID named method name indicating encryption routine...");
                foreach (var method in type.Methods)
                {
                    // method name should be a uuid
                    if (IsValidUuid(method.Name))
                    {
                        // Validate parameter and return type
                        if (method.ParameterDefinitions.Count() == 1 && method.Parameters[0].ParameterType.FullName == "System.Int32")
                        {
                            if (method.Signature.ReturnType.FullName == "System.String") ;
                            {
                                //method.Parameters.ReturnParameter.Name == "System.String"
                                Console.WriteLine($"    Found encryption method:\n    {method.FullName}");
                                encryptionMethod = method;
                                break;
                            }
                        }
                    }
                }
            }
        }

        if (encryptionMethod == null)
        {
            Console.WriteLine("[!] Could not find encryption method.");
            return 2;
        }

        // now lets get the struct containing the encrypted data
        // We should only have one type, thats our encrypted data
        var field = encryptionType.Fields[0];
        var rva = field.FieldRva.Rva;
        _fileOffset = _pefile.RvaToFileOffset(rva);
        Console.WriteLine("    Found encrypted data at RVA 0x" + rva.ToString("X8"));
        Console.WriteLine("    File offset:                0x" + _fileOffset.ToString("X8"));
        // Global key is stored as an int at the beginning of the file
        int globalKey = BitConverter.ToInt32(ReadEncryptedData(0, sizeof(int)));
        Console.WriteLine($"[*] Found global key: {globalKey}");

        Console.WriteLine("-----------------------------------------------------");

        // Loop through all types in the module
        foreach (var type in _module.GetAllTypes())
        {
            // Loop through all methods in the type
            foreach (var method in type.Methods)
            {
                // Skip empty methods and the encryption method itself
                if (method.CilMethodBody == null) continue;
                if (method.FullName == encryptionMethod.FullName) continue;

                // Loop through each instruction in the methods body
                var instructions = method.CilMethodBody.Instructions;
                for (int i = 0; i < instructions.Count; i++)
                {
                    var instruction = instructions[i];

                    // Check if the instruction is a call to the decryption method
                    if (instruction.OpCode == CilOpCodes.Call || instruction.OpCode == CilOpCodes.Callvirt)
                    {
                        if (instruction.Operand is MethodDefinition calledMethod && calledMethod.Name == encryptionMethod.Name)
                        {
                            /*
                             * we could load the malwares method and call it, 
                             * but i dont like loading malware modules into my code >:(
                             */

                            string decrypted;

                            // the operation before the call pushes the string id to the stack
                            int string_id = (int)instructions[i - 1].Operand;

                            // we decrypt the id with the global key to get the offset
                            var offset = globalKey ^ string_id;
                            Console.WriteLine($"  String ID [{string_id}] @ data+{offset}");

                            // decrypt
                            // [ length ] [ key ] [ encrypted_data ]
                            var dataLength = BitConverter.ToInt32(ReadEncryptedData((ulong)offset, sizeof(int)));
                            var xorKey = ReadEncryptedData((ulong)offset + sizeof(int), sizeof(int));
                            var data = ReadEncryptedData((ulong)offset + sizeof(int) * 2, dataLength);

                            // Empty strings have a negative ID
                            if (string_id >> 31 != 0)
                                decrypted = String.Empty;
                            else
                                decrypted = Encoding.UTF8.GetString(RXOR(data, xorKey, dataLength));
                            Console.WriteLine($"  - {decrypted}");

                            instructions.RemoveAt(i - 1); // remove ldc.id4 <ID>
                            instruction.ReplaceWithNop(); // nop call to decryption method
                            instructions.Insert(i, new CilInstruction(CilOpCodes.Ldstr, decrypted));
                        }
                    }
                }
            }
        }

        // -------------------------------------------------------------------------------------------------------------------------

        string outputPath = filename.Insert(filename.Length - 4, "_unpacked");
        _module.Write(outputPath);
        Console.WriteLine($"[*] Strings have been decrypted: \n[*] Output: {outputPath}");
        Console.ReadKey();

        return 0;
    }
}
