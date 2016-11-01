using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

public class SamplesEncoding {

    public static void Main() {

        // The characters to encode:
        //    Latin Small Letter Z (U+007A)
        //    Latin Small Letter A (U+0061)
        //    Combining Breve (U+0306)
        //    Latin Small Letter AE With Acute (U+01FD)
        //    Greek Small Letter Beta (U+03B2)
        //    a high-surrogate value (U+D8FF)
        //    a low-surrogate value (U+DCFF)
        char[] myChars = new char[] { 'z', 'a', '\u0306', '\u01FD', '\u03B2', '\uD8FF', '\uDCFF' };

        // Get different encodings.
        //Encoding u7 = Encoding.UTF7;
        Encoding u8 = Encoding.UTF8;
        Encoding aa = Encoding.ASCII;
        Encoding u16LE = Encoding.Unicode;
        //Encoding u16BE = Encoding.BigEndianUnicode;
        //Encoding u32 = Encoding.UTF32;

        // Encode the entire array, and print out the counts and the resulting bytes.
        //PrintCountsAndBytes(myChars, u7);
        PrintCountsAndBytes(myChars, u8);
    //    PrintCountsAndBytes(myChars, aa);
      //  PrintCountsAndBytes(myChars, u16LE);
        //PrintCountsAndBytes(myChars, u16BE);
        //PrintCountsAndBytes(myChars, u32);

    }


    public static void PrintCountsAndBytes(char[] chars, Encoding enc) {

        // Display the name of the encoding used.
        Console.Write("{0,-30} :", enc.ToString());

        // Display the exact byte count.
        int iBC = enc.GetByteCount(chars);
        Console.Write(" {0,-3}", iBC);

        // Display the maximum byte count.
        int iMBC = enc.GetMaxByteCount(chars.Length);
        Console.Write(" {0,-3} :", iMBC);

        // Encode the array of chars.
        byte[] bytes = enc.GetBytes(chars);

        // Display all the encoded bytes.
        PrintHexBytes(bytes);

        // Encode the array of chars.
        string encrypted = Encrypt(chars, "bob");
        // Display all the encoded bytes.
        PrintHexBytes(Encoding.UTF8.GetBytes(encrypted));

        // Decode the array of chars.
        string decrypted = Decrypt(chars, "bob");
        // Display all the encoded bytes.
        PrintHexBytes(Encoding.UTF8.GetBytes(decrypted));

    }


    public static void PrintHexBytes(byte[] bytes) {

        if ((bytes == null) || (bytes.Length == 0))
            Console.WriteLine("<none>");
        else {
            for (int i = 0; i < bytes.Length; i++)
                Console.Write("{0:X2} ", bytes[i]);
            Console.WriteLine();
        }

    }

    public static string Encrypt(char[] data, string password) {
        //if (String.IsNullOrEmpty(data))
        //    throw new ArgumentException("No data given");
        //if (String.IsNullOrEmpty(password))
        //    throw new ArgumentException("No password given");

        // setup the encryption algorithm
        Rfc2898DeriveBytes keyGenerator = new Rfc2898DeriveBytes(password, 8);
        Rijndael aes = Rijndael.Create();
        aes.IV = keyGenerator.GetBytes(aes.BlockSize / 8);
        aes.Key = keyGenerator.GetBytes(aes.KeySize / 8);

        // encrypt the data
        byte[] rawData = Encoding.Unicode.GetBytes(data);
        using (MemoryStream memoryStream = new MemoryStream())
        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write)) {
            memoryStream.Write(keyGenerator.Salt, 0, keyGenerator.Salt.Length);
            cryptoStream.Write(rawData, 0, rawData.Length);
            cryptoStream.Close();

            return Convert.ToBase64String(memoryStream.ToArray());

           // byte[] encrypted = memoryStream.ToArray();
           // return Encoding.Unicode.GetString(encrypted);
        }
    }

    public static string Decrypt(char[] data, string password) {
        //if (String.IsNullOrEmpty(data))
        //    throw new ArgumentException("No data given");
        //if (String.IsNullOrEmpty(password))
        //    throw new ArgumentException("No password given");

        //byte[] rawData = Encoding.Unicode.GetBytes(data);
        byte[] rawData = Convert.FromBase64CharArray(data);

        if (rawData.Length < 8)
            throw new ArgumentException("Invalid input data");

        // setup the decryption algorithm
        byte[] salt = new byte[8];
        for (int i = 0; i < salt.Length; i++)
            salt[i] = rawData[i];

        Rfc2898DeriveBytes keyGenerator = new Rfc2898DeriveBytes(password, salt);
        Rijndael aes = Rijndael.Create();
        aes.IV = keyGenerator.GetBytes(aes.BlockSize / 8);
        aes.Key = keyGenerator.GetBytes(aes.KeySize / 8);

        // decrypt the data
        using (MemoryStream memoryStream = new MemoryStream())
        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write)) {
            cryptoStream.Write(rawData, 8, rawData.Length - 8);
            cryptoStream.Close();

            return Convert.ToBase64String(memoryStream.ToArray());


            //byte[] decrypted = memoryStream.ToArray();
            //return Encoding.Unicode.GetString(decrypted);
        }
    }
}

/* 
This code produces the following output.

System.Text.UTF7Encoding       : 18  23  :7A 61 2B 41 77 59 42 2F 51 4F 79 32 50 2F 63 2F 77 2D
System.Text.UTF8Encoding       : 12  24  :7A 61 CC 86 C7 BD CE B2 F1 8F B3 BF
System.Text.UnicodeEncoding    : 14  16  :7A 00 61 00 06 03 FD 01 B2 03 FF D8 FF DC
System.Text.UnicodeEncoding    : 14  16  :00 7A 00 61 03 06 01 FD 03 B2 D8 FF DC FF
System.Text.UTF32Encoding      : 24  32  :7A 00 00 00 61 00 00 00 06 03 00 00 FD 01 00 00 B2 03 00 00 FF FC 04 00

*/
