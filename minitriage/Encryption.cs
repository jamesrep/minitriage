using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace minitriage
{
    class Encryption
    {
        CspParameters cspp = new CspParameters();
        RSACryptoServiceProvider rsa;

        public void generateKeys(string strKeyName)
        {
            cspp.KeyContainerName = strKeyName;
            rsa = new RSACryptoServiceProvider(cspp);
        }

        public static bool encryptFile(string strEncryptedFile, string strOutput, byte [] bts2)
        {
            try
            {

                // Create the Rijndael-object
                var rjndl = new System.Security.Cryptography.RijndaelManaged();
                rjndl.KeySize = 256;
                rjndl.BlockSize = 256;
                rjndl.Mode = System.Security.Cryptography.CipherMode.CBC;

                var cspp = new System.Security.Cryptography.CspParameters();
                cspp.KeyContainerName = "jamescontainer";

                // Import the key
                var rsa = new System.Security.Cryptography.RSACryptoServiceProvider(cspp);
                rsa.ImportCspBlob(bts2);

                var btsEncryptedKey = rsa.Encrypt(rjndl.Key, false);
                var btsKeylength = System.BitConverter.GetBytes(btsEncryptedKey.Length);
                var btsIVLength = System.BitConverter.GetBytes(rjndl.IV.Length);

                // Create the file where the encrypted data will be stored.
                var fsOutput = new System.IO.FileStream(strEncryptedFile, System.IO.FileMode.Create);

                // Header: [keylength][iv-length][encrypted-key][iv]
                fsOutput.Write(btsKeylength, 0, 4);
                fsOutput.Write(btsIVLength, 0, 4);
                fsOutput.Write(btsEncryptedKey, 0, btsEncryptedKey.Length);
                fsOutput.Write(rjndl.IV, 0, rjndl.IV.Length);

                var outStreamEncrypted = new System.Security.Cryptography.CryptoStream(fsOutput, rjndl.CreateEncryptor(), System.Security.Cryptography.CryptoStreamMode.Write);

                // Write to stream
                var count = 0;
                var blockSizeBytes = (rjndl.BlockSize / 8);
                var data = new byte[blockSizeBytes];

                // Open the zip-file previously created from the contents of the quarantine folder
                var fsZipFile = new System.IO.FileStream(strOutput, System.IO.FileMode.Open);

                do
                {
                    count = fsZipFile.Read(data, 0, blockSizeBytes);
                    outStreamEncrypted.Write(data, 0, count);
                }
                while (count > 0);

                //// Cleanup
                fsZipFile.Close();
                outStreamEncrypted.FlushFinalBlock();
                outStreamEncrypted.Close();
                fsOutput.Close();

                return true;
            }
            catch(Exception ex)
            {
                LogWriter.writeLog("[-] Error in encryptFile() " + ex.Message);
            }

            return false;
        }

        public void decryptFile(string strInput, string strOutput)
        {
            RijndaelManaged rjndl = new RijndaelManaged();
            rjndl.KeySize = 256;
            rjndl.BlockSize = 256;
            rjndl.Mode = CipherMode.CBC;

            byte[] btsKeyLength = new byte[4];
            byte[] btsIVLength = new byte[4];

            // Decrypt the file
            using (FileStream fsInputFile = new FileStream(strInput, FileMode.Open))
            {
                fsInputFile.Read(btsKeyLength, 0, btsKeyLength.Length);
                fsInputFile.Read(btsIVLength, 0, btsIVLength.Length);

                int lenK = BitConverter.ToInt32(btsKeyLength, 0);
                int lenIV = BitConverter.ToInt32(btsIVLength, 0);
                int headerSize = lenK + lenIV + 8;
                int encryptedBytesLength = (int)fsInputFile.Length - headerSize;

                byte[] btsKeyEncrypted = new byte[lenK];
                byte[] btsIV = new byte[lenIV];

                fsInputFile.Read(btsKeyEncrypted, 0, lenK);
                fsInputFile.Read(btsIV, 0, lenIV);

                // Decrypt the key
                byte[] KeyDecrypted = rsa.Decrypt(btsKeyEncrypted, false);

                // Create transform
                ICryptoTransform transform = rjndl.CreateDecryptor(KeyDecrypted, btsIV);

                // Decrypt the encrypted bytes
                using (FileStream outFs = new FileStream(strOutput, FileMode.Create))
                {
                    int count = 0;
                    int blockSizeBytes = rjndl.BlockSize / 8;
                    byte[] data = new byte[blockSizeBytes];

                    using (CryptoStream outStreamDecrypted = new CryptoStream(outFs, transform, CryptoStreamMode.Write))
                    {
                        do
                        {
                            count = fsInputFile.Read(data, 0, blockSizeBytes);
                            outStreamDecrypted.Write(data, 0, count);
                        }
                        while (count > 0);

                        outStreamDecrypted.FlushFinalBlock();
                        outStreamDecrypted.Close();
                    }
                    outFs.Close();
                }
                fsInputFile.Close();
            }

        }

        public void importKey(byte[] bts, int bsize)
        {
            if (bsize > 0)
            {
                byte[] bts2 = new byte[bsize];
                Array.Copy(bts, bts2, bts2.Length);

                rsa = new RSACryptoServiceProvider();
                rsa.ImportCspBlob(bts2);
            }
        }

        public void importKey(string strFilename)
        {
            FileStream fs = new FileStream(strFilename, FileMode.OpenOrCreate);
            byte[] bts = new byte[8192];

            int bsize = fs.Read(bts, 0, bts.Length);

            importKey(bts, bsize);

            fs.Close();
        }

        public void exportKey(string strFilename, bool bIncludePrivate)
        {
            if (File.Exists(strFilename))
            {
                File.Delete(strFilename);
            }

            FileStream fs = new FileStream(strFilename, FileMode.OpenOrCreate);
            BinaryWriter outputStream = new BinaryWriter(fs);

            // See the doc from...
            // https://msdn.microsoft.com/en-us/library/windows/desktop/aa375601%28v=vs.85%29.aspx
            //
            //PUBLICKEYSTRUC  publickeystruc;     (8 bytes)
            //RSAPUBKEY rsapubkey;                (12 bytes)
            //BYTE modulus[rsapubkey.bitlen/8];   (128 bytes)


            // 8 bytes
            // typedef struct _PUBLICKEYSTRUC {
            // BYTE bType;
            //  BYTE bVersion;
            //  WORD reserved;
            //  ALG_ID aiKeyAlg; (unsigned int)
            //  }
            //      BLOBHEADER, PUBLICKEYSTRUC;

            //  12 bytes

            // typedef struct _RSAPUBKEY {
            //  DWORD magic;
            //  DWORD bitlen;
            //  DWORD pubexp;
            //            }
            //   RSAPUBKEY;


            byte[] bts = rsa.ExportCspBlob(bIncludePrivate);
            outputStream.Write(bts, 0, bts.Length);
            outputStream.Flush();
            outputStream.Close();
            fs.Close();

            if (!bIncludePrivate)
            {
                string strBase64 = Convert.ToBase64String(bts);
                LogWriter.writeLog("[+] Public key: \r\n" + strBase64);
            }
        }
    }

}
