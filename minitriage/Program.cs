// James 2020 - If this code looks strange it may be because I quick-ported this from
// my original powershell-script doing the same thing.
// Uses the Rijndael-implementation from Microsoft https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=netframework-4.8

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
    class Program
    {
        // These values should be placed in settings.txt
        // Example:
        // strPublicKey=asdfasdfasdfasdf
        // strFTPServer=192.168.0.01
        // strFTPUser=user
        string strPublicKey = null; // public info
        string strFTPServer = null;
        string strFTPUser = null; // Consider this to be public info
        string strFTPPassword = null; // This should be considered open info. Security depends on the assymetric encryption of the files.
        string strDirectory = @"c:\quarantine";
        List<string> strCommands = new List<string>();

        string strTempOutputPath = null;

        static List <string> parseCommand(string strCommand)
        {
            List<string> lstRetval = new List<string>();

            if(strCommand.IndexOf('"') == 0)
            {
                string strSub = strCommand.Substring(1);

                int pos = strSub.IndexOf('"');

                string strExe = strSub.Substring(0, pos);
                string strArguments = strSub.Substring(pos + 1);

                lstRetval.Add(strExe);
                lstRetval.Add(strArguments);
            }
            else if(strCommand.IndexOf(' ') > 0)
            {
                int pos = strCommand.IndexOf(' ');

                string strExe = strCommand.Substring(0, pos);
                string strArguments = strCommand.Substring(pos + 1);

                lstRetval.Add(strExe);
                lstRetval.Add(strArguments);
            }
            else
            {
                lstRetval.Add(strCommand);
            }

            lstRetval[0] = lstRetval[0].Replace("@base@", Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location));

            return lstRetval;
        }
        

            // Initialize settings from the settings.txt-file.
        bool initSettings()
        {
            if (strTempOutputPath == null)
            {
                this.strTempOutputPath = getFolderCopyDirectory(); // Set the temporary folder for creating files and the log files.
            }

            string strSettingsFile = Path.GetDirectoryName(System.Reflection.Assembly.GetExecutingAssembly().Location) + 
                Path.DirectorySeparatorChar +
                "settings.txt";

            if(!File.Exists(strSettingsFile))
            {
                LogWriter.writeLog($"[-] Error: Settings file does not exist! {strSettingsFile}");
                return false;
            }

            string[] strAll = File.ReadAllLines(strSettingsFile);

            foreach(string str in strAll)
            {
                if (str.IndexOf('#') == 0) continue;

                Match m = Regex.Match(str, @"^(?<key>[A-z]{1,})\=(?<value>.+)");

                if(m.Success)
                {
                    string strKey = m.Groups["key"].Value.Trim();
                    string strValue = m.Groups["value"].Value.Trim();

                    if(strKey == "strFTPServer")
                    {
                        strFTPServer = strValue;
                    }
                    else if (strKey == "strPublicKey")
                    {
                        strPublicKey = strValue;
                    }
                    else if(strKey == "strFTPUser")
                    {
                        strFTPUser = strValue;
                    }
                    else if (strKey == "strFTPPassword")
                    {
                        strFTPPassword = strValue;
                    }
                    else if (strKey == "strDirectory")
                    {
                        strDirectory = strValue;
                    }
                    else if (strKey == "strCommand")
                    {
                        this.strCommands.Add(strValue);
                    }
                }
            }

            return true;
        }

        static void deleteFile(string strFile)
        {
            try
            {

                if (File.Exists(strFile))
                {
                    File.Delete(strFile);
                }
            }
            catch(Exception ex)
            {
                LogWriter.writeLog("[-] Error when deleting file: " + ex.Message);
            }
        }

        static string getFolderCopyDirectory()
        {
            Random rnd = new Random(); 
            string str = Path.GetTempPath() + "minitriage" + DateTime.Now.ToString("yyyyMMddHHmmss") +"_"+ rnd.Next();

            try
            {
                Directory.CreateDirectory(str);
            }
            catch(Exception ex)
            {
                LogWriter.writeLog("Error when creating folder-copy-directory: " + ex.Message);
                str = null;
            }

            return str;
        }

        void cleanTempFolders()
        {
            if (strTempOutputPath != null && Directory.Exists(strTempOutputPath))
            {
                try
                {
                    Directory.Delete(strTempOutputPath, true);
                }
                catch(Exception ex)
                {
                    LogWriter.writeLog(ex.Message);
                }
            }
        }

        void executeCommands()
        {
            for(int i=0; i < strCommands.Count; i++)
            {
                List<string> lstCommand = parseCommand(strCommands[i]);

                Random rnd = new Random();
                string strOutFile = Path.GetFileNameWithoutExtension(lstCommand[0]) + "_"+ rnd.Next();
                string strOut = this.strTempOutputPath + Path.DirectorySeparatorChar + strOutFile + ".txt";

                AppExecute app = new AppExecute();
                string strReturned = app.executeApp(lstCommand[0], (lstCommand.Count > 1) ? lstCommand[1] : null, this.strTempOutputPath);

                File.WriteAllText(strOut, strReturned);


            }
        }

        void fetchQuarantine()
        {
            var bts2 = System.Convert.FromBase64String(strPublicKey);
            string strOutput = Path.GetTempFileName();
            string strEncryptedFile = Path.GetTempFileName();


            if(this.strTempOutputPath != null)
            {
                LogWriter.writeLog($"[+] Copying all files from  {strDirectory} to {strTempOutputPath}");

                try
                {
                    string[] strFile = Directory.GetFiles(strDirectory);

                    foreach (string str in strFile)
                    {
                        string strFname = Path.GetFileName(str);
                        string strDir = Path.GetDirectoryName(str);

                        try
                        {
                            LogWriter.writeLog("[+] copy file" + strFname);
                            File.Copy($"{strDir}{Path.DirectorySeparatorChar}{strFname}", $"{strTempOutputPath}{Path.DirectorySeparatorChar}{strFname}");
                        }
                        catch (Exception ex2)
                        {
                            LogWriter.writeLog("[-] Error: could not copy file" + strFname + ":" + ex2.Message);
                        }
                    }

                    strDirectory = strTempOutputPath;
                }
                catch(Exception ex3)
                {
                    LogWriter.writeLog("[-] Error when trying to copy files. Reverting to copying directly from folder: " + ex3.Message);
                }
            }
            

            deleteFile(strEncryptedFile);
            deleteFile(strOutput);

            LogWriter.closeLog(); // We need to close the log so that we can include the log file in the archive.

            // Create the zip-archive
            System.IO.Compression.ZipFile.CreateFromDirectory(strDirectory, strOutput);

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

            deleteFile(strOutput);

            //// Send the encrypted file
            try
            {
                LogWriter.writeLog("[+] Uploading file to FTP-server...");
                sendFile(strEncryptedFile);
            }
            catch(Exception exFTP)
            {
                LogWriter.writeLog($"[-] Error when trying to upload file: {exFTP.Message}");
            }

            deleteFile(strEncryptedFile);

            //// Cleanup
            LogWriter.writeLog("[+] All done!");
        }

        // Send the encrypted file
        void sendFile(string strEncryptedFile)
        {
            
            string strDate = DateTime.Now.ToString("yyyyddMMhhMMss");
            System.Net.FtpWebRequest ftp = (System.Net.FtpWebRequest)System.Net.FtpWebRequest.Create($"{strFTPServer}/{strDate}-file.bin");
            ftp.Method = System.Net.WebRequestMethods.Ftp.UploadFile;
            ftp.Credentials = new System.Net.NetworkCredential(strFTPUser, strFTPPassword);

            ftp.UseBinary = true;
            ftp.UsePassive = true;

            // Ingest file
            var filecontent = System.IO.File.ReadAllBytes(strEncryptedFile);
            ftp.ContentLength = filecontent.Length;

            var ftpStream = ftp.GetRequestStream();
            ftpStream.Write(filecontent, 0, filecontent.Length);

            // Cleanup
            ftpStream.Close();
        }
        


        static void Main(string[] args)
        {
            string strTempOut = Program.getFolderCopyDirectory();
            LogWriter.strTempDirectory = strTempOut;
            LogWriter.writeLog("[+] MiniTriage v0.2 - James Dickson 2020");

            
            for (int i = 0; i < args.Length; i++)
            {
                if (args[i] == "--genkeys") // minitriage --genkeys <output_cert> <output_privatekey>
                {
                    LogWriter.writeLog("[+] Generating keys....");
                    Random rnd = new Random();
                    int number = rnd.Next();

                    Encryption enc = new Encryption();
                    enc.generateKeys("genericKeyName" + number.ToString());
                    enc.exportKey(args[++i], false);
                    enc.exportKey(args[++i], true);

                    LogWriter.writeLog("[+] Done!");

                    return;
                }
                else if (args[i] == "--decrypt") // minitriage --decrypt <privatekey> <inputfile> <outputfile>
                {
                    LogWriter.writeLog("[+] Decrypting ...");

                    Encryption enc = new Encryption();
                    enc.importKey(args[++i]);
                    enc.decryptFile(args[++i], args[++i]);

                    LogWriter.writeLog("[+] Done!");
                    return;
                }
            }

            try
            {

                Program p = new Program();
                p.strTempOutputPath = strTempOut;

                if (p.initSettings())
                {
                    try
                    {
                        LogWriter.writeLog("[+] Executing commands... output to " + p.strTempOutputPath);
                        p.executeCommands();
                    }
                    catch(Exception ex4)
                    {
                        LogWriter.writeLog("[-] Error when executing commands: " + ex4.StackTrace);
                    }

                    try
                    {
                        LogWriter.writeLog("[+] Fetching quarantine and sending logs...");
                        p.fetchQuarantine();
                    }
                    catch(Exception ex3)
                    {
                        LogWriter.writeLog(ex3.Message);
                    }

                    LogWriter.closeLog();
                    p.cleanTempFolders();
                }
            }
            catch(Exception ex)
            {
                LogWriter.writeLog(ex.Message + ":" + ex.StackTrace);
            }

            LogWriter.closeLog();

            Console.WriteLine("[+] All done!");
        }
    }
}
