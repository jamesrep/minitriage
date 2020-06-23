// James 2020 - If this code looks strange it may be because I quick-ported this from
// my original powershell-script doing the same thing.
// Uses the Rijndael-implementation from Microsoft https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rsacryptoserviceprovider?view=netframework-4.8

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
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
        List <string> strDirectory = new List<string>();
        List<string> strCommands = new List<string>();
        List<string> strHttpFetch = new List<string>();
        List<string> strUserKeyFetch = new List<string>();
        List<string> strIncludeOnlyFiletypes = new List<string>(); // The file types which should be included. If empty then all are copied.
        List<DirectoryFetcher> lstDirectoryFetcher = new List<DirectoryFetcher>(); // To be able to fetch files in folders more granularly than a global file type setting
        string strTempOutputPath = null;
        List<string> lstGlobalAvoidDirectories = new List<string>(); // Always ignore these directories for file copy operations.
        List<string> lstGlobalIncludeDirectories = new List<string>();
        int fileSizeLimit = 0;
        int maxFolderDepth = 5; // Maximum folder depth for file copy operations.

        class DirectoryFetcher
        {
            public string strDirectoryPath;
            public List<string> lstFileTypes = new List<string>();
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
                LogWriter.writeLog("[-] Error: Settings file does not exist! " + strSettingsFile);
                return false;
            }

            string[] strAll = File.ReadAllLines(strSettingsFile);

            foreach(string str in strAll)
            {
                if (str.IndexOf('#') == 0) continue; // Remove comment-lines

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
                    else if (strKey == "intFolderDepth")
                    {
                        LogWriter.writeLog("[+] Sets the folder depth limit to: " + strValue + " levels");
                        this.maxFolderDepth = Convert.ToInt32(strValue);
                    }
                    else if (strKey == "intFileSizeLimit")
                    {
                        LogWriter.writeLog("[+] Sets the file size limit to: " + strValue + " bytes");
                        this.fileSizeLimit = Convert.ToInt32( strValue);
                    }
                    else if (strKey == "strFTPPassword")
                    {
                        strFTPPassword = strValue;
                    }
                    else if (strKey == "strDirectory")
                    {
                        strDirectory.Add(strValue);
                    }
                    else if (strKey == "strCommand")
                    {
                        this.strCommands.Add(strValue);
                    }
                    else if (strKey == "strHttpFetch")
                    {
                        this.strHttpFetch.Add(strValue);
                    }
                    else if (strKey == "strUserKeyFetch")
                    {
                        this.strUserKeyFetch.Add(strValue);
                    }
                    else if (strKey == "strFileType")
                    {
                        LogWriter.writeLog("[+] Includes the " + strValue + " file type.");
                        this.strIncludeOnlyFiletypes.Add(strValue);
                    }
                    else if (strKey == "strAvoidDirectory")
                    {
                        LogWriter.writeLog("[+] Always ignoring directory: " + strValue );
                        this.lstGlobalAvoidDirectories.Add(strValue);
                    }
                    else if (strKey == "strIncludeDirectory")
                    {
                        LogWriter.writeLog("[+] Including directory (ignoring all others): " + strValue);
                        this.lstGlobalIncludeDirectories.Add(strValue);
                    }
                    else if (strKey == "strFilesInFolders")
                    {
                        // strFilesInFolders=c:\users|.exe|.dll
                        LogWriter.writeLog("[+] Includes the " + strValue + " file type.");

                        string[] strs = strValue.Split(new char[] { '|' });

                        DirectoryFetcher dfetch = new DirectoryFetcher();
                        dfetch.strDirectoryPath = strs[0];

                        for(int i=1; i < strs.Length; i++)
                        {
                            dfetch.lstFileTypes.Add(strs[i]);
                        }

                        this.lstDirectoryFetcher.Add(dfetch);
                    }
                }
            }

            return true;
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

        string getArgumentString(string strArgs)
        {
            string strNoBackslash = strArgs.Replace("\\", "_");

            return Regex.Replace(strNoBackslash, "[^A-z|^0-9|^.]", "_");
        }

        void executeCommands()
        {
            for(int i=0; i < strCommands.Count; i++)
            {
                try
                {
                    List<string> lstCommand = Helpers.parseCommand(strCommands[i]);

                    string strParsedArguments = (lstCommand.Count > 1) ? lstCommand[1] : "";
                    strParsedArguments = getArgumentString(strParsedArguments);

                    Random rnd = new Random();
                    string strOutFile = Path.GetFileNameWithoutExtension(lstCommand[0]) + "_" + strParsedArguments + "_" + rnd.Next();
                    string strOut = this.strTempOutputPath + Path.DirectorySeparatorChar + strOutFile + ".txt";

                    AppExecute app = new AppExecute();
                    string strReturned = app.executeApp(lstCommand[0], (lstCommand.Count > 1) ? lstCommand[1] : null, this.strTempOutputPath);

                    File.WriteAllText(strOut, strReturned);
                }
                catch(Exception ex)
                {
                    Console.WriteLine("[-] Error: Command could not be executed: " + strCommands[i] + ", " + ex.Message);
                }
            }
        }

        void executeUserRegistryKeys()
        {
            for (int i = 0; i < strUserKeyFetch.Count; i++)
            {
                try
                {
                    string strUserKeyFetchFileName = Regex.Replace(strUserKeyFetch[i], "[^A-Za-z0-9 -]", "_");
                    Random rnd = new Random();
                    string strOutFile = "regkey_" + strUserKeyFetchFileName + "_" + rnd.Next();
                    string strOut = this.strTempOutputPath + Path.DirectorySeparatorChar + strOutFile + ".txt";

                    Helpers.printAllKeys(strOut, strUserKeyFetch[i]);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] Error: Http-request could not be executed: " + strHttpFetch[i] + ", " + ex.Message);
                }
            }
        }

        void executeHttpFetch()
        {
            for (int i = 0; i < strHttpFetch.Count; i++)
            {
                try
                {
                    string strHttpFileName = Regex.Replace(strHttpFetch[i], "[^A-Za-z0-9 -]", "_");
                    Random rnd = new Random();
                    string strOutFile = "httpget_" + strHttpFileName + "_" + rnd.Next();
                    string strOut = this.strTempOutputPath + Path.DirectorySeparatorChar + strOutFile + ".txt";

                    string strBody = null;

                    try
                    {

                        WebRequest request = WebRequest.Create(strHttpFetch[i]);
                        WebResponse response = request.GetResponse();
                        Stream dataStream = response.GetResponseStream();
                        StreamReader reader = new StreamReader(dataStream);
                        strBody = reader.ReadToEnd();
                    }
                    catch(Exception exHttp)
                    {
                        strBody = exHttp.StackTrace;
                    }

                    File.WriteAllText(strOut, strBody);
                }
                catch (Exception ex)
                {
                    Console.WriteLine("[-] Error: Http-request could not be executed: " + strHttpFetch[i] + ", " + ex.Message);
                }
            }
        }


        void listProcesses()
        {
            Process [] processes = System.Diagnostics.Process.GetProcesses();
            StringBuilder sb = new StringBuilder();

            foreach (Process p in processes)
            {
                try
                {
                    if (p.MainModule != null)
                    {
                        string strFileName = p.MainModule.FileName;

                        int parentProcess = Helpers.getParentProcess((uint)p.Id);

                        if (strFileName != null && File.Exists(strFileName))
                        {
                            string strMd5 = null;

                            using (var md5 = MD5.Create())
                            {
                                using (var stream = File.OpenRead(strFileName))
                                {
                                    byte[] bts = md5.ComputeHash(stream);
                                    strMd5 = BitConverter.ToString(bts).Replace("-", "").ToLowerInvariant();

                                    sb.Append(strFileName + ":" + strMd5 + ":" + p.Id + ":" + parentProcess + "\r\n");
                                }
                            }
                        }
                    }
                }
                catch(Exception ex1)// This can happen on access denied etc.
                {
                    Console.WriteLine(ex1.GetType().ToString() + ":" + ex1.Message);
                }
            }

            if (strTempOutputPath == null)
            {
                Console.WriteLine(sb.ToString());
            }
            else
            {
                string strBits = (Environment.Is64BitProcess) ? "64" : "32";
                string strOut = this.strTempOutputPath + Path.DirectorySeparatorChar + "allprocesses" + strBits + ".txt";
                File.WriteAllText(strOut, sb.ToString());
            }
        }


        void copyFilesRecursively(string strBaseFolder, string strFolder, List<string> lstIncludeFileTypesArg, int currentDepth,
            bool bStartPathCheck=true)
        {


            string[] strFile = null;

            if(lstGlobalAvoidDirectories.Count > 0)
            {
                foreach(string strAvoidGlobalDir in lstGlobalAvoidDirectories)
                {
                    if(strFolder.ToLower().IndexOf(strAvoidGlobalDir.ToLower()) >= 0)
                    {
                        return;
                    }
                }
            }

            bool bShouldCopyFile = true;

            if (lstGlobalIncludeDirectories.Count > 0)
            {
                bShouldCopyFile = false;

                foreach (string strIncludeGlobalDir in lstGlobalIncludeDirectories)
                {
                    Match mc = Regex.Match(strFolder, strIncludeGlobalDir, RegexOptions.IgnoreCase);

                    if(mc.Success)
                    {
                        bShouldCopyFile = true;
                        break;
                    }
                }
            }

            if (bShouldCopyFile)
            {
                try
                {
                    strFile = Directory.GetFiles(strFolder);
                }
                catch (System.UnauthorizedAccessException exAuthorization)
                {
                    string str = exAuthorization.GetType().ToString();
                    LogWriter.writeLog(str + ":" + strBaseFolder);
                    return;
                }
                catch (Exception exOther)
                {
                    LogWriter.writeLog(exOther.StackTrace);
                    return;
                }


                string strStartPath = strTempOutputPath + Path.DirectorySeparatorChar;

                // If folder does not exist then we create it.
                if (bStartPathCheck && strBaseFolder != strFolder && strFolder.Length > (strBaseFolder.Length + 1))
                {
                    string strExtra = strFolder.Substring(strBaseFolder.Length + 1);

                    strStartPath = strStartPath + strExtra;

                    if (!Directory.Exists(strStartPath))
                    {
                        try
                        {
                            Directory.CreateDirectory(strStartPath);
                        }
                        catch (Exception dirCreateException)
                        {
                            LogWriter.writeLog("[-] Error: could not create directory: " + strStartPath + ", " + dirCreateException.Message);
                            return;
                        }
                    }

                    strStartPath += Path.DirectorySeparatorChar;
                }

                foreach (string str in strFile)
                {
                    string strFname = Path.GetFileName(str);
                    string strDir = Path.GetDirectoryName(str);
                    string strExtension = Path.GetExtension(str).ToLower();

                    try
                    {
                        string strFileToCopy = string.Format("{0}{1}{2}", strDir, Path.DirectorySeparatorChar, strFname);
                        string strDestinationFile = string.Format("{0}{1}", strStartPath, strFname);

                        if (bShouldCopyFile) // 2020-06-23
                        {
                            LogWriter.writeLog("[+] Copying file " + strFileToCopy + " to " + strDestinationFile);

                            if (lstIncludeFileTypesArg.Count > 0)
                            {
                                if (strExtension == ".zip")
                                {
                                    // 2020-02-26 - switched these two lines... yes bad bug, bad bug.
                                    File.Copy(strFileToCopy, strDestinationFile);
                                    Helpers.deleteInsideZipNotMatching(strDestinationFile, lstIncludeFileTypesArg);
                                }
                                else if (lstIncludeFileTypesArg.Contains(strExtension))
                                {
                                    FileInfo finf = new FileInfo(strFileToCopy);

                                    if (finf.Length < fileSizeLimit && fileSizeLimit > 0)
                                    {
                                        File.Copy(strFileToCopy, strDestinationFile);
                                    }
                                    else
                                    {
                                        LogWriter.writeLog("Too big file to copy: " + strFileToCopy + ":" + finf.Length);
                                    }
                                }
                            }
                            else
                            {
                                File.Copy(strFileToCopy, strDestinationFile);
                            }
                        }
                    }
                    catch (Exception ex2)
                    {
                        LogWriter.writeLog("[-] Error: could not copy file" + strFname + ":" + ex2.Message);
                    }
                }
            }

            string[] strDirectories = new string[] { };

            try
            {
                strDirectories = Directory.GetDirectories(strFolder);
            }
            catch(Exception exFaildDir)
            {
                ;
                return;
            }

            if (maxFolderDepth > 0 && currentDepth > maxFolderDepth)
            {
                //LogWriter.writeLog("[+] Max folder depth reached");
                return;
            }

            foreach (string strDir in strDirectories)
            {
                copyFilesRecursively(strBaseFolder, strDir, lstIncludeFileTypesArg, currentDepth+1);
            }

        }

        void fetchQuarantine()
        {
            var bts2 = System.Convert.FromBase64String(strPublicKey);
            string strOutput = Path.GetTempFileName();
            string strEncryptedFile = Path.GetTempFileName();

            if (strDirectory.Count < 1) strDirectory.Add(@"c:\quarantine");

            if (this.strTempOutputPath != null)
            {
                foreach (string strDirSpec in strDirectory)
                {
                    LogWriter.writeLog("[+] Copying all files from  " + strDirSpec + " to "+ strTempOutputPath);

                    try
                    {

                        copyFilesRecursively(strDirSpec, strDirSpec, this.strIncludeOnlyFiletypes, 0);
                    }
                    catch (Exception ex3)
                    {
                        LogWriter.writeLog("[-] Error when trying to copy files. Reverting to copying directly from folder: " + ex3.Message);
                    }
                }
            }


            Helpers.deleteFile(strEncryptedFile);
            Helpers.deleteFile(strOutput);

            LogWriter.closeLog(); // We need to close the log so that we can include the log file in the archive.

            // Create the zip-archive
            System.IO.Compression.ZipFile.CreateFromDirectory(strTempOutputPath, strOutput);

            // Encrypt the zip-archive
            if(!Encryption.encryptFile(strEncryptedFile, strOutput, bts2))
            {
                LogWriter.writeLog("[-] Error when encrypting file");
                return;
            }
 
            Helpers.deleteFile(strOutput); // Delete the temporary file

            //// Send the encrypted file
            try
            {
                LogWriter.writeLog("[+] Uploading file to FTP-server...");
                sendFile(strEncryptedFile);
            }
            catch(Exception exFTP)
            {
                LogWriter.writeLog("[-] Error when trying to upload file: " + exFTP.Message);
            }

            Helpers.deleteFile(strEncryptedFile);

            //// Cleanup
            LogWriter.writeLog("[+] All done!");
        }

        // Send the encrypted file
        void sendFile(string strEncryptedFile)
        {
            
            string strDate = DateTime.Now.ToString("yyyyddMMhhMMss");
            System.Net.FtpWebRequest ftp = (System.Net.FtpWebRequest)System.Net.FtpWebRequest.Create(strFTPServer + "/" + strDate + "-file.bin");
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
        
        class GraphNode
        {
            public string strLabel;
            public int id;
            public int parentId;
            public GraphNode parent;
            public string strMD5;

            public List<GraphNode> lstChildren = new List<GraphNode>();
        }

        Hashtable treeGraphDraw(string strFilename)
        {
            Hashtable htGraph = new Hashtable();


            string[] strLines = File.ReadAllLines(strFilename);
            char[] delim = new char[] { ':' };

            foreach(string strLine in strLines)
            {
                string[] strSplitted = strLine.Split(delim);
                int adder = 0;
                string strVolumeLabel = string.Empty;

                if(strSplitted.Length > 3)
                {
                    if(strSplitted.Length == 5)
                    {
                        adder++;
                        strVolumeLabel = strSplitted[0] + ":"; // Bizarre consequence of bad delimiter choice.
                    }
                    int id = Convert.ToInt32(strSplitted[2+ adder]);
                    int parentId = Convert.ToInt32(strSplitted[3+ adder]);

                    GraphNode gnode = new GraphNode()
                    {
                        strLabel = strVolumeLabel + strSplitted[0+ adder],
                        strMD5 =  strSplitted[1+ adder],
                        id = id,
                        parentId = parentId
                    };

                    if (htGraph.ContainsKey(parentId))
                    {
                        GraphNode gnParent = (GraphNode) htGraph[parentId];
                        gnParent.lstChildren.Add(gnode);
                        gnode.parent = gnParent;
                    }
                    else
                    {
                        
                        List<GraphNode> lstNodesToRemove = new List<GraphNode>();
                        
                        // Reorganize when we get a new root-node.
                        foreach(int childrenIds in htGraph.Keys)
                        {
                            GraphNode child = (GraphNode)htGraph[childrenIds];

                            if (child.parentId == id)
                            {
                                child.parent = gnode;
                                gnode.lstChildren.Add(child);
                                lstNodesToRemove.Add(child);
                            }
                        }

                        foreach(GraphNode nodeToRemove in lstNodesToRemove)
                        {
                            htGraph.Remove(nodeToRemove.id);
                        }

                        htGraph.Add(id, gnode);
                    }
                }
            }

            return htGraph;
        }

        void traverseNodes(Hashtable htGraph)
        {
            foreach (int key in htGraph.Keys)
            {
                GraphNode dNode = (GraphNode)htGraph[key];

                displayNode(dNode, "");
            }
        }

        void displayNode(GraphNode dNode, string strPrefix)
        {
            Console.WriteLine(strPrefix + ">" + dNode.strLabel + "(" + dNode.id + ")" + dNode.parentId);

            foreach(GraphNode gn in dNode.lstChildren)
            {
                displayNode(gn, strPrefix + "---");
            }
        }

        void packFolders()
        {
            foreach(DirectoryFetcher dfetcher in this.lstDirectoryFetcher)
            {
                copyFilesRecursively(dfetcher.strDirectoryPath, dfetcher.strDirectoryPath, dfetcher.lstFileTypes, 0);
            }
        }

        static void Main(string[] args)
        {
            string strTempOut = Program.getFolderCopyDirectory();
            LogWriter.strTempDirectory = strTempOut;
            LogWriter.writeLog("[+] MiniTriage v0.5 - James Dickson 2020");

            
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
                else if (args[i] == "--listprocesses") // minitriage --onlyprocesses
                {
                    LogWriter.writeLog("[+] Only executing processes-test ...");

                    Program p = new Program();
                    p.strTempOutputPath = null;
                    p.listProcesses();

                    return;
                }
                else if (args[i] == "--graph") // minitriage --onlyprocesses
                {
                    LogWriter.writeLog("[+] Graph...");

                    Program p = new Program();
                    Hashtable htGraph = p.treeGraphDraw(args[++i]);
                    p.traverseNodes(htGraph);


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
                        if(p.lstDirectoryFetcher.Count > 0)
                        {
                            LogWriter.writeLog("[+] Packing folders ");
                            p.packFolders();
                        }

                    }
                    catch (Exception ex4)
                    {
                        LogWriter.writeLog("[-] Error when packing folders: " + ex4.StackTrace);
                    }

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
                        LogWriter.writeLog("[+] Executing http request... output to " + p.strTempOutputPath);
                        p.executeHttpFetch();
                    }
                    catch (Exception ex5)
                    {
                        LogWriter.writeLog("[-] Error when executing httprequest: " + ex5.StackTrace);
                    }

                    try
                    {
                        LogWriter.writeLog("[+] Fetching user registry keys... output to " + p.strTempOutputPath);
                        p.executeUserRegistryKeys();
                    }
                    catch (Exception ex5)
                    {
                        LogWriter.writeLog("[-] Error when executing user key get: " + ex5.StackTrace);
                    }

                    try
                    {
                        LogWriter.writeLog("[+] Listing processes..");
                        p.listProcesses();
                    }
                    catch (Exception ex4)
                    {
                        LogWriter.writeLog(ex4.Message);
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
