using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Collections;
using System.IO.Compression;

using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;

namespace minitriage
{
    class Helpers
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        // https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
        [StructLayout(LayoutKind.Sequential)]
        struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
        };

        // Returns parent process id
        public static int getParentProcess(uint processID)
        {
            PROCESSENTRY32 pe32 = new PROCESSENTRY32()
            {
                dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32))
            };

            // https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
            IntPtr hSnap = CreateToolhelp32Snapshot(0x02, processID);

            if (hSnap == null)
            {
                LogWriter.writeLog("[-] Error: Could not enumerate processes. CreateToolHelp32Snapshot returned -1");
                return -1;
            }

            try
            {
                if (!Process32First(hSnap, ref pe32))
                {
                    int errorCode = Marshal.GetLastWin32Error();

                    LogWriter.writeLog("[-] Error: Could not enumerate processes: " + errorCode);

                    return -1;
                }

                do
                {
                    if (pe32.th32ProcessID == processID) return (int)pe32.th32ParentProcessID;

                } while (Process32Next(hSnap, ref pe32));
            }
            finally
            {
                CloseHandle(hSnap);
            }
            

            return -1;
        }


        static bool printKeys(string strUser, StreamWriter sw, string strSubkey)
        {
            NTAccount account = new NTAccount(strUser);
            SecurityIdentifier secId = (SecurityIdentifier)account.Translate(typeof(SecurityIdentifier));

            if (secId == null) return false;

            string strSID = secId.ToString();

            Microsoft.Win32.RegistryKey regKey = Microsoft.Win32.Registry.Users;

            string strRegistryKey = strSID + "\\" + strSubkey;

            LogWriter.writeLog("[+] Opening key: " + strRegistryKey);

            regKey = regKey.OpenSubKey(strRegistryKey, true);

            if (regKey != null)
            {
                foreach (string strKey in regKey.GetSubKeyNames())
                {
                    LogWriter.writeLog("[+] Enumerating: " + strKey);

                    sw.WriteLine(strKey);
                }

                string[] strNames = regKey.GetValueNames();

                foreach (string strName in strNames)
                {
                    LogWriter.writeLog("[+] Name: " + strName);
                    sw.WriteLine(strRegistryKey + ": " + strName + ": " + regKey.GetValue(strName));
                }

                return true;
            }
            LogWriter.writeLog("[-] Key could not be opened");

            return false;
        }
        


        // We need a secure and simple way without wmi etc to get users that has logged in
        static string[] getUsers()
        {
            string[] strUsers = Directory.GetDirectories("c:\\Users");

            for (int i = 0; i < strUsers.Length; i++)
            {
                int last = strUsers[i].LastIndexOf('\\');

                if (last > 0 && ((last + 1) < strUsers[i].Length))
                {
                    strUsers[i] = strUsers[i].Substring(last + 1);
                }
            }

            return strUsers;
        }

        public static void printAllKeys(string strFilename, string strSubkey)
        {
            string[] strUsers = getUsers();

            if (strUsers != null && strUsers.Length > 0)
            {
                using (StreamWriter sw = new StreamWriter(strFilename))
                {
                    foreach (string strUser in strUsers)
                    {
                        try
                        {
                            printKeys(strUser, sw, strSubkey);
                        }
                        catch (Exception ex1)
                        {
                            sw.WriteLine("[-] Could not get " + strSubkey + " for " + strUser + " :" + ex1.Message);
                        }

                    }
                }
            }
        }

        public static void deleteInsideZipNotMatching(string strFile, List <string> lstFiles)
        {
            using (FileStream zipToOpen = new FileStream(strFile, FileMode.Open))
            {
                using (ZipArchive archive = new ZipArchive(zipToOpen, ZipArchiveMode.Update))
                {
                    List<ZipArchiveEntry> lstEntriesToDelete = new List<ZipArchiveEntry>();

                    foreach (var item in archive.Entries)
                    {
                        if (!lstFiles.Contains(Path.GetExtension(item.Name)))
                        {
                            lstEntriesToDelete.Add(item);
                        }
                    }

                    foreach(var entry in lstEntriesToDelete)
                    {
                        entry.Delete();
                    }
                }

            }
        }

        public static void deleteFile(string strFile)
        {
            try
            {

                if (File.Exists(strFile))
                {
                    File.Delete(strFile);
                }
            }
            catch (Exception ex)
            {
                LogWriter.writeLog("[-] Error when deleting file: " + ex.Message);
            }
        }

        public static List<string> parseCommand(string strCommand)
        {
            List<string> lstRetval = new List<string>();

            if (strCommand.IndexOf('"') == 0)
            {
                string strSub = strCommand.Substring(1);

                int pos = strSub.IndexOf('"');

                string strExe = strSub.Substring(0, pos);
                string strArguments = strSub.Substring(pos + 1);

                lstRetval.Add(strExe);
                lstRetval.Add(strArguments);
            }
            else if (strCommand.IndexOf(' ') > 0)
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
    }
}
