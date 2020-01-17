using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Collections;
using System.IO.Compression;

namespace minitriage
{
    class Helpers
    {

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
