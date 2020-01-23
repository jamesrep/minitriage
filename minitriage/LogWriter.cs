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
    class LogWriter
    {
        static FileStream fsOut = null;
        static StreamWriter swOut = null;
        static bool bCheckedWrite = false;
        public static string strTempDirectory = null;

        public static void closeLog()
        {
            if (fsOut != null)
            {
                try
                {
                    fsOut.Close();
                    fsOut = null;
                    bCheckedWrite = false;
                }
                catch
                {

                }
            }
        }

        public static void writeLog(string strLog)
        {
            Console.WriteLine(strLog);

            try
            {
                if (!bCheckedWrite)
                {
                    bCheckedWrite = true;

                    string strDir = @"c:\jamestest";

                    if (strTempDirectory != null && Directory.Exists(strTempDirectory))
                    {
                        strDir = strTempDirectory;
                    }

                    if (Directory.Exists(strDir))
                    {
                        Random rnd = new Random();

                        fsOut = new FileStream(strDir + "\\" + DateTime.Now.ToString("yyyyMMdd_HHmmss") + "_" + rnd.Next() + ".txt", FileMode.OpenOrCreate);
                        swOut = new StreamWriter(fsOut);
                    }
                }

                if (swOut != null)
                {
                    swOut.WriteLine(DateTime.Now.ToString("yyyyMMddHHmmss") + ":" + strLog);
                    swOut.Flush();
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error on log: " + ex.Message);
            }
        }
    }

}
