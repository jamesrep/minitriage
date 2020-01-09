using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.IO;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography;

using System.Runtime.ConstrainedExecution;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using System.Collections;


namespace minitriage
{
    class AppExecute
    {
        public string executeApp(string strExe, string strArguments, string strOutputPath, string strBinaryOutput=null, bool bText=false, string strInput=null)
        {
            StreamReader sr = null;
            StreamReader srError = null;
            Process proc = new Process();
            proc.StartInfo = new ProcessStartInfo();

            bool bShellExecute = proc.StartInfo.UseShellExecute;
            //bool bNoWindow = true; // proc.StartInfo.CreateNoWindow;
            proc.StartInfo.CreateNoWindow = true;

            if (!File.Exists(strExe))
            {
                Console.WriteLine("[-] Error: The executable does not exist: " + strExe);
                return null;
            }

            Console.WriteLine("[+] Executing: " + strExe + " " + strArguments);

            proc.StartInfo.WorkingDirectory = strOutputPath;

            if (strInput != null)
            {
                proc.StartInfo.UseShellExecute = true;
            }
            else
            {

                proc.StartInfo.UseShellExecute = false;
                proc.StartInfo.RedirectStandardOutput = true;
                proc.StartInfo.RedirectStandardError = true;


            }

            proc.StartInfo.Arguments = strArguments;
            proc.StartInfo.FileName = strExe;
            proc.Start();

            if (proc.StartInfo.RedirectStandardOutput)
            {
                sr = proc.StandardOutput;
                srError = proc.StandardError;
            }

            if (strInput != null && proc.StartInfo.RedirectStandardInput)
            {
                proc.StandardInput.WriteLine(strInput);
            }

            string strAll = null;
            string strAllError = null;

            if (strBinaryOutput != null && proc.StartInfo.RedirectStandardOutput)
            {
                if (bText)
                {
                    strAll = sr.ReadToEnd();
                    strAllError = srError.ReadToEnd();

                    using (var fs = new FileStream(strBinaryOutput, FileMode.OpenOrCreate))
                    {
                        StreamWriter srw = new StreamWriter(fs);

                        if (strAllError != null && strAllError.Length > 0)
                        {
                            srw.WriteLine(strAllError);
                        }
                        srw.WriteLine(strAll);

                        srw.Close();
                    }
                }
                else
                {
                    using (var fileStream = new FileStream(strBinaryOutput, FileMode.OpenOrCreate))
                    {
                        var br = new BinaryReader(proc.StandardOutput.BaseStream);

                        while (!proc.StandardOutput.EndOfStream)
                        {
                            byte[] buffer = new byte[8112];
                            int readBytes = br.Read(buffer, 0, buffer.Length);

                            if (readBytes > 0)
                            {
                                fileStream.Write(buffer, 0, readBytes);
                            }
                            else
                            {
                                break;
                            }
                        }
                    }
                }
            }
            else if (proc.StartInfo.RedirectStandardOutput)
            {
                strAll = sr.ReadToEnd();
                strAllError = srError.ReadToEnd();
            }

            proc.WaitForExit(); // This will fail if we start as a non admin and the process switches to admin

            if (proc.StartInfo.RedirectStandardOutput)
            {
                sr.Close();
                srError.Close();
            }

            if (strAllError != null && strAllError.Length > 0)
            {
                return "Errors: \r\n" + strAllError + "\r\n---------\r\n" + strAll;
            }

            return strAll;
        }
    }
}
