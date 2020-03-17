# James simpla kompilera-verktyg-kommando...
$dict = New-Object 'system.collections.generic.dictionary[[string],[string]]'
$dict.Add("CompilerVersion","v4.0")



[string[]]$references=@("System.dll",
                        "System.Xml.dll",
                        "System.Core.dll",
                        "System.Text.RegularExpressions.dll",
                        "System.IO.Compression.ZipFile.dll",
                        "System.IO.Compression.FileSystem.dll",
                        "System.Diagnostics.Process.dll",
                        "netstandard.dll",
                        "System.IO.Compression.dll")

$strWorkDirectory = get-location
$codeprovider = new-object Microsoft.CSharp.CSharpCodeProvider $dict

$icc = $codeprovider.CreateCompiler()
$opt = new-object System.CodeDom.Compiler.CompilerParameters

$opt.CompilerOptions = "-platform:x64";

$opt.ReferencedAssemblies.AddRange($references)
$opt.GenerateExecutable = $true
$opt.MainClass = "minitriage.Program"
$opt.OutputAssembly = "$strWorkDirectory\minitriage64.exe"

$strSources = Get-ChildItem $strWorkDirectory -Include "*.cs" -recurse;
$strFullPaths = ($strSources | % { $_.FullName; });

write-host "[+] Compiling 64-bit executable ..."
$result = $icc.CompileAssemblyFromFileBatch($opt, $strFullPaths)

write-host "[+] Done with nr of errors:"  $result.Errors.Count

if($result.Errors.Count -gt 0)
{
    write-host $result.Errors
}

$opt.CompilerOptions = "-platform:x86";
$opt.OutputAssembly = "$strWorkDirectory\minitriage.exe"

write-host "[+] Compiling 32-bit executable ..."
$result = $icc.CompileAssemblyFromFileBatch($opt, $strFullPaths)

write-host "[+] Done with nr of errors:"  $result.Errors.Count

if($result.Errors.Count -gt 0)
{
    write-host $result.Errors
}


