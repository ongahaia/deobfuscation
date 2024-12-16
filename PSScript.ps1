

function invoke_deob_function($func2, $paramaters)
{
# make ps object of func
$func_ps =$func2 | ForEach-Object { New-Object psobject -Property @{
    Name = $_.Name
    FullName = $_.FullName
    ReturnType = $_.ReturnType.FullName
    mdtoken = $_.MDToken
    Parameters = foreach ($param in $_.Parameters) {
        @{
            Name = $param.Name
            ParameterType = $param.ParameterType.FullName
        }
    }
}
}

# resolve the new method 
$func_conc = $assembly.ManifestModule.ResolveMethod($func_ps.mdtoken.toint32())

    Write-Host "Deobfuscaation func invoked" -ForegroundColor DarkRed
    return $func_conc.invoke($null, $paramaters)
}

function replace_deobf_method($all_methods, $deobfs){

foreach ($amethod in $all_methods)
{
    #write-host $method
    if(-not $amethod.HasBody){continue}
    $instrucions = $amethod.MethodBody.Instructions.ToArray()
    foreach($instr in $instrucions)
    {
    # Write-Host "Method analysing: $amethod" -ForegroundColor DarkYellow
    
        if($instr.OpCode.Name -like "call" -and $instr.operand.ismethod -and $instr.operand.NumberOfGenericParameters -eq 1)
        {
         #write-host "Trying to catch deobf methods!!!!"
                          
          $inst_idx= $amethod.MethodBody.Instructions.IndexOf($instr)
          #$in | ForEach-Object {if($_.opcode.name -like "call" -and $_.operand.NumberOfGenericParameters -eq 1) {$_.operand}}
          #Write-Host $amethod.MethodBody.Instructions[$inst_idx-1]
          #if($instr.operand.parameters.count -eq 1 -and $instr.operand.parameters[0].Type.FullName -eq "system.int32" -and $instr.operand.ReturnType.FullName -eq "system.string")
          if ($amethod.MethodBody.Instructions[$inst_idx-1].opcode.name -eq "Ldc.i4")
           {
           $func = $instr.Operand
           #replace the call with the return value and nop the one obove
           write-host "Found a deobfuscation method, lets replace it" -ForegroundColor DarkMagenta
           $para =@()
           $para += $amethod.MethodBody.Instructions[($inst_idx - 1)].operand
           $string = invoke_deob_function -func2 $func -paramaters $para
          $amethod.MethodBody.Instructions[$inst_idx].Opcode = [dnlib.DotNet.Emit.OpCodes]::Ldstr
           $amethod.MethodBody.Instructions[$inst_idx].Operand = $string
           $amethod.MethodBody.Instructions[$inst_idx-1].Opcode = [dnlib.DotNet.Emit.OpCodes]::NOP
           write-host $string
           }
          }
$amethod.MethodBody.UpdateInstructionOffsets() | Out-Null
    }
}
   Write-Host "ALL DOne!!!" -ForegroundColor Red
}

function find_deobfuscation_method($methods)
{
  $matchingCandidates = @()
  foreach ($candidate in $methods)
  {

    if (-not $candidate.hasbody) {continue}
    $tokenValue = [int]::Parse($candidate.mdtoken, [System.Globalization.NumberStyles]::HexNumber)
    if($tokenValue -ge  0x06000004 -and $tokenValue -le 0x06000008)
   
    {
       $matchingCandidates += $candidate

    }
  }

    if ($matchingCandidates.Count -gt 0) {return $matchingCandidates}
      else { return $null }
}

$assembly = [reflection.assembly]::loadfile("C:\Users\malware\Desktop\ConfuserEx\cleaned_2.dll")
$patched = "C:\Users\malware\Desktop\ConfuserEx\cleaned_2_patched.dll"
#[system.reflection.assembly]::loadfile("C:\Users\malware\Desktop\ConfuserEx\dnlib.dll")
[System.Reflection.Assembly]::LoadFile("C:\Users\malware\Desktop\TOOLS\de4dot-cex\bin\dnlib.dll")
$moduleDefMD = [dnlib.DotNet.ModuleDefMD]::Load("C:\Users\malware\Desktop\ConfuserEx\cleaned_2.dll")
$trammy_methods = $moduleDefMD.GetTypes().ForEach{$_.methods}

$deobf_methods = find_deobfuscation_method -methods $trammy_methods
$deobf_methods_PS = $deobf_methods | ForEach-Object { New-Object psobject -Property @{
    Name = $_.Name
    FullName = $_.FullName
    ReturnType = $_.ReturnType.FullName
    mdtoken = $_.MDToken
    Parameters = foreach ($param in $_.Parameters) {
        @{
            Name = $param.Name
            ParameterType = $param.ParameterType.FullName
        }
    }
}
}
$conc_deobf = @($deobf_methods_PS | ForEach-Object {$assembly.ManifestModule.ResolveMethod($_.mdtoken.toint32())} | ForEach-Object {$_.MakeGenericMethod([String])})
$global:methodsToRemove = @($deobf_methods_PS)
replace_deobf_method -all_methods $trammy_methods -deobfs $deobf_methods

#$method = $assembly.ManifestModule.ResolveMethod(0x06000004)
#$method_ctor = $assembly.ManifestModule.ResolveMethod(0x06000001)
#$method_concrete = $method.MakeGenericMethod([string])
#$param=@(-11596244)
#$method_concrete.Invoke($null,$Param)

$moduleWriterOptions = [dnlib.DotNet.Writer.ModuleWriterOptions]::new($moduleDefMD)
$moduleWriterOptions.MetadataOptions.Flags = $moduleWriterOptions.MetadataOptions.Flags -bor [dnlib.DotNet.Writer.MetadataFlags]::KeepOldMaxStack

$moduleDefMD.Write($patched, $moduleWriterOptions)
