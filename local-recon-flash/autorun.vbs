' autorun.vbs - скрытый запуск Local Recon Suite
Set objShell = CreateObject("WScript.Shell")
Set objFSO = CreateObject("Scripting.FileSystemObject")

scriptPath = objFSO.GetParentFolderName(WScript.ScriptFullName)
exePath = scriptPath & "\local_recon_suite.exe"
outputDir = scriptPath & "\reports"

If Not objFSO.FolderExists(outputDir) Then
    objFSO.CreateFolder(outputDir)
End If

' Запускаем полностью скрыто (0 = скрытое окно)
' --auto автоматически сохраняет отчёт без вопросов
objShell.Run """" & exePath & """ --auto --format csv --out-dir """ & outputDir & """", 0, False
