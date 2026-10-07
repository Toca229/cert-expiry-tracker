#Requires -Version 5.1

# ==================== НАСТРОЙКИ ====================
$AlertDays = 14  # За сколько дней начинать предупреждать
$CooldownHours = 2 # Через сколько высылать повтороное уведомление
$LogRetentionDays = 1 # Сколько дней хранить записи в лог-файле

# Настройки почты (SMTP)
$SmtpServer = "smtp.gmail.com"         #Если нужна mail.ru то замените на smtp.mail.ru
$SmtpPort   = 587                    
$UseSsl     = $true
$SmtpUser   = "ваша почта@gmail.com"     #Ваша почта для отправки
$SmtpPass   = "ваш пароль"       #Ваш пароль приложений для отправки   
$EmailTo    = "куда пишем"     #Почта куда отправляем уведы

$LogPath    = "$PSScriptRoot\cert_check.log" #логи
$DbPath     = "$PSScriptRoot\certs_db.json"  # <--- Файл нашей базы данных
$SpamFilter = "$PSScriptRoot\last_alert.txt" # Файл-таймер для защиты от спама
# ===================================================

$Now = Get-Date
$Threshold = $Now.AddDays($AlertDays)

function Write-Log {
    param([string]$Message)
    $TimeStamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $LogPath -Value "[$TimeStamp] $Message" -Encoding UTF8
}

function Show-WindowsNotification {
    param([string]$Title, [string]$Text)
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $notify = New-Object System.Windows.Forms.NotifyIcon
    $notify.Icon = [System.Drawing.SystemIcons]::Warning
    $notify.BalloonTipIcon = [System.Windows.Forms.ToolTipIcon]::Warning
    $notify.BalloonTipTitle = $Title
    $notify.BalloonTipText = $Text
    $notify.Visible = $true

    $notify.ShowBalloonTip(10000) 
    Start-Sleep -Seconds 2
    $notify.Dispose()
}

function Send-AlertEmail {
    param([string]$Subject, [string]$HtmlBody)
    try {
        $mail = New-Object System.Net.Mail.MailMessage
        $mail.From = New-Object System.Net.Mail.MailAddress($SmtpUser, "Мониторинг ЭЦП")
        
        foreach ($addr in ($EmailTo -split ',')) {
            if (-not [string]::IsNullOrWhiteSpace($addr)) {
                $mail.To.Add($addr.Trim())
            }
        }
        
        $mail.Subject = $Subject
        $mail.Body = $HtmlBody
        $mail.IsBodyHtml = $true
        $mail.BodyEncoding = [System.Text.Encoding]::UTF8
        $mail.SubjectEncoding = [System.Text.Encoding]::UTF8

        $smtp = New-Object System.Net.Mail.SmtpClient($SmtpServer, $SmtpPort)
        $smtp.EnableSsl = $UseSsl
        $smtp.Credentials = New-Object System.Net.NetworkCredential($SmtpUser, $SmtpPass)
        $smtp.Timeout = 15000

        $smtp.Send($mail)
        $mail.Dispose()
        $smtp.Dispose()
        Write-Log "Письмо успешно отправлено."
    }
    catch {
        Write-Log "Ошибка отправки почты: $($_.Exception.Message)"
    }
}

# --- 0. ОЧИСТКА СТАРЫХ ЛОГОВ ---
if (Test-Path $LogPath) {
    $CutoffString = $Now.AddDays(-$LogRetentionDays).ToString("yyyy-MM-dd")
    $LogLines = Get-Content $LogPath -ErrorAction SilentlyContinue
    if ($LogLines) {
        $FilteredLines = $LogLines | Where-Object {
            # Проверяем дату в начале строки. Строковое сравнение yyyy-MM-dd работает идеально.
            if ($_ -match '^\[(\d{4}-\d{2}-\d{2})') {
                $matches[1] -ge $CutoffString
            } else {
                $true # Оставляем строки без даты на всякий случай
            }
        }
        $FilteredLines | Set-Content $LogPath -Encoding UTF8 -ErrorAction SilentlyContinue
    }
}

Write-Log "--- ЗАПУСК ПРОВЕРКИ ---"

# --- 1. ЧТЕНИЕ БАЗЫ ---
$KnownCerts = @{}
if (Test-Path $DbPath) {
    try {
        $DbData = Get-Content $DbPath -Raw -Encoding UTF8 | ConvertFrom-Json
        foreach ($item in $DbData) { $KnownCerts[$item.Thumbprint] = $item }
    } catch { Write-Log "Ошибка чтения БД." }
}

# --- 2. СБОР ТЕКУЩИХ СЕРТИФИКАТОВ ---
$CertsUser = Get-ChildItem -Path Cert:\CurrentUser\My -Recurse -ErrorAction SilentlyContinue | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] }
$CertsMachine = Get-ChildItem -Path Cert:\LocalMachine\My -Recurse -ErrorAction SilentlyContinue | Where-Object { $_ -is [System.Security.Cryptography.X509Certificates.X509Certificate2] }

$AllCerts = @($CertsUser) + @($CertsMachine) | Sort-Object -Property Thumbprint -Unique

foreach ($cert in $AllCerts) {
    $CN = if ($cert.Subject -match 'CN=([^,]+)') { $matches[1] } else { $cert.FriendlyName }
    if ([string]::IsNullOrWhiteSpace($CN)) { $CN = "Без имени (CN)" }
    $Org = if ($cert.Subject -match 'O=([^,]+)') { $matches[1] } else { "" }
    $INN = if ($cert.Subject -match 'ИНН(?:ЮЛ)?=([0-9]+)') { $matches[1] } else { "" }

    $KnownCerts[$cert.Thumbprint] = [PSCustomObject]@{
        Thumbprint = $cert.Thumbprint
        CN         = $CN
        Org        = $Org
        INN        = $INN
        NotAfter   = $cert.NotAfter.ToString("yyyy-MM-ddTHH:mm:ss")
    }
}

# --- 3. АНАЛИЗ БАЗЫ И ГРУППИРОВКА ---
$ValidCertsToSave = @()
$ExpiringList = @()
$GroupedCerts = @{}

foreach ($key in @($KnownCerts.Keys)) {
    $item = $KnownCerts[$key]
    $itemDate = [datetime]::ParseExact($item.NotAfter, "yyyy-MM-ddTHH:mm:ss", $null)
    
    if ($itemDate -lt $Now) { continue } # Удаляем просроченный мусор

    $ValidCertsToSave += $item

    # Уникальный ключ: Имя + Организация + ИНН
    $GroupKey = "$($item.CN)_$($item.Org)_$($item.INN)"
    
    if (-not $GroupedCerts.ContainsKey($GroupKey)) {
        $GroupedCerts[$GroupKey] = @()
    }
    $GroupedCerts[$GroupKey] += [PSCustomObject]@{
        Item = $item
        Date = $itemDate
        DaysLeft = [math]::Floor(($itemDate - $Now).TotalDays)
    }
}

$ValidCertsToSave | ConvertTo-Json -Depth 3 | Set-Content $DbPath -Encoding UTF8

# Проверяем группы (игнорируем старые дубли, если есть новая ЭЦП)
foreach ($key in $GroupedCerts.Keys) {
    $CertsForEntity = $GroupedCerts[$key] | Sort-Object Date -Descending
    $NewestCert = $CertsForEntity[0]
    
    Write-Log "ОК [База]: $($NewestCert.Item.CN) | Осталось: $($NewestCert.DaysLeft) дн. (до $($NewestCert.Date.ToString('dd.MM.yyyy')))"
    
    if ($CertsForEntity.Count -gt 1) {
        Write-Log "  -> Найдено старых дублей для $($NewestCert.Item.CN): $($CertsForEntity.Count - 1) шт. (Игнорируем, так как есть свежий)"
    }

    if ($NewestCert.Date -le $Threshold) {
        $ExpiringList += [PSCustomObject]@{
            CN         = $NewestCert.Item.CN
            Org        = $NewestCert.Item.Org
            INN        = $NewestCert.Item.INN
            Expires    = $NewestCert.Date.ToString("dd.MM.yyyy HH:mm")
            DaysLeft   = $NewestCert.DaysLeft
            Thumbprint = $NewestCert.Item.Thumbprint
        }
    }
}

# --- 4. РЕАКЦИЯ И ЗАЩИТА ОТ СПАМА ---
if ($ExpiringList.Count -gt 0) {
    $CanAlert = $true
    if (Test-Path $SpamFilter) {
        $LastAlertTime = [datetime]::ParseExact((Get-Content $SpamFilter -Raw).Trim(), "yyyy-MM-ddTHH:mm:ss", $null)
        if (($Now - $LastAlertTime).TotalHours -lt $CooldownHours) {
            $CanAlert = $false
        }
    }

    if ($CanAlert) {
        Write-Log "Отправляем уведомления (таймер спама разрешил)."

        $ToastTitle = "Скоро истекает ЭЦП ($($ExpiringList.Count) шт.)"
        $ShortDetails = @()
        foreach ($item in ($ExpiringList | Select-Object -First 3)) { $ShortDetails += "$($item.CN) (осталось $($item.DaysLeft) дн.)" }
        if ($ExpiringList.Count -gt 3) { $ShortDetails += "...и ещё $($ExpiringList.Count - 3) шт." }
        Show-WindowsNotification -Title $ToastTitle -Text ($ShortDetails -join "`n")

        $EmailSubject = "Внимание: истекает срок действия ЭЦП ($($ExpiringList.Count) шт.) — $env:COMPUTERNAME"
        $TableRows = ""
        foreach ($c in ($ExpiringList | Sort-Object DaysLeft)) {
            $statusColor = if ($c.DaysLeft -le 5) { "#ff4d4f" } else { "#faad14" } 
            $TableRows += "<tr style='border-bottom: 1px solid #e8e8e8;'><td style='padding: 10px;'><b>$($c.CN)</b><br><small style='color: #666;'>$($c.Org) $($c.INN)</small></td><td style='padding: 10px; text-align: center; font-weight: bold; color: $statusColor;'>$($c.DaysLeft) дн.</td><td style='padding: 10px; text-align: center;'>$($c.Expires)</td><td style='padding: 10px; font-family: monospace; font-size: 11px; color: #555;'>$($c.Thumbprint)</td></tr>"
        }

        $HtmlContent = "<html><head><meta charset='utf-8'></head><body style='font-family: Arial, sans-serif; color: #333; line-height: 1.5;'><h2 style='color: #faad14;'>⚠️ Требуется замена сертификатов ЭЦП</h2><p>Компьютер: <b>$env:COMPUTERNAME</b> | Пользователь: <b>$env:USERNAME</b></p><table style='width: 100%; border-collapse: collapse; margin-top: 15px;'><thead><tr style='background-color: #f5f5f5; text-align: left; border-bottom: 2px solid #ccc;'><th style='padding: 10px;'>Владелец / Организация</th><th style='padding: 10px; text-align: center;'>Осталось</th><th style='padding: 10px; text-align: center;'>Действует до</th><th style='padding: 10px;'>Отпечаток (SHA1)</th></tr></thead><tbody>$TableRows</tbody></table></body></html>"

        Send-AlertEmail -Subject $EmailSubject -HtmlBody $HtmlContent

        $Now.ToString("yyyy-MM-ddTHH:mm:ss") | Set-Content $SpamFilter -Encoding UTF8
    } else {
        Write-Log "Найдены истекающие ЭЦП, но уведомления на паузе ($CooldownHours ч.) для защиты от спама."
    }
} else {
    Write-Log "Все актуальные сертификаты в норме. Старые дубли (если были) проигнорированы."
}