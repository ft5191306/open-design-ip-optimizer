# ============================================================================
#  cfpin.ps1 — cfhk 优选线路（bat 版）入口
#
#  1  执行一次测速并展示结果        （只测、只显示，不改 hosts）
#  2  测速并自动写入 hosts          （测完写最优的 1~2 个，带证书闸门）
#  3  常驻检测和切换                （默认档：3s 采样 / 并发 1 / 阈值 150ms / 轮间隔 5 分钟）
#
#  测量口径、分档规则、hosts 写法全部照搬 dsh-cf-pin 插件，
#  与插件共用 hosts 里的 CLOUDFLARE-PIN 标记段。
# ============================================================================

param(
    [ValidateSet('1', '2', '3', '0', '')]
    [string]$Action = '',
    [switch]$NoElevate,
    [switch]$KeepOpen
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

try { [Console]::OutputEncoding = [Text.Encoding]::UTF8 } catch { }
try { $OutputEncoding = [Text.Encoding]::UTF8 } catch { }

. (Join-Path $PSScriptRoot 'cfpin-core.ps1')

# ---------------------------------------------------------------- 提权
function Test-CfElevated {
    return (Test-CfAdmin)
}

function Get-CfElevatedArguments {
    # 提权后要传给新进程的参数列表（数组，交给 Start-Process 自己拼）。
    #
    # 不要用 -join ' ' 拼字符串：$Action 为空时（无参数启动 → 菜单）会拼出
    # "... -Action  -KeepOpen"，PowerShell 解析成「-Action 缺少参数」，
    # 提权窗口一闪而过，选 2/3 等于什么都没做。
    param(
        [string]$ActionValue = $Action,
        [string]$ScriptPath = (Join-Path $PSScriptRoot 'cfpin.ps1')
    )
    $args = @('-NoProfile', '-ExecutionPolicy', 'Bypass',
              '-File', ('"' + $ScriptPath + '"'))
    if (-not [string]::IsNullOrWhiteSpace($ActionValue)) {
        $args += @('-Action', $ActionValue)
    }
    $args += '-KeepOpen'
    return $args
}

function Restart-CfElevated {
    param([string]$Why)
    if ($NoElevate) {
        Write-Host ''
        Write-Host ('  需要管理员权限：' + $Why) -ForegroundColor Yellow
        Write-Host '  （-NoElevate：不请求提权，操作继续，但写 hosts 会失败）' -ForegroundColor DarkGray
        return
    }
    $argList = Get-CfElevatedArguments
    Write-Host ''
    Write-Host ('  需要管理员权限：' + $Why) -ForegroundColor Yellow
    Write-Host '  正在请求提权（UAC 窗口请点「是」），结果会在新窗口里显示…' -ForegroundColor Yellow
    try {
        Start-Process -FilePath 'powershell.exe' -ArgumentList $argList -Verb RunAs | Out-Null
    } catch {
        Write-Host '  提权被取消，操作已终止。' -ForegroundColor Red
        Read-Host '  按回车返回'
        exit 1
    }
    Write-Host '  已在新窗口里启动。' -ForegroundColor DarkGray
    exit 0
}

# ---------------------------------------------------------------- 菜单
function Show-CfMenu {
    $cfg = Get-CfConfig
    $current = Get-CfCurrentPin (Read-CfHostsText)
    $admin = if (Test-CfElevated) { '管理员' } else { '普通用户' }

    Clear-Host
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor DarkCyan
    Write-Host '            cfhk 优选线路  ·  bat 版' -ForegroundColor Cyan
    Write-Host '  ============================================================' -ForegroundColor DarkCyan
    Write-Host ('   探测     ' + ($cfg.addresses -join '、')) -ForegroundColor Gray
    $writeDomains = Get-CfWriteDomains $cfg
    $onlyWrite = @($writeDomains | Where-Object { $cfg.addresses -notcontains $_ })
    if ($onlyWrite.Count -gt 0) {
        Write-Host ('   写入     ' + ($writeDomains -join '、') + '（' + ($onlyWrite -join '、') + ' 只写不测）') -ForegroundColor Gray
    } else {
        Write-Host ('   写入     ' + ($writeDomains -join '、')) -ForegroundColor Gray
    }
    Write-Host ('   当前线路 ' + $(if ($current.ips.Count -gt 0) { ($current.ips -join ', ') } else { '未固定（hosts 里没有标记段）' })) -ForegroundColor Gray
    Write-Host ('   权限     ' + $admin) -ForegroundColor Gray
    Write-Host ''
    Write-Host '   1  执行一次测速并展示结果' -ForegroundColor White
    Write-Host '      粗筛 → 读机房 → 实测 12 个候选，只显示，不改 hosts' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '   2  测速并自动写入 hosts' -ForegroundColor White
    Write-Host '      测完把最优的 1~2 个写进 hosts 的 CLOUDFLARE-PIN 段（写前做证书校验）' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '   3  常驻检测和切换' -ForegroundColor White
    Write-Host '      当前线路每 3 秒采样，候选每 5 分钟一轮，快 150ms 就自动换' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '   0  退出' -ForegroundColor DarkGray
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor DarkCyan
    $choice = Read-Host '  请选择 [1/2/3/0]'
    return $choice.Trim()
}

# ---------------------------------------------------------------- 公共：准备
function Initialize-CfRuntime {
    param($Config)
    Initialize-CfPinNative
    if (-not (Test-Path -LiteralPath $script:CfDataDir)) {
        New-Item -ItemType Directory -Path $script:CfDataDir -Force | Out-Null
    }
    Write-CfLog ('==== 启动：Action 会话开始 · 探测 ' + ($Config.addresses -join ',') + ' · 写入 ' + ((Get-CfWriteDomains $Config) -join ','))
}

function Get-CfContext {
    $cfg = Get-CfConfig
    $text = try { Read-CfHostsText } catch { '' }
    $pin = if ($text) { Get-CfCurrentPin $text } else { @{ ips = @(); domains = @() } }
    return @{
        config = $cfg
        hosts = $text
        currentIps = @($pin.ips)
        currentDomains = @($pin.domains)
    }
}

# ---------------------------------------------------------------- 选项 1
function Invoke-CfActionScan {
    $ctx = Get-CfContext
    $cfg = $ctx.config
    Initialize-CfRuntime $cfg

    Write-CfHeader -Title '① 测速（只显示，不改 hosts）' -Addresses $cfg.addresses -WriteDomains (Get-CfWriteDomains $cfg)

    $previous = $null
    if ($ctx.currentIps.Count -gt 0) {
        Write-Host '  正在采样当前线路…' -NoNewline
        $previous = Get-CfCurrentReading -CurrentIps $ctx.currentIps -Addresses $cfg.addresses -Previous $null -ProbeMs $cfg.currentProbeMs
        Write-Host ' 完成'
    } else {
        Write-Host '  hosts 里没有 CLOUDFLARE-PIN 固定段，本次只做候选测速。' -ForegroundColor DarkGray
    }
    Write-Host ''

    $scan = Invoke-CfScan -Addresses $cfg.addresses -Mode 'manual' -ExcludeIps @()
    if (-not $scan.ok) {
        Write-Host ''
        Write-Host ('  测速失败：' + $scan.reason) -ForegroundColor Red
        Write-CfLog ('测速失败：' + $scan.reason)
        return 1
    }
    Write-CfLog ('测速完成：候选 ' + @($scan.candidates).Count + ' 个')

    Write-CfCurrentLine -Current $previous
    Write-CfCandidateTable -Candidates $scan.candidates -Current $previous -Threshold $cfg.switchThresholdMs
    Write-Host ('  一轮耗时 {0:N0} 秒 · 候选数 {1}' -f $scan.elapsed.TotalSeconds, @($scan.candidates).Count) -ForegroundColor DarkGray

    # 「如果写会写什么」
    $writeDomains = Get-CfWriteDomains $cfg
    $usable = @($scan.candidates | Where-Object { -not $_.broken } | Select-Object -First $script:MAX_WRITE_IPS)
    if ($usable.Count -eq 0) {
        $usable = @($scan.candidates | Select-Object -First $script:MAX_WRITE_IPS)
        Write-Host ('  没有任何不丢包的候选，若写入会降级写：' + (($usable | ForEach-Object { $_.ip }) -join '、')) -ForegroundColor Yellow
    } else {
        Write-Host ('  若写入，会写：' + (($usable | ForEach-Object { $_.ip }) -join '、')) -ForegroundColor DarkGray
    }
    Write-Host ('  写进 hosts 的域名：' + ($writeDomains -join '、') + '（同一个 IP，同一个标记段）') -ForegroundColor DarkGray
    Write-Host ''
    return 0
}

# ---------------------------------------------------------------- 选项 2
function Invoke-CfActionWrite {
    $ctx = Get-CfContext
    $cfg = $ctx.config
    Initialize-CfRuntime $cfg

    if (-not (Test-CfElevated)) {
        Restart-CfElevated -Why '写 hosts 需要管理员权限'
    }

    Write-CfHeader -Title '② 测速并写入 hosts' -Addresses $cfg.addresses -WriteDomains (Get-CfWriteDomains $cfg)

    $previous = $null
    if ($ctx.currentIps.Count -gt 0) {
        Write-Host '  正在采样当前线路…' -NoNewline
        $previous = Get-CfCurrentReading -CurrentIps $ctx.currentIps -Addresses $cfg.addresses -Previous $null -ProbeMs $cfg.currentProbeMs
        Write-Host ' 完成'
    }
    Write-Host ''

    $scan = Invoke-CfScan -Addresses $cfg.addresses -Mode 'manual' -ExcludeIps @()
    if (-not $scan.ok) {
        Write-Host ('  测速失败：' + $scan.reason) -ForegroundColor Red
        Write-CfLog ('测速失败：' + $scan.reason)
        return 1
    }

    Write-CfCurrentLine -Current $previous
    Write-CfCandidateTable -Candidates $scan.candidates -Current $previous -Threshold $cfg.switchThresholdMs

    Write-Host '  正在做写前证书校验（逐个候选 × 探测域名，真实证书链 + 主机名）…'
    $certFailures = @{}
    $result = Invoke-CfApply -Candidates $scan.candidates -Addresses $cfg.addresses -WriteDomains (Get-CfWriteDomains $cfg) -CurrentIps $ctx.currentIps -CertFailures $certFailures -Forced
    if (-not $result.ok) {
        Write-Host ''
        Write-Host ('  写入失败：' + $result.reason) -ForegroundColor Red
        Write-CfLog ('写入失败：' + $result.reason)
        return 1
    }

    Write-Host ''
    $tag = if ($result.degraded) { '（降级：全部候选都在丢包，写了最不坏的一条）' } else { '' }
    Write-Host ('  已写入 hosts：' + ($result.ips -join '、') + $tag) -ForegroundColor Green
    if (@($result.certRejected).Count -gt 0) {
        Write-Host ('  已跳过证书校验未通过的：' + ($result.certRejected -join '、')) -ForegroundColor Yellow
    }
    Write-Host ('  写入方式：' + $result.mode + ' · 已刷新 DNS 缓存') -ForegroundColor DarkGray
    if ($result.backupCreated) {
        Write-Host ('  原始 hosts 备份：' + $result.backup + '（仅本次首次写入前创建）') -ForegroundColor DarkGray
    } elseif ($result.backup) {
        Write-Host ('  备份已存在，未覆盖：' + $result.backup + '（备份只在首次运行时创建）') -ForegroundColor DarkGray
    }

    $newPin = Get-CfCurrentPin (Read-CfHostsText)
    Write-Host ''
    Write-Host '  hosts 里的固定段现在是：' -ForegroundColor DarkGray
    foreach ($ip in $newPin.ips) {
        foreach ($domain in $newPin.domains) {
            Write-Host ('    ' + $ip + '  ' + $domain) -ForegroundColor DarkGray
        }
    }
    Write-Host ''
    return 0
}

# ---------------------------------------------------------------- 选项 3
function Show-CfResidentBanner {
    param($Config, $Admin)
    Clear-Host
    Write-Host ''
    Write-Host '  ============================================================' -ForegroundColor DarkCyan
    Write-Host '         cfhk 优选线路 · 常驻检测和切换' -ForegroundColor Cyan
    Write-Host '  ============================================================' -ForegroundColor DarkCyan
    Write-Host ('   探测        ' + ($Config.addresses -join '、')) -ForegroundColor Gray
    $wd = Get-CfWriteDomains $Config
    $ow = @($wd | Where-Object { $Config.addresses -notcontains $_ })
    Write-Host ('   写入        ' + ($wd -join '、') + $(if ($ow.Count -gt 0) { '（' + ($ow -join '、') + ' 只写不测）' } else { '' })) -ForegroundColor Gray
    Write-Host ('   当前采样    {0} 秒一次' -f [int]($Config.currentProbeMs / 1000)) -ForegroundColor Gray
    Write-Host ('   切换阈值    {0} ms' -f $Config.switchThresholdMs) -ForegroundColor Gray
    Write-Host ('   候选并发    {0} 个' -f $Config.candidateConcurrency) -ForegroundColor Gray
    $groups = [Math]::Ceiling($script:CANDIDATE_COUNT / [double]$Config.candidateConcurrency)
    $roundSec = $groups * $script:SLOT_MS / 1000
    Write-Host ('   候选轮      {0} 个候选 ÷ {1} 并发 × 25 秒 ≈ {2:N0} 分钟一轮，轮间隔 {3:N0} 分钟' -f $script:CANDIDATE_COUNT, $Config.candidateConcurrency, ($roundSec / 60), ($roundSec / 60)) -ForegroundColor Gray
    Write-Host ('   权限        ' + $Admin) -ForegroundColor Gray
    Write-Host ''
    Write-Host '   自动切换已开启 · 按 Ctrl+C 停止' -ForegroundColor DarkGray
    Write-Host '  ============================================================' -ForegroundColor DarkCyan
    Write-Host ''
}

function Write-CfStatusLine {
    param([string]$Text, [string]$Color = 'Gray')
    # 用 \r 回到行首、补齐到固定宽度再覆盖，上一拍更长的文字不会留下尾巴。
    Write-Host ("`r  " + (Format-CfPad $Text 74)) -NoNewline -ForegroundColor $Color
}

function Invoke-CfActionResident {
    $ctx = Get-CfContext
    $cfg = $ctx.config
    Initialize-CfRuntime $cfg

    if (-not (Test-CfElevated)) {
        Restart-CfElevated -Why '自动写 hosts 需要管理员权限'
    }

    $env:CFPIN_KEEP = '1'
    $tickMs = [Math]::Max(1000, $cfg.currentProbeMs)
    # 冷启动时是否允许「按第一轮结果先固定一次」。插件在这方面是刻意保守的：
    # 取消固定之后不会自动再钉回去。所以这里只在确实没有固定段时问一句，
    # 并把答案留给本次运行；不问就不动用户的机器。
    $script:CfBootstrapped = $false
    $script:CfBootstrapOnRound = $false
    if ($ctx.currentIps.Count -eq 0 -and $env:CFPIN_ASSUME_BOOTSTRAP -ne '1') {
        Write-Host '  hosts 里目前没有 CLOUDFLARE-PIN 固定段。' -ForegroundColor Yellow
        Write-Host '  常驻模式需要一条「当前线路」才能判断该不该换。' -ForegroundColor DarkGray
        $answer = Read-Host '  第一轮测完后按结果先固定一次？[Y/n]'
        if ($answer -eq '' -or $answer -match '^[Yy]') { $script:CfBootstrapOnRound = $true }
    } elseif ($ctx.currentIps.Count -eq 0) {
        $script:CfBootstrapOnRound = $true
    }

    Show-CfResidentBanner -Config $cfg -Admin $(if (Test-CfElevated) { '管理员' } else { '普通用户（写 hosts 会失败）' })
    # 轮间隔由并发数**推导**，不是独立旋钮（与插件 engine.minRoundIntervalMin 一致）：
    # 并发 1 → 12 组 × 25 秒 = 5 分钟；并发 2 → 6 组 = 3 分钟；并发 3 → 4 组 = 2 分钟。
    $groups = [Math]::Ceiling($script:CANDIDATE_COUNT / [double]$cfg.candidateConcurrency)
    $roundIntervalMs = [int]($groups * $script:SLOT_MS)
    # 联调时可用 CFPIN_ROUND_INTERVAL_MS 临时缩短，正式使用不要设它。
    if (-not [string]::IsNullOrWhiteSpace($env:CFPIN_ROUND_INTERVAL_MS)) {
        $roundIntervalMs = [int]$env:CFPIN_ROUND_INTERVAL_MS
    }
    $maxRounds = 0
    if (-not [string]::IsNullOrWhiteSpace($env:CFPIN_MAX_ROUNDS)) { $maxRounds = [int]$env:CFPIN_MAX_ROUNDS }
    $nextRoundAt = [DateTime]::Now          # 启动后立刻跑第一轮候选
    $candidates = @()
    $current = $null
    $certFailures = @{}
    $lastSwitchAt = $null
    $lastSwitchIps = @()
    $roundsDone = 0
    $lastRoundNote = '尚未跑过候选轮'

    $sw = [Diagnostics.Stopwatch]::StartNew()
    try {
        while ($true) {
            $loopStart = [DateTime]::Now

            # ---- 1. 到点就跑一轮候选（阻塞，约 5 分钟；轮内不采样当前线路）
            if ([DateTime]::Now -ge $nextRoundAt) {
                Write-Host ''
                Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] 开始候选轮（粗筛 ' + (Get-CfPoolSize) + ' → 读机房 → 实测 12 个）…') -ForegroundColor DarkCyan
                $ctx2 = Get-CfContext
                $roundSw = [Diagnostics.Stopwatch]::StartNew()
                $scan = Invoke-CfScan -Addresses $cfg.addresses -Mode 'auto' -ProbeConcurrency $cfg.candidateConcurrency -ExcludeIps $ctx2.currentIps -Quiet
                if ($scan.ok) {
                    $candidates = @($scan.candidates)
                    $roundsDone++
                    $lastRoundNote = ('第 {0} 轮完成，{1:N0} 秒，{2} 个候选' -f $roundsDone, $roundSw.Elapsed.TotalSeconds, $candidates.Count)
                    Write-Host ''
                    Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] ' + $lastRoundNote) -ForegroundColor DarkCyan
                    Write-CfCandidateTable -Candidates $candidates -Current $current -Threshold $cfg.switchThresholdMs
                    Write-CfLog ('候选轮完成：' + (($candidates | ForEach-Object { $_.ip + '=' + (Format-CfMs $_.p50) + '/' + $_.tier }) -join ', '))
                } else {
                    $lastRoundNote = ('候选轮失败：' + $scan.reason)
                    Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] ' + $lastRoundNote) -ForegroundColor Red
                    Write-CfLog $lastRoundNote
                }
                $nextRoundAt = [DateTime]::Now.AddMilliseconds($roundIntervalMs)
                # 轮结束后立刻采一次当前线路，让判定基于新鲜读数
                $ctx3 = Get-CfContext
                if ($ctx3.currentIps.Count -gt 0) {
                    $current = Get-CfCurrentReading -CurrentIps $ctx3.currentIps -Addresses $cfg.addresses -Previous $current -ProbeMs $cfg.currentProbeMs
                } elseif ($scan.ok -and $script:CfBootstrapOnRound -and -not $script:CfBootstrapped) {
                    # 冷启动：hosts 里没有固定段就没有「当前线路」，判定永远停在 cold-start。
                    # 插件刻意不替你决定要不要接管机器（取消固定之后它也不会自动钉回去），
                    # 所以这里只在启动时问过、用户答了「要」的情况下才固定这一次。
                    $script:CfBootstrapped = $true
                    Write-Host ''
                    Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] hosts 里还没有固定段，按第一轮结果先固定一次…') -ForegroundColor DarkCyan
                    $boot = Invoke-CfApply -Candidates $candidates -Addresses $cfg.addresses -WriteDomains (Get-CfWriteDomains $cfg) -CurrentIps @() -CertFailures $certFailures
                    if ($boot.ok) {
                        $lastSwitchAt = Get-Date
                        $lastSwitchIps = @($boot.ips)
                        Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] 已固定：' + ($boot.ips -join '、') + ' · 此后按阈值自动切换') -ForegroundColor Green
                        Write-CfLog ('冷启动首次固定：' + ($boot.ips -join ','))
                        $current = Get-CfCurrentReading -CurrentIps @($boot.ips) -Addresses $cfg.addresses -Previous $null -ProbeMs $cfg.currentProbeMs
                        $nextRoundAt = [DateTime]::Now.AddMilliseconds($roundIntervalMs)
                    } else {
                        Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] 首次固定失败：' + $boot.reason) -ForegroundColor Red
                        Write-CfLog ('冷启动首次固定失败：' + $boot.reason)
                    }
                }
                Write-Host ''
            }

            # ---- 2. 采样当前线路 + 判定
            $ctxNow = Get-CfContext
            if ($ctxNow.currentIps.Count -gt 0) {
                if ($candidates.Count -gt 0) {
                    $current = Get-CfCurrentReading -CurrentIps $ctxNow.currentIps -Addresses $cfg.addresses -Previous $current -ProbeMs $cfg.currentProbeMs
                }
                $decision = Get-CfDecision -Current $current -Candidates $candidates -Threshold $cfg.switchThresholdMs -CertFailedIps @($certFailures.Keys)

                if ($current -ne $null) {
                    $colo = if ($current.colo) { $current.colo } else { '?' }
                    $line = '当前 {0}（{1}） p50 {2}  丢包 {3}%  |  {4}' -f `
                        $current.ip, $colo, (Format-CfMs $current.p50), (Format-CfOne $current.loss), (Get-CfDecisionText $decision)
                    Write-CfStatusLine $line 'Gray'
                }

                if ($decision.write -and -not $cfg.autoWrite) {
                    # 判定说「该切」之后才看 autoWrite：与插件同一个顺序
                    # （值不值得 → 有没有权限 → 要不要自动写）。
                    # 关掉自动写不等于「没必要换」，所以两句文案要分开。
                    Write-Host ''
                    Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] 判定该切（快 ' + [int][Math]::Round($decision.advantage) + 'ms），但自动切换是关掉的，跳过') -ForegroundColor Yellow
                    Write-Host '    要开自动切换：把 data/config.json 的 autoWrite 改成 true' -ForegroundColor DarkGray
                    $decision = @{ write = $false; reason = 'auto-off' }
                }
                if ($decision.write) {
                    Write-Host ''
                    Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] 判定成立：' + (Get-CfDecisionText $decision) + ('（快 {0}ms）' -f [int][Math]::Round($decision.advantage))) -ForegroundColor Green
                    $applied = Invoke-CfApply -Candidates $candidates -Addresses $cfg.addresses -WriteDomains (Get-CfWriteDomains $cfg) -CurrentIps $ctxNow.currentIps -CertFailures $certFailures
                    if ($applied.ok) {
                        $lastSwitchAt = Get-Date
                        $lastSwitchIps = @($applied.ips)
                        $tag = if ($applied.degraded) { '（降级）' } else { '' }
                        Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] 已切换' + $tag + '：' + ($applied.ips -join '、') + ' · 已刷新 DNS') -ForegroundColor Green
                        Write-CfLog ('自动切换：' + ($applied.ips -join ','))
                        # 换完之后清掉旧读数：下一拍会按 hosts 里的新 IP 重新采样。
                        # 候选列表**不删**——插件的做法也一样：新 IP 就在候选里，
                        # 它和当前读数的差距会自然缩到 0，判定随即回到 observing。
                        $current = $null
                    } else {
                        Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] 写入失败：' + $applied.reason) -ForegroundColor Red
                        Write-CfLog ('自动写入失败：' + $applied.reason)
                    }
                }
            } else {
                Write-CfStatusLine ('hosts 里没有 CLOUDFLARE-PIN 固定段，等待候选轮后写入 · ' + $lastRoundNote) 'DarkGray'
            }

            # ---- 3. 控制节奏：每 tickMs 一拍
            $elapsed = ([DateTime]::Now - $loopStart).TotalMilliseconds
            $rest = $tickMs - $elapsed
            if ($rest -gt 0) { Start-Sleep -Milliseconds ([int]$rest) }
            # 联调用：跑够指定轮数就停（正式使用不设这个环境变量，永远不停）
            if ($maxRounds -gt 0 -and $roundsDone -ge $maxRounds) {
                Write-Host ''
                Write-Host ('  [' + (Get-Date -Format 'HH:mm:ss') + '] 已跑满 ' + $maxRounds + ' 轮（联调模式），退出常驻。') -ForegroundColor Yellow
                break
            }
        }
    } finally {
        Write-Host ''
        Write-Host ''
        Write-Host ('  常驻检测已停止（共 ' + $roundsDone + ' 轮候选，' + $(if ($lastSwitchAt) { '最近一次切换 ' + $lastSwitchAt.ToString('HH:mm:ss') + ' → ' + ($lastSwitchIps -join '、') } else { '本次运行未切换过' }) + '）') -ForegroundColor Yellow
        Write-CfLog '常驻检测已停止'
    }
    return 0
}

# ---------------------------------------------------------------- 主流程
function Invoke-CfMain {
    param([string]$Choice)

    switch ($Choice) {
        '1' { return Invoke-CfActionScan }
        '2' { return Invoke-CfActionWrite }
        '3' { return Invoke-CfActionResident }
        '0' { return 0 }
        default {
            Write-Host '  无效选项。' -ForegroundColor Red
            return 1
        }
    }
}

# 有 -Action 时直接执行（bat 传进来），否则弹菜单
if ($Action -ne '') {
    $code = 1
    try {
        $code = Invoke-CfMain -Choice $Action
    } catch {
        Write-Host ''
        Write-Host ('  出错了：' + $_.Exception.Message) -ForegroundColor Red
        Write-CfLog ('未捕获异常：' + $_.Exception.ToString())
        $code = 1
    }
    if ($KeepOpen) {
        Write-Host ''
        Read-Host '  按回车关闭'
    }
    exit $code
}

# 无参数：交互菜单（自己循环，省得每次都重开窗口）
while ($true) {
    $choice = Show-CfMenu
    if ($choice -eq '0' -or $choice -eq '') { break }
    try {
        $code = Invoke-CfMain -Choice $choice
    } catch {
        Write-Host ''
        Write-Host ('  出错了：' + $_.Exception.Message) -ForegroundColor Red
        Write-CfLog ('未捕获异常：' + $_.Exception.ToString())
        $code = 1
    }
    Write-Host ''
    Read-Host '  按回车返回菜单'
}
exit 0
