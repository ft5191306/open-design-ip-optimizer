# ============================================================================
#  cfpin-core.ps1 — cfhk 优选线路（bat 版）内核
#
#  把 dsh-cf-pin 插件的测量口径、判定规则与 hosts 写入原样搬到 PowerShell：
#  同一套候选池、同一套分档/排序、同一套写前证书闸门、同一套标记段格式。
#  插件与 bat 共用 hosts 里的 CLOUDFLARE-PIN 标记段，可以互相接管。
#
#  只依赖 Windows PowerShell 5.1 自带的 .NET（自带的 csc 编译网络原语），
#  不需要 Node、不需要装任何东西。
# ============================================================================

$script:CfRoot    = $PSScriptRoot
$script:CfDataDir = Join-Path $PSScriptRoot 'data'
$script:CfLogFile = Join-Path $PSScriptRoot 'cfpin.log'
$script:CfStateFile = Join-Path $script:CfDataDir 'state.json'
$script:CfConfigFile = Join-Path $script:CfDataDir 'config.json'

# hosts 的编码/BOM：Read-CfHostsText 探测后记在这里，Write-CfHostsText 沿用同一组。
# 中文 Windows 上的 hosts 常被存成 ANSI/GBK 甚至 UTF-16，用 UTF-8 强读强写会把
# 中文注释永久替换成 U+FFFD（无法还原），所以必须保持原编码写回。
$script:CfHostsEncoding = New-Object System.Text.UTF8Encoding($false)
$script:CfHostsPreamble = [byte[]]@()
# 本次写入是否新建了备份（备份只在首次运行时创建一次）
$script:CfBackupCreated = $false


# ---------------------------------------------------------------- 常量
# 全部照抄插件 lib/probe.js 与 lib/engine.js，改任何一个都要先看那边的注释。
$script:BEGIN_MARK = '# >>> CLOUDFLARE-PIN BEGIN (managed by cf_pin.py) >>>'
$script:END_MARK   = '# <<< CLOUDFLARE-PIN END <<<'

$script:PENALTY_MS        = 999      # 超时样本计入的固定惩罚值
$script:WINDOW_MS         = 20000    # 候选采样窗口，硬上限
# 联调用的快速窗口：设了 CFPIN_FAST=1 就把采样窗口压到 3 秒、粗筛并发拉满，
# 只为了让「常驻」这条路径能在几分钟内被验证一遍。正式使用不要设它。
if ($env:CFPIN_FAST -eq '1' -and -not [string]::IsNullOrWhiteSpace($env:CFPIN_WINDOW_MS)) {
    $script:WINDOW_MS = [int]$env:CFPIN_WINDOW_MS
}
$script:INTERVAL_MS       = 50       # 候选采样间隔
$script:DOMAIN_TIMEOUT_MS = 1500     # 单次完整 HTTPS 的耐心
$script:FLAKY_LOSS_PCT    = 7.5      # 「断」的丢包线
$script:CANDIDATE_COUNT   = 12       # 一轮实测的候选数
$script:MAX_WRITE_IPS     = 2        # 写 hosts 最多两个 IP
$script:SLOT_MS           = 25000    # 一轮里每个候选的时间槽

$script:NEAR_COLOS = @('HKG','NRT','KIX','ICN','SIN','TPE','BKK','MNL','SGN')
$script:ACCEPTABLE_COLOS = @('HKG','NRT','KIX','ICN','SIN','TPE','BKK','MNL','SGN','SJC')

# 默认配置：与插件面板里的默认档一致（图片里的那组选项）
#
# 两组地址，职责不同，不要混：
#   addresses      —— **参与探测**的地址。候选的 p50/p95/丢包、写前证书闸门、
#                     「当前线路」采样与判定基准，全都只认这一组。
#   writeAddresses —— **只参与写入**的地址。不测速、不影响名次，只是把这些域名
#                     和最终选中的 IP 一起写进 hosts（同一个 IP，同一个标记段）。
#                     默认带上 open-design.ai：它和 amr-link 是同一张边缘证书、
#                     同一个 zone，用同一个 IP 不会有额外风险，但拿它去测速只会
#                     让候选读数多出一份噪声。
#
# addresses[0] 是「当前线路」的采样目标：放在 amr-link，因为它就是 DSH 宿主的
# baseURL，用户体感以它为准。
$script:CfDefaults = [ordered]@{
    autoWrite            = $true
    currentProbeMs       = 3000
    candidateConcurrency = 1
    switchThresholdMs    = 150
    addresses            = @('amr-link.open-design.ai')
    writeAddresses       = @('amr-link.open-design.ai', 'open-design.ai')
}

# ---------------------------------------------------------------- 网络原语（C#）
# 用 C# 而不是纯 PowerShell：粗筛要并发探测几十个 IP × 2 次 TCP，
# PowerShell 的 ConnectAsync().Wait() 单线程跑要三分钟，C# 里并发 96 是几秒。
$script:CfSharpSource = @'
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

public static class CfPin
{
    public const int PenaltyMs = 999;
    static readonly CultureInfo Inv = CultureInfo.InvariantCulture;
    static readonly Encoding Latin1 = Encoding.GetEncoding(28591);

    static CfPin()
    {
        try { ThreadPool.SetMinThreads(512, 512); } catch { }
    }

    static string F(double v) { return v.ToString("0.0", Inv); }

    static string Trim(string s, int max)
    {
        if (string.IsNullOrEmpty(s)) return "";
        s = s.Replace("\r", " ").Replace("\n", " ").Replace("\t", " ").Trim();
        return s.Length <= max ? s : s.Substring(0, max);
    }

    sealed class Sample
    {
        public bool Ok;
        public double Ms;
        public string Colo;
        public bool Edge;
        public string EdgeNote = "";
        public int Status;
    }

    static void Fill(Sample s, string text)
    {
        Match cm = Regex.Match(text, "(?m)^colo=(\\S+)");
        if (cm.Success) s.Colo = cm.Groups[1].Value;
        Match sm = Regex.Match(text, "^HTTP/1\\.[01]\\s+(\\d{3})");
        if (sm.Success) { int st; if (int.TryParse(sm.Groups[1].Value, NumberStyles.Integer, Inv, out st)) s.Status = st; }
        Match em = Regex.Match(text, "error code:\\s*(\\d{4})", RegexOptions.IgnoreCase);
        if (em.Success) { s.Edge = true; s.EdgeNote = "error code: " + em.Groups[1].Value; }
        else if (s.Status >= 400) { s.Edge = true; s.EdgeNote = "HTTP " + s.Status.ToString(Inv); }
        s.Ok = true;
    }

    static bool TryTcp(string ip, int port, int timeoutMs, out double ms)
    {
        ms = 0;
        Stopwatch sw = Stopwatch.StartNew();
        TcpClient client = new TcpClient();
        try
        {
            Task t = client.ConnectAsync(ip, port);
            if (!t.Wait(timeoutMs)) return false;
            if (!client.Connected) return false;
            ms = sw.Elapsed.TotalMilliseconds;
            return true;
        }
        catch { return false; }
        finally { try { client.Close(); } catch { } }
    }

    /// 粗筛：TCP 只判存活。返回 "ip\trtt\tloss"
    public static string[] TcpScan(string[] ips, int concurrency, int timeoutMs, int tries)
    {
        ConcurrentBag<string> bag = new ConcurrentBag<string>();
        ParallelOptions opt = new ParallelOptions();
        opt.MaxDegreeOfParallelism = Math.Max(1, concurrency);
        Parallel.ForEach(ips, opt, delegate(string ip)
        {
            double best = double.MaxValue;
            int fail = 0;
            for (int i = 0; i < tries; i++)
            {
                double ms;
                if (TryTcp(ip, 443, timeoutMs, out ms)) { if (ms < best) best = ms; }
                else fail++;
            }
            if (best < double.MaxValue)
                bag.Add(ip + "\t" + F(best) + "\t" + F(100.0 * fail / tries));
        });
        return bag.ToArray();
    }

    static Sample Once(string ip, string domain, int timeoutMs, bool full)
    {
        Stopwatch sw = Stopwatch.StartNew();
        TcpClient client = new TcpClient();
        SslStream ssl = null;
        try
        {
            try
            {
                Task ct = client.ConnectAsync(ip, 443);
                if (!ct.Wait(timeoutMs)) return null;
            }
            catch { return null; }

            ssl = new SslStream(client.GetStream(), false, delegate(object a, System.Security.Cryptography.X509Certificates.X509Certificate b, System.Security.Cryptography.X509Certificates.X509Chain c, SslPolicyErrors d) { return true; });
            try
            {
                Task au = ssl.AuthenticateAsClientAsync(domain);
                if (!au.Wait(timeoutMs)) return null;
            }
            catch { return null; }

            byte[] req = Encoding.ASCII.GetBytes("GET /cdn-cgi/trace HTTP/1.1\r\nHost: " + domain +
                "\r\nUser-Agent: cf-pin\r\nConnection: close\r\n\r\n");
            ssl.Write(req, 0, req.Length);
            ssl.Flush();

            byte[] buf = new byte[4096];
            int n;
            try
            {
                Task<int> rd = ssl.ReadAsync(buf, 0, buf.Length);
                if (!rd.Wait(timeoutMs)) return null;
                n = rd.Result;
            }
            catch { return null; }
            if (n <= 0) return null;

            Sample s = new Sample();
            s.Ms = sw.Elapsed.TotalMilliseconds;
            string text = Latin1.GetString(buf, 0, n);
            if (full && text.IndexOf("colo=", StringComparison.Ordinal) < 0)
            {
                StringBuilder sb = new StringBuilder(text);
                while (sb.Length < 8192 && sb.ToString().IndexOf("colo=", StringComparison.Ordinal) < 0)
                {
                    int left = timeoutMs - (int)sw.Elapsed.TotalMilliseconds;
                    if (left <= 0) break;
                    try
                    {
                        Task<int> rd2 = ssl.ReadAsync(buf, 0, buf.Length);
                        if (!rd2.Wait(left)) break;
                        int m = rd2.Result;
                        if (m <= 0) break;
                        sb.Append(Latin1.GetString(buf, 0, m));
                    }
                    catch { break; }
                }
                text = sb.ToString();
            }
            Fill(s, text);
            return s;
        }
        catch { return null; }
        finally
        {
            try { if (ssl != null) ssl.Dispose(); } catch { }
            try { client.Close(); } catch { }
        }
    }

    /// 读落地机房（SNI 用 cloudflare.com）。返回 "colo\ttotalMs" 或 "null\tnull"
    public static string Trace(string ip, int timeoutMs)
    {
        Sample s = Once(ip, "cloudflare.com", timeoutMs, true);
        if (s == null) return "null\tnull";
        return (s.Colo == null ? "null" : s.Colo) + "\t" + F(s.Ms);
    }

    /// 批量读机房，受并发限制。返回每行 "ip\tcolo\ttotalMs"
    public static string[] TraceMany(string[] ips, int concurrency, int timeoutMs)
    {
        ConcurrentBag<string> bag = new ConcurrentBag<string>();
        ParallelOptions opt = new ParallelOptions();
        opt.MaxDegreeOfParallelism = Math.Max(1, concurrency);
        Parallel.ForEach(ips, opt, delegate(string ip)
        {
            bag.Add(ip + "\t" + Trace(ip, timeoutMs));
        });
        return bag.ToArray();
    }

    /// 单次采样：TTFB（含连接与 TLS）。返回 "ms\tcolo\tstatus" / "timeout\t\t" / "edge\tnote\t"
    public static string SampleTTFB(string ip, string domain, int timeoutMs)
    {
        Sample s = Once(ip, domain, timeoutMs, false);
        if (s == null) return "timeout\t\t";
        if (s.Edge) return "edge\t" + s.EdgeNote + "\t";
        return F(s.Ms) + "\t" + (s.Colo == null ? "" : s.Colo) + "\t" + s.Status.ToString(Inv);
    }

    /// 完整采样窗口：返回 "n\tp50\tp95\tloss\ttimeouts\tconnRetries\tcolo\tedge"
    public static string Probe(string ip, string domain, int windowMs, int intervalMs, int timeoutMs, bool retryLinkOnce)
    {
        double[] samples = new double[1024];
        int count = 0;
        int timeouts = 0;
        int retries = 0;
        string colo = null;
        bool edgeRefused = false;
        Stopwatch total = Stopwatch.StartNew();

        while (total.ElapsedMilliseconds < windowMs)
        {
            Stopwatch one = Stopwatch.StartNew();
            Sample s = Once(ip, domain, timeoutMs, false);
            if (s == null && retryLinkOnce)
            {
                s = Once(ip, domain, timeoutMs, false);
                if (s != null) retries++;
            }
            if (s == null)
            {
                timeouts++;
                if (count < samples.Length) samples[count++] = PenaltyMs;
            }
            else if (s.Edge)
            {
                edgeRefused = true;
                timeouts++;
                if (count < samples.Length) samples[count++] = PenaltyMs;
                break;
            }
            else
            {
                if (count < samples.Length) samples[count++] = s.Ms;
                if (colo == null && s.Colo != null) colo = s.Colo;
            }

            double rest = intervalMs - one.Elapsed.TotalMilliseconds;
            if (rest > 0 && total.Elapsed.TotalMilliseconds + rest < windowMs)
                Thread.Sleep((int)Math.Ceiling(rest));
        }

        if (count == 0) return "0\t\t" + F(PenaltyMs) + "\t100.0\t0\t" + retries.ToString(Inv) + "\t" + (colo == null ? "" : colo) + "\t" + (edgeRefused ? "1" : "0");

        double[] arr = new double[count];
        Array.Copy(samples, arr, count);
        Array.Sort(arr);
        double p50 = Percentile(arr, 0.5);
        double p95 = Percentile(arr, 0.95);
        double loss = 100.0 * timeouts / count;
        return count.ToString(Inv) + "\t" + F(p50) + "\t" + F(p95) + "\t" + F(loss) + "\t" +
               timeouts.ToString(Inv) + "\t" + retries.ToString(Inv) + "\t" + (colo == null ? "" : colo) + "\t" +
               (edgeRefused ? "1" : "0");
    }

    /// 多个 IP × 多个域名的完整采样，受并发限制。返回每行
    /// "ip\t<Probe 字段>"，多个域名之间用 '\t' 分隔（Probe 字段本身也用 \t，
    /// 调用方按 8 个字段一组切）。
    public static string[] ProbeMany(string[] ips, string[] domains, int concurrency, int windowMs, int intervalMs, int timeoutMs)
    {
        ConcurrentBag<string> bag = new ConcurrentBag<string>();
        ParallelOptions opt = new ParallelOptions();
        opt.MaxDegreeOfParallelism = Math.Max(1, concurrency);
        Parallel.ForEach(ips, opt, delegate(string ip)
        {
            StringBuilder sb = new StringBuilder(ip);
            for (int i = 0; i < domains.Length; i++)
            {
                sb.Append('\t');
                sb.Append(Probe(ip, domains[i], windowMs, intervalMs, timeoutMs, true));
            }
            bag.Add(sb.ToString());
        });
        return bag.ToArray();
    }

    /// 同 ProbeMany，但立刻返回 Task，让 PowerShell 侧能在等待期间画进度。
    public static Task<string[]> ProbeManyAsync(string[] ips, string[] domains, int concurrency, int windowMs, int intervalMs, int timeoutMs)
    {
        return Task.Factory.StartNew<string[]>(delegate
        {
            return ProbeMany(ips, domains, concurrency, windowMs, intervalMs, timeoutMs);
        }, TaskCreationOptions.LongRunning);
    }

    /// 同 TcpScan，异步版。
    public static Task<string[]> TcpScanAsync(string[] ips, int concurrency, int timeoutMs, int tries)
    {
        return Task.Factory.StartNew<string[]>(delegate
        {
            return TcpScan(ips, concurrency, timeoutMs, tries);
        }, TaskCreationOptions.LongRunning);
    }

    static double Percentile(double[] sorted, double q)
    {
        if (sorted.Length == 0) return double.NaN;
        if (sorted.Length == 1) return sorted[0];
        double pos = (sorted.Length - 1) * q;
        int lo = (int)Math.Floor(pos);
        int hi = Math.Min(lo + 1, sorted.Length - 1);
        return sorted[lo] + (sorted[hi] - sorted[lo]) * (pos - lo);
    }

    /// 写前证书闸门：真实证书链 + 主机名校验，再确认边缘真的为该 zone 服务。
    /// 返回 "ok\tdetail" / "cert\tmsg" / "edge\tmsg" / "link\tmsg"
    public static string CertCheck(string ip, string domain, int timeoutMs)
    {
        TcpClient client = new TcpClient();
        SslStream ssl = null;
        Stopwatch sw = Stopwatch.StartNew();
        try
        {
            try
            {
                Task ct = client.ConnectAsync(ip, 443);
                if (!ct.Wait(timeoutMs)) return "link\ttcp timeout";
            }
            catch (Exception ex) { return "link\t" + Trim(Unwrap(ex), 70); }

            bool certBad = false;
            string certDetail = "";
            ssl = new SslStream(client.GetStream(), false, delegate(object a, System.Security.Cryptography.X509Certificates.X509Certificate b, System.Security.Cryptography.X509Certificates.X509Chain c, SslPolicyErrors d)
            {
                if (d != SslPolicyErrors.None) { certBad = true; certDetail = d.ToString(); return false; }
                return true;
            });
            try
            {
                Task au = ssl.AuthenticateAsClientAsync(domain);
                if (!au.Wait(timeoutMs)) return "link\ttls timeout";
            }
            catch (Exception ex)
            {
                string msg = Unwrap(ex);
                if (certBad || msg.IndexOf("certificate", StringComparison.OrdinalIgnoreCase) >= 0 ||
                    msg.IndexOf("cert", StringComparison.OrdinalIgnoreCase) >= 0)
                    return "cert\t证书校验失败: " + Trim(msg, 60);
                return "link\t" + Trim(msg, 70);
            }

            string detail = "证书校验通过";
            try
            {
                System.Security.Cryptography.X509Certificates.X509Certificate cert = ssl.RemoteCertificate;
                if (cert != null) detail += " · 至 " + cert.GetExpirationDateString();
            }
            catch { }

            byte[] req = Encoding.ASCII.GetBytes("GET /cdn-cgi/trace HTTP/1.1\r\nHost: " + domain +
                "\r\nUser-Agent: cf-pin\r\nConnection: close\r\n\r\n");
            try
            {
                ssl.Write(req, 0, req.Length);
                ssl.Flush();
            }
            catch (Exception ex) { return "link\t" + Trim(Unwrap(ex), 70); }

            byte[] buf = new byte[4096];
            int n;
            try
            {
                Task<int> rd = ssl.ReadAsync(buf, 0, buf.Length);
                int left = timeoutMs - (int)sw.Elapsed.TotalMilliseconds;
                if (left <= 0 || !rd.Wait(left)) return "link\tresponse timeout";
                n = rd.Result;
            }
            catch (Exception ex) { return "link\t" + Trim(Unwrap(ex), 70); }
            if (n <= 0) return "link\tempty response";

            Sample s = new Sample();
            Fill(s, Latin1.GetString(buf, 0, n));
            if (s.Edge) return "edge\t边缘拒绝服务: " + s.EdgeNote + "（" + domain + "）";
            return "ok\t" + detail;
        }
        catch (Exception ex) { return "link\t" + Trim(Unwrap(ex), 70); }
        finally
        {
            try { if (ssl != null) ssl.Dispose(); } catch { }
            try { client.Close(); } catch { }
        }
    }

    static string Unwrap(Exception ex)
    {
        Exception cur = ex;
        while (cur.InnerException != null) cur = cur.InnerException;
        return cur.Message == null ? "" : cur.Message;
    }

    [System.Runtime.InteropServices.DllImport("kernel32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    static extern bool MoveFileEx(string existingFileName, string newFileName, int flags);
    const int MOVEFILE_REPLACE_EXISTING = 0x1;
    const int MOVEFILE_WRITE_THROUGH = 0x8;

    /// 原子替换：MoveFileEx(MOVEFILE_REPLACE_EXISTING)。
    /// 比 File.Replace 更合适——hosts 这种「被别的进程开着看一眼」的文件，
    /// 失败时拿到的是明确的 Win32 错误码，调用方好判断要不要退避重试。
    /// 返回空字符串表示成功，否则返回 "win32:错误码 消息"。
    public static string AtomicReplace(string tmp, string target)
    {
        try
        {
            if (MoveFileEx(tmp, target, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) return "";
            int code = System.Runtime.InteropServices.Marshal.GetLastWin32Error();
            return "win32:" + code.ToString(Inv);
        }
        catch (Exception ex) { return Trim(Unwrap(ex), 100); }
    }
}
'@

function Initialize-CfPinNative {
    if ('CfPin' -as [type]) { return }
    Add-Type -TypeDefinition $script:CfSharpSource -Language CSharp -ErrorAction Stop
}

# ---------------------------------------------------------------- 小工具
function Write-CfLog {
    param([string]$Message)
    $line = ('[{0}] {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message)
    try { Add-Content -LiteralPath $script:CfLogFile -Value $line -Encoding UTF8 } catch { }
}

function Get-CfDisplayWidth {
    param([string]$Text)
    $w = 0
    foreach ($ch in $Text.ToCharArray()) {
        $code = [int]$ch
        if (($code -ge 0x1100 -and $code -le 0x115F) -or
            ($code -ge 0x2E80 -and $code -le 0xA4CF) -or
            ($code -ge 0xAC00 -and $code -le 0xD7A3) -or
            ($code -ge 0xF900 -and $code -le 0xFAFF) -or
            ($code -ge 0xFE30 -and $code -le 0xFE6F) -or
            ($code -ge 0xFF00 -and $code -le 0xFF60) -or
            ($code -ge 0xFFE0 -and $code -le 0xFFE6)) { $w += 2 } else { $w += 1 }
    }
    return $w
}

function Format-CfPad {
    param([string]$Text, [int]$Width, [string]$Align = 'left')
    $s = if ($null -eq $Text) { '' } else { [string]$Text }
    $pad = $Width - (Get-CfDisplayWidth $s)
    if ($pad -le 0) { return $s }
    if ($Align -eq 'right') { return (' ' * $pad) + $s }
    return $s + (' ' * $pad)
}

function Format-CfMs {
    param($Value)
    if ($null -eq $Value) { return '—' }
    return ([string][int][Math]::Round([double]$Value) + 'ms')
}

function Format-CfOne {
    param($Value)
    if ($null -eq $Value) { return '—' }
    return ([double]$Value).ToString('0.0')
}

# ---------------------------------------------------------------- 配置与状态
function Get-CfConfig {
    $cfg = [ordered]@{}
    foreach ($key in $script:CfDefaults.Keys) { $cfg[$key] = $script:CfDefaults[$key] }
    if (Test-Path -LiteralPath $script:CfConfigFile) {
        try {
            $raw = Get-Content -LiteralPath $script:CfConfigFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($null -ne $raw.autoWrite)            { $cfg.autoWrite = [bool]$raw.autoWrite }
            if ($null -ne $raw.currentProbeMs)       { $cfg.currentProbeMs = [int]$raw.currentProbeMs }
            if ($null -ne $raw.candidateConcurrency) { $cfg.candidateConcurrency = [int]$raw.candidateConcurrency }
            if ($null -ne $raw.switchThresholdMs)    { $cfg.switchThresholdMs = [int]$raw.switchThresholdMs }
            if ($null -ne $raw.addresses) {
                $list = @()
                foreach ($a in @($raw.addresses)) { if ("$a".Trim().Length -gt 0) { $list += "$a".Trim() } }
                if ($list.Count -gt 0) { $cfg.addresses = $list }
            }
            if ($null -ne $raw.writeAddresses) {
                $wlist = @()
                foreach ($a in @($raw.writeAddresses)) { if ("$a".Trim().Length -gt 0) { $wlist += "$a".Trim() } }
                if ($wlist.Count -gt 0) { $cfg.writeAddresses = $wlist }
            }
        } catch { Write-CfLog "读 config.json 失败，按默认继续：$($_.Exception.Message)" }
    }
    return $cfg
}

# 真正写进 hosts 的域名列表 = writeAddresses ∪ addresses（去重、保序）。
#
# 为什么并上 addresses：探测地址一定是用户要用的域名，漏写它等于换了线却不生效
# （插件在这里踩过坑：曾经沿用旧标记段里的域名，新勾的地址永远写不进去）。
function Get-CfWriteDomains {
    param($Config)
    $out = @()
    foreach ($a in @($Config.writeAddresses) + @($Config.addresses)) {
        $name = [string]$a
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        $name = $name.Trim()
        if ($out -notcontains $name) { $out += $name }
    }
    return $out
}

function Save-CfConfig {
    param($Config)
    try {
        if (-not (Test-Path -LiteralPath $script:CfDataDir)) { New-Item -ItemType Directory -Path $script:CfDataDir -Force | Out-Null }
        $Config | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:CfConfigFile -Encoding UTF8
    } catch { Write-CfLog "写 config.json 失败：$($_.Exception.Message)" }
}

function Get-CfState {
    $state = @{ rotation = 0; manualRotation = 0; switchLog = @() }
    if (Test-Path -LiteralPath $script:CfStateFile) {
        try {
            $raw = Get-Content -LiteralPath $script:CfStateFile -Raw -Encoding UTF8 | ConvertFrom-Json
            if ($null -ne $raw.rotation)       { $state.rotation = [int]$raw.rotation }
            if ($null -ne $raw.manualRotation) { $state.manualRotation = [int]$raw.manualRotation }
            if ($null -ne $raw.switchLog)      { $state.switchLog = @($raw.switchLog) }
        } catch { }
    }
    return $state
}

function Save-CfState {
    param($State)
    try {
        if (-not (Test-Path -LiteralPath $script:CfDataDir)) { New-Item -ItemType Directory -Path $script:CfDataDir -Force | Out-Null }
        # switchLog 只保留最近 24 小时，与插件一致
        $cut = (Get-Date).AddHours(-24).ToUniversalTime()
        $kept = @()
        foreach ($t in @($State.switchLog)) {
            try { if ([DateTimeOffset]::FromUnixTimeMilliseconds([int64]$t).UtcDateTime -ge $cut) { $kept += [int64]$t } } catch { }
        }
        $State.switchLog = $kept
        [ordered]@{ switchLog = $kept; rotation = $State.rotation; manualRotation = $State.manualRotation } |
            ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:CfStateFile -Encoding UTF8
    } catch { Write-CfLog "写 state.json 失败：$($_.Exception.Message)" }
}

# ---------------------------------------------------------------- hosts
function Get-CfHostsPath {
    # 自测时可以用环境变量指向一份临时 hosts，避免改真实系统文件
    if (-not [string]::IsNullOrWhiteSpace($env:CFPIN_HOSTS_FILE)) { return $env:CFPIN_HOSTS_FILE }
    $root = $env:SystemRoot
    if ([string]::IsNullOrWhiteSpace($root)) { $root = 'C:\Windows' }
    return (Join-Path $root 'System32\drivers\etc\hosts')
}

function Get-CfAnsiEncoding {
    # 系统 ANSI 代码页（中文 Windows 一般是 936）。拿不到就用 latin-1：
    # 它对任意字节都能严格往返，至少保证写回不损坏原文件。
    try {
        $cp = [Globalization.CultureInfo]::CurrentCulture.TextInfo.ANSICodePage
        if ($cp -gt 0) { return [Text.Encoding]::GetEncoding($cp) }
    } catch { }
    return [Text.Encoding]::GetEncoding(28591)
}

function Read-CfHostsText {
    param([string]$Path = (Get-CfHostsPath))
    $bytes = [IO.File]::ReadAllBytes($Path)
    $script:CfHostsPreamble = [byte[]]@()

    # 1) BOM 优先：UTF-8 / UTF-16 LE / UTF-16 BE
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        $script:CfHostsPreamble = [byte[]]@(0xEF, 0xBB, 0xBF)
        $script:CfHostsEncoding = New-Object System.Text.UTF8Encoding($false)
        return $script:CfHostsEncoding.GetString($bytes, 3, $bytes.Length - 3)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        $script:CfHostsPreamble = [byte[]]@(0xFF, 0xFE)
        $script:CfHostsEncoding = [Text.Encoding]::GetEncoding(1200)   # UTF-16 LE
        return $script:CfHostsEncoding.GetString($bytes, 2, $bytes.Length - 2)
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        $script:CfHostsPreamble = [byte[]]@(0xFE, 0xFF)
        $script:CfHostsEncoding = [Text.Encoding]::GetEncoding(1201)   # UTF-16 BE
        return $script:CfHostsEncoding.GetString($bytes, 2, $bytes.Length - 2)
    }

    # 2) 严格 UTF-8：能无损解码就用它（大多数 hosts 都是这一档）
    $strict = New-Object System.Text.UTF8Encoding -ArgumentList $false, $true
    try {
        $text = $strict.GetString($bytes)
        $script:CfHostsEncoding = $strict
        return $text
    } catch { }

    # 3) 系统 ANSI（中文 Windows 上是 cp936）：能无损编码回去才算数
    $ansi = Get-CfAnsiEncoding
    try {
        $text = $ansi.GetString($bytes)
        $null = $ansi.GetBytes($text)
        $script:CfHostsEncoding = $ansi
        return $text
    } catch { }

    # 4) latin-1 兜底：任意字节可严格往返，最坏也只是显示成乱码
    $script:CfHostsEncoding = [Text.Encoding]::GetEncoding(28591)
    return $script:CfHostsEncoding.GetString($bytes)
}

function Get-CfHostsBytes {
    param([string]$Text)
    $body = $script:CfHostsEncoding.GetBytes($Text)
    if ($script:CfHostsPreamble.Length -eq 0) { return $body }
    return [byte[]]($script:CfHostsPreamble + $body)
}

# 复刻 Python str.splitlines(keepends=True) 的切分集合
function Get-CfLines {
    param([string]$Text)
    $pattern = '[^\r\n\v\f\x1c-\x1e\x85\u2028\u2029]*(?:\r\n|[\r\n\v\f\x1c-\x1e\x85\u2028\u2029]|$)'
    $out = @()
    foreach ($m in [regex]::Matches($Text, $pattern)) {
        if ($m.Value.Length -gt 0) { $out += $m.Value }
    }
    return $out
}

function Get-CfPyStrip {
    param([string]$Value)
    return $Value.Trim([char[]]@("`t","`n","`v","`f","`r"," ", [char]0x1c, [char]0x1d, [char]0x1e, [char]0x1f, [char]0x85, [char]0xA0))
}

function Get-CfPinBlockState {
    # 标记段状态："none"（没有）/ "ok"（成对）/ "broken"（不配对）。
    # "broken" 包括：只有 BEGIN 没有 END、END 出现在 BEGIN 之前、BEGIN 嵌套。
    # 这种时候删标记段会把 BEGIN 之后的全部内容一起删掉，调用方必须 fail-closed。
    param([string]$Text)
    $inside = $false
    $pairs = 0
    foreach ($line in (Get-CfLines $Text)) {
        $bare = Get-CfPyStrip $line
        if ($bare -eq $script:BEGIN_MARK) {
            if ($inside) { return 'broken' }
            $inside = $true
            continue
        }
        if ($bare -eq $script:END_MARK) {
            if (-not $inside) { return 'broken' }
            $inside = $false
            $pairs++
            continue
        }
    }
    if ($inside) { return 'broken' }
    if ($pairs -gt 0) { return 'ok' }
    return 'none'
}

function Remove-CfPinBlock {
    param([string]$Text)
    $out = New-Object System.Text.StringBuilder
    $skipping = $false
    foreach ($line in (Get-CfLines $Text)) {
        $bare = Get-CfPyStrip $line
        if ($bare -eq $script:BEGIN_MARK) { $skipping = $true; continue }
        if ($bare -eq $script:END_MARK)   { $skipping = $false; continue }
        if (-not $skipping) { [void]$out.Append($line) }
    }
    return $out.ToString()
}

function Get-CfCurrentPin {
    param([string]$Text)
    $ips = @()
    $domains = @()
    $inside = $false
    foreach ($line in (Get-CfLines $Text)) {
        $bare = Get-CfPyStrip $line
        if ($bare -eq $script:BEGIN_MARK) { $inside = $true; continue }
        if ($bare -eq $script:END_MARK)   { $inside = $false; continue }
        if (-not $inside) { continue }
        if ($bare.Length -eq 0 -or $bare.StartsWith('#')) { continue }
        $parts = $bare -split '\s+'
        if ($parts.Count -ge 2) {
            if ($ips -notcontains $parts[0]) { $ips += $parts[0] }
            if ($domains -notcontains $parts[1]) { $domains += $parts[1] }
        }
    }
    return @{ ips = $ips; domains = $domains }
}

function New-CfPinBlock {
    param([string[]]$Ips, [string[]]$Domains, [string]$Eol = "`r`n")
    $lines = @($script:BEGIN_MARK)
    foreach ($domain in $Domains) {
        foreach ($ip in $Ips) { $lines += "$ip $domain" }
    }
    $lines += $script:END_MARK
    return ($lines -join $Eol) + $Eol
}

function Get-CfEol {
    param([string]$Text)
    if ($Text.Contains("`r`n")) { return "`r`n" }
    return "`n"
}

function New-CfComposedHosts {
    param([string]$Text, [string[]]$Ips, [string[]]$Domains)
    if ((Get-CfPinBlockState $Text) -eq 'broken') {
        throw 'hosts 里的 CLOUDFLARE-PIN 标记段不完整（BEGIN/END 不成对），已中止写入以免误删标记段之后的条目'
    }
    $eol = Get-CfEol $Text
    $base = Remove-CfPinBlock $Text
    if ($base.Length -gt 0 -and -not ($base.EndsWith("`r") -or $base.EndsWith("`n"))) { $base += $eol }
    return $base + (New-CfPinBlock -Ips $Ips -Domains $Domains -Eol $eol)
}

# 备份 + 原子替换（4 次退避）+ 原地重写兜底，与插件 hosts.js 一致
#
# 备份策略：只在「备份文件还不存在」时创建一次（本工具第一次改 hosts 之前），
# 之后任何一次写入都不再动它。旧版每次写入都用 -Force 覆盖同名 hosts.bak，
# 第二次写入就会把真正的原始 hosts 顶掉，等于没有备份。
function Write-CfHostsText {
    param([string]$Text, [string]$Path = (Get-CfHostsPath), [switch]$NoBackup)
    $script:CfBackupCreated = $false
    $bak = $Path + '.bak'
    if (-not $NoBackup -and (Test-Path -LiteralPath $Path) -and -not (Test-Path -LiteralPath $bak)) {
        Copy-Item -LiteralPath $Path -Destination $bak
        $script:CfBackupCreated = $true
    }
    # 编码以「即将被替换的这个文件」为准（顺便刷新全局编码），
    # 不能依赖上一次读取留下的状态。
    if (Test-Path -LiteralPath $Path) { $null = Read-CfHostsText $Path }
    $bytes = Get-CfHostsBytes $Text
    $tmp = $Path + '.cfpin.tmp'
    [IO.File]::WriteAllBytes($tmp, $bytes)
    # 一级：原子替换。hosts 被 DNS 客户端 / 杀软 / 索引器短暂占用是常态，
    # 那种失败几十毫秒后自己就消失，所以退避重试而不是立刻报权限不足。
    $delays = @(150, 400, 800, 1500)
    for ($i = 0; $i -lt $delays.Count; $i++) {
        $err = [CfPin]::AtomicReplace($tmp, $Path)
        if ([string]::IsNullOrEmpty($err)) { return 'atomic' }
        $transient = $err -match 'win32:(5|32|33)$' -or $err -match 'being used|denied|sharing'
        if (-not $transient -or $i -eq ($delays.Count - 1)) { break }
        Start-Sleep -Milliseconds $delays[$i]
    }
    # 二级：原地重写（保留 ACL / 属性）
    [IO.File]::WriteAllBytes($Path, $bytes)
    try { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } catch { }
    return 'in-place'
}

function Invoke-CfFlushDns {
    try { & ipconfig /flushdns *> $null } catch { }
}

function Test-CfAdmin {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        $p = New-Object Security.Principal.WindowsPrincipal($id)
        return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# ---------------------------------------------------------------- 候选池与探测
#
# 候选池 = 56 个**已实测确认机房**的地址，不再做全量扫描：
#
#   104.17.128–159          32 个 → 全 SJC（回源在美西，边缘挂 SJC 省一个跨太平洋往返）
#   104.26.0/2/4/6/8/10/12/14  8 个 → 全 HKG
#   162.159.128–158 偶        16 个 → 全 HKG
#
# 主机位固定 .1。段内其余地址要么实测落远端机房（LAX 等）、要么未被验证，
# 一律不进池——池子小 5 倍，粗筛从 ~6 秒降到 1 秒出头。
$script:POOL_SJC_104_17  = @(128..159)                 # 104.17.<n>.1
$script:POOL_HKG_104_26  = @(0, 2, 4, 6, 8, 10, 12, 14) # 104.26.<n>.1
$script:POOL_HKG_162_159 = @(128, 130, 132, 134, 136, 138, 140, 142, 144, 146, 148, 150, 152, 154, 156, 158)

function Get-CfCandidatePool {
    $ips = New-Object System.Collections.Generic.List[string]
    foreach ($third in $script:POOL_SJC_104_17)  { $ips.Add("104.17.$third.1") }
    foreach ($third in $script:POOL_HKG_104_26)  { $ips.Add("104.26.$third.1") }
    foreach ($third in $script:POOL_HKG_162_159) { $ips.Add("162.159.$third.1") }
    return ($ips | Sort-Object -Property @{Expression = { $parts = $_ -split '\.'; ([int]$parts[0] * 16777216) + ([int]$parts[1] * 65536) + ([int]$parts[2] * 256) + [int]$parts[3] } })
}

function Get-CfPoolSize {
    return ($script:POOL_SJC_104_17.Count + $script:POOL_HKG_104_26.Count + $script:POOL_HKG_162_159.Count)
}

function Invoke-CfCoarse {
    param([string[]]$Pool, [int]$Concurrency, [int]$TimeoutMs = 1000, [int]$Tries = 2)
    $lines = [CfPin]::TcpScan($Pool, $Concurrency, $TimeoutMs, $Tries)
    $hits = @()
    foreach ($line in $lines) {
        $f = $line -split "`t"
        $hits += [pscustomobject]@{ ip = $f[0]; rtt = [double]$f[1]; loss = [double]$f[2] }
    }
    return @($hits | Sort-Object -Property rtt)
}

function Invoke-CfTraceMany {
    param([string[]]$Ips, [int]$Concurrency = 10)
    $lines = [CfPin]::TraceMany($Ips, $Concurrency, 6000)
    $out = @()
    foreach ($line in $lines) {
        $f = $line -split "`t"
        $out += [pscustomobject]@{
            ip = $f[0]
            colo = if ($f[1] -eq 'null' -or [string]::IsNullOrWhiteSpace($f[1])) { '' } else { [string]$f[1] }
            total = if ($f[2] -eq 'null' -or [string]::IsNullOrWhiteSpace($f[2])) { $null } else { [double]$f[2] }
        }
    }
    return $out
}

function ConvertFrom-CfProbeLine {
    param([string]$Ip, [string[]]$Fields)
    $n = [int]$Fields[0]
    $p50 = if ([string]::IsNullOrWhiteSpace($Fields[1])) { $null } else { [double]$Fields[1] }
    $p95 = [double]$Fields[2]
    $loss = [double]$Fields[3]
    $timeouts = [int]$Fields[4]
    $retries = [int]$Fields[5]
    $colo = if ($Fields.Count -gt 6) { $Fields[6] } else { '' }
    $edge = ($Fields.Count -gt 7 -and $Fields[7] -eq '1')
    $broken = (($timeouts -ge 3) -or ($loss -ge $script:FLAKY_LOSS_PCT))
    $tier = if ($broken) { 'degraded' } elseif ($retries -gt 0) { 'ok' } elseif ($timeouts -eq 0 -and $loss -eq 0) { 'clean' } else { 'ok' }
    return [pscustomobject]@{
        ip = $Ip
        p50 = $p50
        p95 = $p95
        loss = $loss
        samples = $n
        timeouts = $timeouts
        connRetries = $retries
        colo = $colo
        edgeRefused = $edge
        broken = $broken
        tier = $tier
    }
}

function Invoke-CfProbeOne {
    param([string]$Ip, [string]$Domain, [int]$WindowMs = $script:WINDOW_MS, [int]$IntervalMs = $script:INTERVAL_MS, [int]$TimeoutMs = $script:DOMAIN_TIMEOUT_MS)
    $line = [CfPin]::Probe($Ip, $Domain, $WindowMs, $IntervalMs, $TimeoutMs, $true)
    $f = $line -split "`t"
    return (ConvertFrom-CfProbeLine -Ip $Ip -Fields $f)
}

function Sort-CfCandidates {
    param($List)
    return @($List | Sort-Object -Property `
        @{ Expression = { if ($_.tier -eq 'degraded') { 1 } else { 0 } } }, `
        @{ Expression = { if ($null -eq $_.p50) { $script:PENALTY_MS } else { $_.p50 } } }, `
        @{ Expression = { $_.loss } }, `
        @{ Expression = { $_.p95 } })
}

function Get-CfTierName {
    param([string]$Tier)
    switch ($Tier) {
        'clean'    { return '健康' }
        'ok'       { return '可用' }
        'degraded' { return '丢包' }
        default    { return $Tier }
    }
}

function Test-CfAcceptableColo {
    param([string]$Colo)
    if ([string]::IsNullOrWhiteSpace($Colo) -or $Colo -eq 'null') { return $false }
    return ($script:ACCEPTABLE_COLOS -contains $Colo)
}

# ---------------------------------------------------------------- 扫描流程
function Select-CfMeasureTargets {
    param($Traced, [int]$Count, [int]$Rotation, [string[]]$ExcludeIps, [string]$Mode)
    # Mode = 'auto' | 'manual'
    $eligible = @($Traced | Where-Object { $ExcludeIps -notcontains $_.ip })
    if ($eligible.Count -eq 0) { $eligible = @($Traced) }
    if ($eligible.Count -eq 0) { return @{ items = @(); rotation = $Rotation } }

    # 远端机房（LAX / FRA / DEN …）永不补位：那不是慢一点，是差一个数量级。
    # 「机房没识别出来」的可以补位——识别失败常是 TLS 探测超时，与远近无关。
    # 这一段与插件 runManualScan / runCandidateRoundOnce 的过滤同一个意思。
    $near = @($eligible | Where-Object { (Test-CfAcceptableColo $_.colo) -and $null -ne $_.total })
    $unknown = @($eligible | Where-Object { [string]::IsNullOrWhiteSpace([string]$_.colo) -and $null -ne $_.total })
    $pool = @($near + $unknown)
    if ($pool.Count -eq 0) {
        # 一个近端/未识别都没有时才放宽到全部（否则等于本轮什么都不测）
        $pool = @($eligible | Where-Object { $null -ne $_.total })
    }
    if ($pool.Count -eq 0) { return @{ items = @(); rotation = $Rotation } }

    if ($Mode -eq 'manual') {
        # 手动：按「近端 → 读机房真实耗时 → TCP rtt」排，再按 manualRotation 轮换起点。
        # 不能用 TCP rtt 截前 N（TCP 不可排序，是实测结论）。
        $ranked = @($pool | Sort-Object -Property `
            @{ Expression = { if (Test-CfAcceptableColo $_.colo) { 0 } else { 1 } } }, `
            @{ Expression = { if ($null -eq $_.total) { [double]::MaxValue } else { [double]$_.total } } }, `
            @{ Expression = { [double]$_.rtt } })
    } else {
        # 自动轮：按近端优先、保持 hits 的 rtt 顺序（插件里就是 near + unknown）
        $ranked = @($near + $unknown)
        if ($ranked.Count -eq 0) { $ranked = $pool }
    }

    $span = [Math]::Min($Count, $ranked.Count)
    $items = @()
    for ($i = 0; $i -lt $span; $i++) {
        $items += $ranked[($Rotation + $i) % $ranked.Count]
    }
    $newRotation = ($Rotation + $span) % [Math]::Max(1, $ranked.Count)
    return @{ items = $items; rotation = $newRotation }
}

function Invoke-CfScan {
    param(
        [string[]]$Addresses,
        [string]$Mode = 'manual',      # manual: 粗筛 96 / 读机房 10 / 实测 12；auto: 8 / 6 / 并发数
        [int]$ProbeConcurrency = 0,    # 0 = 按 Mode 取默认
        [string[]]$ExcludeIps = @(),
        [switch]$Quiet,
        [scriptblock]$OnProgress
    )
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $concurrency = if ($Mode -eq 'manual') {
        @{ coarse = 96; trace = 10; probe = 12 }
    } else {
        # 自动轮：池子只有 56 个，读机房也一并提到 10 并发——这一步从 16 秒降到 10 秒，
        # 而它只是一堆 TLS 握手，不会像 20 秒采样窗口那样抢用户带宽。
        @{ coarse = 8; trace = 10; probe = [Math]::Max(1, $(if ($ProbeConcurrency -gt 0) { $ProbeConcurrency } else { 1 })) }
    }
    if ($ProbeConcurrency -gt 0) { $concurrency.probe = $ProbeConcurrency }

    $poolSize = Get-CfPoolSize
    if (-not $Quiet) { Write-Host ("  ① 粗筛 {0} 个候选（TCP 只判存活）…" -f $poolSize) -NoNewline }
    $pool = Get-CfCandidatePool
    $hits = Invoke-CfCoarse -Pool $pool -Concurrency $concurrency.coarse
    if (-not $Quiet) { Write-Host (" 完成：存活 {0} 个（{1:N0}s）" -f $hits.Count, $sw.Elapsed.TotalSeconds) }
    if ($hits.Count -eq 0) { return @{ ok = $false; reason = '一个 IP 都没连通，检查网络' } }

    # 池子只有 56 个，全部读完机房也不必再截断——多读几个只会让候选更全，
    # 成本是每个地址一次 TLS 握手（并发下 1~2 秒）。
    $traceCount = [Math]::Min($poolSize, $hits.Count)
    $traceIps = @($hits[0..($traceCount - 1)] | ForEach-Object { $_.ip })
    if (-not $Quiet) { Write-Host ("  ② 读前 {0} 个的落地机房…" -f $traceCount) -NoNewline }
    $traced = Invoke-CfTraceMany -Ips $traceIps -Concurrency $concurrency.trace
    if (-not $Quiet) { Write-Host (" 完成（{0:N0}s）" -f $sw.Elapsed.TotalSeconds) }

    # 把 rtt 合并回去（traced 里只有 ip / colo / total）
    $rttOf = @{}
    foreach ($h in $hits) { $rttOf[$h.ip] = $h.rtt }
    $merged = @()
    foreach ($t in $traced) {
        $null = 0
        $merged += [pscustomobject]@{
            ip = $t.ip
            colo = if ($t.colo -eq 'null') { '' } else { [string]$t.colo }
            total = if ($t.total -eq 'null') { $null } else { [double]$t.total }
            rtt = if ($rttOf.ContainsKey($t.ip)) { $rttOf[$t.ip] } else { 9999 }
        }
    }
    if ($merged.Count -eq 0) { return @{ ok = $false; reason = '读机房全部失败，检查网络' } }

    $state = Get-CfState
    $rotField = if ($Mode -eq 'manual') { 'manualRotation' } else { 'rotation' }
    $pick = Select-CfMeasureTargets -Traced $merged -Count $script:CANDIDATE_COUNT -Rotation $state.$rotField -ExcludeIps $ExcludeIps -Mode $Mode
    $state.$rotField = $pick.rotation
    Save-CfState $state

    $targets = @($pick.items)
    if ($targets.Count -eq 0) { return @{ ok = $false; reason = '没有可实测的候选' } }

    if (-not $Quiet) {
        Write-Host ("  ③ 实测 {0} 个候选 × {1} 个域名（每个 {2} 秒）…" -f $targets.Count, $Addresses.Count, ($script:WINDOW_MS / 1000))
    }

    # 每个候选 × 每个域名都要跑满 20s 窗口。同一候选的多个域名并发、候选之间按
    # 「并发数」排队——与插件的 mapLimit(rotated, candidateConcurrency, ...) 同构。
    $targetIps = @($targets | ForEach-Object { $_.ip })
    $coloOf = @{}
    foreach ($t in $targets) { $coloOf[$t.ip] = $t.colo }
    $lines = [CfPin]::ProbeMany(
        [string[]]$targetIps, [string[]]$Addresses, $concurrency.probe,
        $script:WINDOW_MS, $script:INTERVAL_MS, $script:DOMAIN_TIMEOUT_MS)

    $measured = @()
    foreach ($line in $lines) {
        $f = $line -split "`t"
        $ip = $f[0]
        # 每个域名的 Probe 都是 8 个字段：n, p50, p95, loss, timeouts, retries, colo, edge
        $per = @()
        for ($i = 1; $i + 7 -lt $f.Count; $i += 8) {
            $per += (ConvertFrom-CfProbeLine -Ip $ip -Fields @($f[$i..($i + 7)]))
        }
        if ($per.Count -eq 0) { continue }
        $p50s = @($per | Where-Object { $null -ne $_.p50 } | ForEach-Object { $_.p50 })
        $p95s = @($per | ForEach-Object { $_.p95 })
        $samples = 0; $timeouts = 0; $retries = 0
        foreach ($r in $per) { $samples += $r.samples; $timeouts += $r.timeouts; $retries += $r.connRetries }
        $loss = if ($samples -gt 0) { 100.0 * $timeouts / $samples } else { 100 }
        $broken = (($timeouts -ge 3) -or ($loss -ge $script:FLAKY_LOSS_PCT))
        $tier = if ($broken) { 'degraded' } elseif ($retries -gt 0) { 'ok' } elseif ($timeouts -eq 0 -and $loss -eq 0) { 'clean' } else { 'ok' }
        $measured += [pscustomobject]@{
            ip = $ip
            colo = if ($coloOf.ContainsKey($ip)) { $coloOf[$ip] } else { '' }
            p50 = if ($p50s.Count -gt 0) { ($p50s | Measure-Object -Average).Average } else { $script:PENALTY_MS }
            p95 = if ($p95s.Count -gt 0) { ($p95s | Measure-Object -Maximum).Maximum } else { $script:PENALTY_MS }
            loss = $loss
            samples = $samples
            timeouts = $timeouts
            connRetries = $retries
            broken = $broken
            tier = $tier
        }
    }
    if (-not $Quiet) {
        Write-Host (" 完成（{0:N0}s）" -f $sw.Elapsed.TotalSeconds)
        Write-Host ''
    }

    $sorted = Sort-CfCandidates $measured
    return @{ ok = $true; candidates = $sorted; elapsed = $sw.Elapsed }
}

# ---------------------------------------------------------------- 当前线路读数
function Get-CfCurrentReading {
    param([string[]]$CurrentIps, [string[]]$Addresses, $Previous, [int]$ProbeMs, [int]$Passes = 2)
    if ($CurrentIps.Count -eq 0) { return $null }
    $ip = $CurrentIps[0]
    $domain = $Addresses[0]
    $cap = [Math]::Max(1200, [Math]::Min(6000, $ProbeMs - 500))
    $prev = $Previous
    $reading = $null
    for ($i = 0; $i -lt $Passes; $i++) {
        $p50prev = $null
        if ($null -ne $prev -and $null -ne $prev.p50) { $p50prev = [double]$prev.p50 }
        # 窗口按上一拍 p50 外推：慢线路也要能采到 3 个样本，否则「样本不足」
        # 会把慢线路永久判成不可靠（与插件 engine.currentWindowMs 同一口径）。
        $window = if ($null -eq $p50prev) { 1200 } else { [Math]::Min($cap, [Math]::Max(1200, [int][Math]::Round(3 * $p50prev + 300))) }
        $reading = Invoke-CfProbeOne -Ip $ip -Domain $domain -WindowMs $window -IntervalMs 100 -TimeoutMs 1500
        $reading | Add-Member -NotePropertyName reliable -NotePropertyValue ((($reading.samples -ge 3) -or ($reading.loss -ge 50))) -Force
        $reading | Add-Member -NotePropertyName at -NotePropertyValue (Get-Date) -Force
        $prev = $reading
        # 样本够了就收工；不够就再采一拍（冷启动第一次窗口只有 1.2s）
        if ($reading.reliable) { break }
    }
    return $reading
}

# ---------------------------------------------------------------- 判定
function Get-CfDecision {
    param($Current, $Candidates, [int]$Threshold, [string[]]$CertFailedIps = @())
    if ($null -eq $Current -or $null -eq $Current.p50) { return @{ write = $false; reason = 'cold-start' } }
    if ($null -eq $Candidates -or @($Candidates).Count -eq 0) { return @{ write = $false; reason = 'no-candidate' } }

    $healthy = @($Candidates | Where-Object { $CertFailedIps -notcontains $_.ip })
    if ($healthy.Count -eq 0) { return @{ write = $false; reason = 'no-candidate' } }
    $usable = @($healthy | Where-Object { -not $_.broken })
    $degraded = ($usable.Count -eq 0)
    $best = if ($degraded) { $healthy[0] } else { $usable[0] }
    $advantage = $Current.p50 - $best.p50

    if (-not $Current.reliable) {
        return @{ write = $false; reason = 'observing'; note = 'unreliable'; candidate = $best; advantage = $advantage; degraded = $degraded }
    }
    $lossOk = $true
    if ($degraded -and $null -ne $Current.loss -and $null -ne $best.loss) { $lossOk = ($best.loss -le $Current.loss) }

    if ($advantage -lt $Threshold -or -not $lossOk) {
        return @{
            write = $false
            reason = if ($degraded) { 'all-degraded' } else { 'observing' }
            candidate = $best
            advantage = $advantage
            degraded = $degraded
        }
    }
    return @{
        write = $true
        reason = if ($degraded) { 'degraded-switched' } else { 'switched' }
        candidate = $best
        advantage = $advantage
        degraded = $degraded
    }
}

function Get-CfDecisionText {
    param($Decision)
    switch ($Decision.reason) {
        'cold-start'        { return '冷启动：hosts 里还没有固定段，等下一拍' }
        'no-candidate'      { return '没有可用候选（证书全部不适配或还没测过）' }
        'observing'         {
            if ($Decision.note -eq 'unreliable') { return '观察中：当前读数样本不足，等下一拍' }
            $adv = if ($null -ne $Decision.advantage) { [int][Math]::Round($Decision.advantage) } else { 0 }
            if ($adv -gt 0) { return ("观察中：最优候选快 {0}ms，未达阈值" -f $adv) }
            return '观察中：当前已是最优'
        }
        'all-degraded'      { return '全部偏慢/丢包，暂不切换（相对择优也未通过丢包约束）' }
        'switched'          { return ("已切换：{0}" -f $Decision.candidate.ip) }
        'degraded-switched' { return ("全部偏慢，已切到相对较好的一条：{0}" -f $Decision.candidate.ip) }
        default             { return $Decision.reason }
    }
}

# ---------------------------------------------------------------- 写入
function Invoke-CfApply {
    param(
        $Candidates,
        [string[]]$Addresses,             # 参与探测的地址：证书闸门只校验这一组
        [string[]]$WriteDomains = @(),    # 实际写进 hosts 的域名：默认等于 Addresses
        [string[]]$CurrentIps = @(),
        [hashtable]$CertFailures = @{},
        [switch]$Forced,
        [switch]$DryRun
    )
    if ($null -eq $Candidates -or @($Candidates).Count -eq 0) {
        return @{ ok = $false; reason = '还没有候选读数，未写入' }
    }
    if ($null -eq $WriteDomains -or $WriteDomains.Count -eq 0) { $WriteDomains = $Addresses }
    $now = Get-Date
    $healthy = @($Candidates | Where-Object {
        $at = $CertFailures[$_.ip]
        if ($null -eq $at) { $true } elseif (($now - $at).TotalHours -gt 1) { $CertFailures.Remove($_.ip); $true } else { $false }
    })
    if ($healthy.Count -eq 0) {
        return @{ ok = $false; reason = '候选在证书校验上均已被判为不适配，已记下并暂时跳过' }
    }
    $usable = @($healthy | Where-Object { -not $_.broken })
    $chosen = @($usable | Select-Object -First $script:MAX_WRITE_IPS)
    $degraded = $false
    if ($chosen.Count -eq 0) {
        $fresh = @($healthy | Where-Object { $CurrentIps -notcontains $_.ip })
        $degradedPool = if ($fresh.Count -gt 0) { $fresh } else { $healthy }
        $chosen = @($degradedPool | Select-Object -First $script:MAX_WRITE_IPS)
        $degraded = $chosen.Count -gt 0
    }
    if ($chosen.Count -eq 0) { return @{ ok = $false; reason = '还没有候选读数，未写入' } }

    # 写前证书闸门：逐个候选 × 逐个域名
    $verified = @()
    $rejected = @()
    $rejectedEdge = @()
    foreach ($cand in $chosen) {
        $level = 'ok'
        $lastMessage = ''
        foreach ($address in $Addresses) {
            $verdict = [CfPin]::CertCheck($cand.ip, $address, 8000)
            $vf = $verdict -split "`t", 2
            $kind = $vf[0]
            $lastMessage = if ($vf.Count -gt 1) { $vf[1] } else { '' }
            if ($kind -eq 'link') {
                $verdict = [CfPin]::CertCheck($cand.ip, $address, 8000)
                $vf = $verdict -split "`t", 2
                $kind = $vf[0]
                $lastMessage = if ($vf.Count -gt 1) { $vf[1] } else { '' }
            }
            if ($kind -eq 'ok') { continue }
            if ($kind -eq 'cert') { $CertFailures[$cand.ip] = Get-Date; $level = 'cert'; break }
            if ($kind -eq 'edge') {
                $CertFailures[$cand.ip] = Get-Date
                $level = 'edge'
                $rejectedEdge += $cand.ip
                break
            }
            $level = 'unknown'
            break
        }
        if ($level -eq 'cert' -or $level -eq 'edge' -or $level -eq 'unknown') {
            $rejected += $cand.ip
            Write-CfLog ("证书闸门剔除 {0}：{1} {2}" -f $cand.ip, $level, $lastMessage)
            continue
        }
        $verified += $cand
    }
    if ($verified.Count -eq 0) {
        $why = if ($rejectedEdge.Count -gt 0 -and $rejectedEdge.Count -eq $rejected.Count) {
            "候选边缘均拒绝为该域名服务（$($rejected -join '、')），可能是候选池包含受限 IP"
        } elseif ($rejected.Count -gt 0) {
            "候选在 $($Addresses -join '、') 上证书校验均未通过（$($rejected -join '、')）"
        } else { '没有候选通过证书校验' }
        return @{ ok = $false; reason = $why }
    }
    $accepted = @($verified | ForEach-Object { $_.ip })
    $chosen = @($chosen | Where-Object { $accepted -contains $_.ip })
    $ips = @($chosen | ForEach-Object { $_.ip })
    $certRejected = @($rejected)

    if ($DryRun) {
        return @{ ok = $true; ips = $ips; degraded = $degraded; dryRun = $true; certRejected = $certRejected; mode = 'dry-run' }
    }

    try {
        $path = Get-CfHostsPath
        $text = Read-CfHostsText $path
        # 标记段不配对时直接拒绝：后面 Remove-CfPinBlock 会把 BEGIN 之后的
        # 全部内容删掉（包括用户自己的 hosts 条目），这种破坏不可接受。
        if ((Get-CfPinBlockState $text) -eq 'broken') {
            return @{ ok = $false; reason = 'hosts 里的 CLOUDFLARE-PIN 标记段不完整（BEGIN/END 不成对），继续写入会误删标记段之后的条目，已中止；请先手工修复 hosts' }
        }
        # 写入的域名 = WriteDomains（默认 addresses ∪ writeAddresses）。
        # 只写不做证书校验的域名（open-design.ai 这类）：它与探测域名同属一个
        # zone、同一张边缘证书，闸门在 addresses 上已经验过这条 IP 能为该 zone
        # 服务；再对同一个 IP 重复握手只是多花时间。
        $next = New-CfComposedHosts -Text $text -Ips $ips -Domains $WriteDomains
        $mode = Write-CfHostsText -Text $next -Path $path
        Invoke-CfFlushDns
        $state = Get-CfState
        $state.switchLog += [int64]([DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds())
        Save-CfState $state
        Write-CfLog ("写入 hosts：{0} -> {1}（{2}）{3}" -f ($WriteDomains -join ','), ($ips -join ','), $mode, $(if ($degraded) { ' [降级]' } else { '' }))
        return @{ ok = $true; ips = $ips; domains = $WriteDomains; degraded = $degraded; mode = $mode;
                  certRejected = $certRejected; backup = ($path + '.bak');
                  backupCreated = [bool]$script:CfBackupCreated }
    } catch {
        return @{ ok = $false; reason = "写 hosts 失败：$($_.Exception.Message)" }
    }
}

# ---------------------------------------------------------------- 展示
function Write-CfHeader {
    param([string]$Title, [string[]]$Addresses, [string[]]$WriteDomains = @())
    $line = '=' * 78
    Write-Host ''
    Write-Host $line -ForegroundColor DarkCyan
    Write-Host ('  cfhk 优选线路（bat 版） · ' + $Title) -ForegroundColor Cyan
    Write-Host ('  探测：' + ($Addresses -join '、') + '    时间：' + (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')) -ForegroundColor DarkGray
    if ($null -ne $WriteDomains -and $WriteDomains.Count -gt 0) {
        $onlyWrite = @($WriteDomains | Where-Object { $Addresses -notcontains $_ })
        if ($onlyWrite.Count -gt 0) {
            Write-Host ('  写入：' + ($WriteDomains -join '、') + '（其中 ' + ($onlyWrite -join '、') + ' 只写不测）') -ForegroundColor DarkGray
        }
    }
    Write-Host $line -ForegroundColor DarkCyan
}

function Write-CfCurrentLine {
    param($Current, [string]$Label = '当前线路')
    if ($null -eq $Current) {
        Write-Host ('  ' + $Label + '：hosts 里没有 CLOUDFLARE-PIN 固定段') -ForegroundColor DarkGray
        return
    }
    $colo = if ($Current.colo) { $Current.colo } else { '?' }
    $text = '  {0}：{1}（{2}）  p50 {3}  p95 {4}  丢包 {5}%{6}' -f `
        $Label, $Current.ip, $colo, (Format-CfMs $Current.p50), (Format-CfMs $Current.p95), (Format-CfOne $Current.loss), `
        $(if ($Current.reliable) { '' } else { '  [样本不足]' })
    Write-Host $text -ForegroundColor Gray
}

function Write-CfCandidateTable {
    param($Candidates, $Current, [int]$Threshold)
    $best = $null
    if (@($Candidates).Count -gt 0) { $best = @($Candidates)[0] }

    # 每列先按内容算好宽度，再统一补齐——右对齐的数字列不会把后一列「吃进去」。
    $rows = @()
    $i = 0
    foreach ($c in $Candidates) {
        $i++
        $rows += , @(
            [string]$i,
            ($c.ip + $(if ($best -ne $null -and $c.ip -eq $best.ip) { ' *' } else { '' })),
            $(if ($c.colo) { $c.colo } else { '?' }),
            (Format-CfMs $c.p50),
            (Format-CfMs $c.p95),
            ((Format-CfOne $c.loss) + '%'),
            (Get-CfTierName $c.tier)
        )
    }
    $titles = @('#', '候选 IP', '机房', 'p50', 'p95', '丢包', '档位')
    $aligns = @('left', 'left', 'left', 'right', 'right', 'right', 'left')
    $widths = @()
    for ($k = 0; $k -lt $titles.Count; $k++) {
        $w = Get-CfDisplayWidth $titles[$k]
        foreach ($r in $rows) { $w = [Math]::Max($w, (Get-CfDisplayWidth $r[$k])) }
        $widths += $w
    }

    $render = {
        param($cells)
        $parts = @()
        for ($k = 0; $k -lt $cells.Count; $k++) { $parts += (Format-CfPad $cells[$k] $widths[$k] $aligns[$k]) }
        return '  ' + ($parts -join '   ')
    }

    Write-Host ''
    Write-Host (& $render $titles) -ForegroundColor DarkGray
    Write-Host ('  ' + ('-' * 74)) -ForegroundColor DarkGray
    $i = 0
    foreach ($r in $rows) {
        $color = switch ($Candidates[$i].tier) { 'clean' { 'Green' } 'ok' { 'Yellow' } default { 'Red' } }
        Write-Host (& $render $r) -ForegroundColor $color
        $i++
    }
    Write-Host ''
    if ($null -ne $best -and $null -ne $Current -and $null -ne $Current.p50) {
        $adv = [int][Math]::Round($Current.p50 - $best.p50)
        if ($adv -ge $Threshold) {
            Write-Host ("  结论：{0} 比当前快 {1}ms，达到切换阈值 {2}ms" -f $best.ip, $adv, $Threshold) -ForegroundColor Green
        } elseif ($adv -gt 0) {
            Write-Host ("  结论：{0} 比当前快 {1}ms，未达切换阈值 {2}ms（不值得换）" -f $best.ip, $adv, $Threshold) -ForegroundColor Yellow
        } else {
            Write-Host ('  结论：当前线路已优于全部候选（最优候选慢 {0}ms）' -f [Math]::Abs($adv)) -ForegroundColor Green
        }
    }
}

function Show-CfScanResult {
    param($Scan, $Current, [int]$Threshold)
    Write-CfCandidateTable -Candidates $Scan.candidates -Current $Current -Threshold $Threshold
    Write-Host ('  一轮耗时 {0:N0} 秒 · 候选数 {1}' -f $Scan.elapsed.TotalSeconds, @($Scan.candidates).Count) -ForegroundColor DarkGray
}
