#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cloudflare 优选 IP 工具
==============================================================
为什么这些域名会慢：Cloudflare 用 anycast，同一个域名在不同线路上会落到
不同机房。国内很多线路默认被甩到 LAX（洛杉矶），国际链路严重丢包：

  open-design.ai          首页 387KB 要 5~53 秒，TLS 握手 15~25 秒后超时
  amr-link.open-design.ai API /v1 直接超时；连纯边缘、不回源的
                          /cdn-cgi/trace 都要 2~6 秒 —— 瓶颈在链路，不在源站

而 162.159.x / 104.26.x 这一段的 IP 会落到 HKG（香港）：60~100ms，
首页 0.3 秒、API 0.43 秒，成功率 100%。

本工具做的事：
  scan    扫描 Cloudflare 官方 IP 段，找出你这条线路上最快的落地机房
  apply   把选出的 IP 写进 hosts（先备份、逐个域名校验证书、可一键还原）
  revert  删除本工具写入的 hosts 段，恢复原样
  status  查看当前优选状态与实测延迟
  menu    交互式菜单（推荐直接跑这个）

默认优选域名见 DEFAULT_DOMAINS（含 open-design.ai 及其 amr-link 子域），
可用 --domains 覆盖。只改 hosts 里一段带标记的内容，其余内容一个字都不动。
写 hosts 需要管理员权限，双击「Cloudflare优选IP.bat」会自动提权。
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

# ----------------------------------------------------------------- 常量
BEGIN_MARK = "# >>> CLOUDFLARE-PIN BEGIN (managed by cf_pin.py) >>>"
END_MARK = "# <<< CLOUDFLARE-PIN END <<<"

DEFAULT_DOMAINS = ["cloudflare.com", "www.cloudflare.com",
                   "open-design.ai", "www.open-design.ai",
                   "amr-link.open-design.ai"]

# 仅用于自测：把 hosts 操作指向副本，避免动到系统文件
HOSTS_OVERRIDE = None

CF_RANGES_V4 = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.159.0.0/16", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]
# 已知会落到亚洲近端机房的段，优先扫
#
# 默认只扫这两个 /16（各隔 2 个 /24 取 1，合计 256 个候选）。
# 实测依据（同一线路、同一时段，只改候选池）：
#     全量 912 个          → 317 有响应 → 前 12 个里近端机房 10 个，耗时 22s
#     两段隔4取1（128 个） → 近端 8 个 / 段，合格 9 个，粗筛 4s
#     两段隔2取1（256 个） → 12 个，粗筛 7s
#     单个 /16 扫满 256 个 → 近端仍是 12 个（多扫一倍收益为零）
# 也就是说：候选从 912 降到 256（1/4），近端候选反而更多、快 3 倍；
# 而再多扫（every=1）也不会增加近端候选——每段能落到近端的 /24 就这么些。
# 其余大段（104.16/13、172.64/13 等）的抽样落到近端机房的比例很低，
# 扫它们基本是在浪费时间。但链路状况会变，所以保留 --full 走全量兜底。
#
# 为什么用等距而不是随机：实测两者统计上无法区分（近端 11~12，均值 11.75）。
# 但随机会让每次 scan 结果不可复现、出问题难排查；等距的确定性本身就是价值。
PRIORITY_RANGES = [("162.159.0.0/16", 2), ("104.26.0.0/16", 2)]
NEAR_COLOS = ("HKG", "NRT", "KIX", "ICN", "SIN", "TPE", "BKK", "MNL", "SGN")

SNI_FALLBACK = "cloudflare.com"

# ---------------------------------------------------------------- 测量轮参数
# 两段式测量的第二阶段。第一阶段（粗筛）只负责快速筛掉完全不通的 IP，
# 真正决定排序的是这里的测量轮。
#
# 为什么必须单独开一轮：这条线路上 5~14% 的 SYN 会随机丢失（跨境链路 RTO），
# 低并发时碰到丢包要等满超时，高并发时又可能「恰好连续成功」拿到虚假的好成绩。
# 粗筛阶段的 rtt 是 min() 出来的幸运值，不能用来排序。
FINAL_TIMEOUT_MS = 999          # 超时样本计入的固定惩罚值，参与 p95 计算
FINAL_WINDOW_S = 20.0           # 每个「IP × 域名」组合的采样时间窗口（硬上限）
FINAL_INTERVAL_S = 0.05         # 两次探测之间的最小间隔（实际节奏受 RTT 约束）
FINAL_WORKERS = 16              # 保留给只测 TCP 的 final_round
# 单次 TCP 握手的耐心：超过这条线就当丢包直接掐掉，不再干等。
# 本线路正常 RTT 约 120~170ms，300ms 已是 2 个 RTT 以上，
# 还不回来基本就是 SYN 丢了；继续等满 1s 只是白白拖慢扫描。
# 注意：域名实测是完整 HTTPS，单次约 500ms，所以那边用下面的 DOMAIN_TIMEOUT。
FINAL_TCP_TIMEOUT = 0.3
# 域名实测的单次 HTTPS 超时：正常一次约 500ms（TCP 92 + TLS 100 + 首字节 280），
# 给到 1.5s 留足余量，超了就当这次卡死、记 999。
DOMAIN_TIMEOUT = 1.5
# 域名实测轮的并发：同时在测多少个「IP × 域名」组合。
DOMAIN_WORKERS = 12
# 淘汰阈值：域名的 p95 达到惩罚值（999ms）意味着该组合至少有 5% 的请求
# 是硬超时的。这种 IP 不是「慢一点」，是「时断时续」——写进 hosts 后用户
# 会随机遇到几秒卡死。所以它不进推荐池，只在凑不够 want 个时降级兜底。
P95_REJECT_MS = FINAL_TIMEOUT_MS
#
# 关于窗口时长（为什么是 20s 而不是 5s）：
# 完整 HTTPS 单次约 500ms，5s 窗口只能采到约 10 个样本——p95 在这种样本量下
# 几乎等于「最差的那一次」，一个偶发超时就把 p95 顶到 999，所有 IP 分数拉不开。
# 20s 窗口能采到约 40 个样本，p95 才真正代表「1/20 的偶发卡顿」。


# ----------------------------------------------------------------- 测量
def tcp_rtt(ip, port=443, tries=3, timeout=1.2, family=socket.AF_INET):
    times, fail = [], 0
    for _ in range(tries):
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            times.append((time.perf_counter() - t0) * 1000)
            s.close()
        except OSError:
            fail += 1
    if not times:
        return None, 100.0
    return min(times), 100.0 * fail / tries


def percentile(sorted_vals, q):
    """线性插值百分位（与 numpy 默认口径一致）。输入必须已排序。"""
    if not sorted_vals:
        return None
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    pos = (len(sorted_vals) - 1) * q
    lo = int(pos)
    hi = min(lo + 1, len(sorted_vals) - 1)
    return sorted_vals[lo] + (sorted_vals[hi] - sorted_vals[lo]) * (pos - lo)


def final_round(ip, port=443, window_s=FINAL_WINDOW_S, interval_s=FINAL_INTERVAL_S,
                timeout=FINAL_TCP_TIMEOUT, penalty_ms=FINAL_TIMEOUT_MS):
    """决赛轮：在 window_s 时间窗口内对单个 IP 连续探测，返回 p95/中位数/超时率等。

    关键点是「超时不丢弃，而是按 penalty_ms 计入统计」。原因：
    丢弃超时样本会让一个「10 次里卡 1 次」的 IP 看起来无比完美，
    而那一次卡顿正是用户实际会感知到的。按 999ms 记账后，
    只要卡顿率超过 5%，p95 就会被顶上 999ms，自然排到后面。

    窗口是硬上限：到点就收工，绝不为了多采几个样本而超时占用。
    实际采样数由 RTT 决定（本线路约 130ms/次 → 5s 约 40 个样本）。

    返回 dict；一次都没探完时返回 {"ip": ip, "n": 0, ...}。
    """
    samples, timeouts = [], 0
    deadline = time.perf_counter() + window_s

    while True:
        if time.perf_counter() >= deadline:
            break                                  # 窗口到点，立刻收工
        t0 = time.perf_counter()
        try:
            s = socket.create_connection((ip, port), timeout=timeout)
            s.close()
            samples.append((time.perf_counter() - t0) * 1000)
        except OSError:
            # 丢包：立即掐断连接，按 penalty_ms 记账后马上探下一次，
            # 不在这里干等——等待对判定没有任何帮助，只会拖慢扫描。
            timeouts += 1
            samples.append(float(penalty_ms))

        # 扣掉本次探测耗时，保证整体节奏稳定在 interval_s
        rest = interval_s - (time.perf_counter() - t0)
        if rest > 0:
            now = time.perf_counter()
            if now + rest < deadline:
                time.sleep(rest)

    samples.sort()
    n = len(samples)
    if not n:
        return {"ip": ip, "n": 0, "p50": None, "p95": float(penalty_ms),
                "loss": 100.0, "timeouts": 0}

    return {
        "ip": ip,
        "n": n,
        "p50": round(percentile(samples, 0.50), 1),
        "p95": round(percentile(samples, 0.95), 1),
        "loss": round(100.0 * timeouts / n, 1),
        "timeouts": timeouts,
    }


def run_final_round(cands, workers=FINAL_WORKERS, verbose=True):
    """对所有候选并发跑决赛轮（候选之间并发，单个 IP 内部按节奏采样）。"""
    if not cands:
        return []
    t0 = time.perf_counter()
    if verbose:
        print(f"  决赛轮：{len(cands)} 个候选，并发 {workers}，"
              f"每个采样 {FINAL_WINDOW_S:g}s"
              f"（≈{int(FINAL_WINDOW_S / FINAL_INTERVAL_S)} 次，"
              f"超时记 {FINAL_TIMEOUT_MS}ms 计入 p95）…", flush=True)

    def work(r):
        return {**r, **final_round(r["ip"])}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        out = list(pool.map(work, cands))

    # 排序口径：p95 优先（用户实际感知的「最差常态延迟」），
    # p95 相同再看 p50，最后看超时率。999ms 惩罚值天然把卡顿的 IP 压到后面。
    out.sort(key=lambda r: (r["p95"], r["p50"], r["loss"]))
    if verbose:
        print(f"  决赛轮完成，耗时 {time.perf_counter() - t0:.0f}s", flush=True)
    return out


def tls_trace(ip, sni=SNI_FALLBACK, timeout=6.0):
    """TLS 握手 + 取 /cdn-cgi/trace，拿到真实落地机房 colo"""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    t0 = time.perf_counter()
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=sni) as s:
            tls_ms = (time.perf_counter() - t0) * 1000
            s.sendall((f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {sni}\r\n"
                       "User-Agent: cf-pin\r\nConnection: close\r\n\r\n").encode())
            buf = b""
            while len(buf) < 8192:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
            total_ms = (time.perf_counter() - t0) * 1000
    except Exception as exc:                       # noqa: BLE001
        return {"error": str(exc)[:70]}
    info = dict(re.findall(r"^([a-z_]+)=(\S+)$", buf.decode("utf-8", "replace"), re.M))
    info.update(tls_ms=round(tls_ms, 1), total_ms=round(total_ms, 1))
    return info


def domain_p95(ip, domain, port=443, window_s=FINAL_WINDOW_S,
               interval_s=FINAL_INTERVAL_S, timeout=DOMAIN_TIMEOUT,
               penalty_ms=FINAL_TIMEOUT_MS):
    """对「单个 IP × 单个域名」做完整 HTTPS 请求（TLS + 拿到首字节），算 p95。

    和 final_round 的区别：final_round 只做 TCP 握手（不区分域名），
    这里带上真实 SNI/Host 走完整 HTTPS 请求——这才是用户实际感知的延迟。
    不同域名落到不同 CF 机房时，TCP 握手可能很快、HTTPS 却慢，
    只测 TCP 会漏掉这种差异。

    注意 timeout 必须是完整 HTTPS 的耐心（默认 DOMAIN_TIMEOUT=1.5s），
    不能沿用只测 TCP 时的 0.3s——正常一次 HTTPS 就要约 500ms，
    用 0.3s 会把所有健康请求都误判成超时。

    不做证书校验（只为测速，不用于写 hosts 的安全判定）。
    超时样本按 penalty_ms 计入统计，参与 p95 计算。
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = (f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {domain}\r\n"
           "User-Agent: cf-pin\r\nConnection: close\r\n\r\n").encode()

    samples, timeouts, colo = [], 0, None
    deadline = time.perf_counter() + window_s

    while time.perf_counter() < deadline:
        t0 = time.perf_counter()
        try:
            raw = socket.create_connection((ip, port), timeout=timeout)
            with ctx.wrap_socket(raw, server_hostname=domain) as s:
                s.settimeout(timeout)
                s.sendall(req)
                head = s.recv(1024)                # 首字节到达即停，不读完整个响应
                if not head:
                    raise OSError("empty response")
            samples.append((time.perf_counter() - t0) * 1000)
            if colo is None:
                m = re.search(rb"^colo=(\S+)$", head, re.M)
                if m:
                    colo = m.group(1).decode("ascii", "replace")
        except OSError:
            timeouts += 1
            samples.append(float(penalty_ms))
        except ssl.SSLError:
            timeouts += 1
            samples.append(float(penalty_ms))

        rest = interval_s - (time.perf_counter() - t0)
        if rest > 0 and time.perf_counter() + rest < deadline:
            time.sleep(rest)

    if not samples:
        return {"domain": domain, "colo": colo, "n": 0, "p50": None,
                "p95": float(penalty_ms), "loss": 100.0, "timeouts": 0}
    samples.sort()
    return {
        "domain": domain,
        "colo": colo,
        "n": len(samples),
        "p50": round(percentile(samples, 0.50), 1),
        "p95": round(percentile(samples, 0.95), 1),
        "loss": round(100.0 * timeouts / len(samples), 1),
        "timeouts": timeouts,
    }


def probe_domains(ip, domains, workers=8):
    """对同一个 IP 并发测多个域名，返回 {域名: p95 结果}。

    并发的是「域名」，不是同一域名的多次采样——同一个域名的连续采样
    必须保持节奏，否则会自己把链路打拥塞，测出来的延迟失真。
    """
    def work(d):
        return domain_p95(ip, d)

    with ThreadPoolExecutor(max_workers=min(workers, len(domains))) as pool:
        rows = list(pool.map(work, domains))
    return {r["domain"]: r for r in rows} 


def cert_ok(ip, domain, timeout=8.0):
    """写入 hosts 前的安全闸门：用真实证书校验连一次。

    判定标准是「证书链 + 主机名校验通过」——`wrap_socket` 能完成握手，
    就证明这个 IP 确实持有该域名的合法证书。
    HTTP 状态码只作参考，不参与判定：API 子域（如 amr-link.open-design.ai）
    根路径返回 404 是正常行为，不能据此认为该 IP 不可信。"""
    ctx = ssl.create_default_context()             # 开启校验
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=domain) as s:
            s.sendall((f"GET / HTTP/1.1\r\nHost: {domain}\r\n"
                       "User-Agent: cf-pin\r\nConnection: close\r\n\r\n").encode())
            head = s.recv(512).decode("latin-1", "replace")
    except ssl.SSLCertVerificationError as exc:
        return False, f"证书校验失败: {str(exc)[:60]}"
    except Exception as exc:                       # noqa: BLE001
        return False, str(exc)[:80]
    m = re.match(r"HTTP/1\.[01] (\d{3})", head)
    return True, f"证书校验通过 · HTTP {m.group(1) if m else '?'}"


def throughput(ip, kib=1024, timeout=15.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    host = "speed.cloudflare.com"
    try:
        raw = socket.create_connection((ip, 443), timeout=timeout)
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            s.settimeout(timeout)
            s.sendall((f"GET /__down?bytes={kib * 1024} HTTP/1.1\r\nHost: {host}\r\n"
                       "User-Agent: cf-pin\r\nConnection: close\r\n\r\n").encode())
            got, t0, started = 0, 0.0, False
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    break
                if not started:
                    t0, started = time.perf_counter(), True
                got += len(chunk)
            dt = time.perf_counter() - t0 if started else 0
    except Exception:                              # noqa: BLE001
        return None
    return (got / 1024 / dt) if dt > 0 and got > 10240 else None


# ----------------------------------------------------------------- 扫描
def build_candidates(quick=True):
    """构造候选 IP 列表。

    quick=True （默认）：只扫 PRIORITY_RANGES 两段、隔 4 个 /24 取 1，约 128 个。
                        实测这一步就能拿到 11 个近端机房候选，比全量还多。
    quick=False（--full）：扫 CF_RANGES_V4 全部官方段。这是逃生通道：
                        链路状况变了、或关键段被阻断时仍有兜底。
                        其余每段抽样 20 个 /24，避免候选数爆炸。
    """
    cands = []
    for cidr, every in PRIORITY_RANGES:
        subs = list(ipaddress.ip_network(cidr).subnets(new_prefix=24))
        cands += [str(ipaddress.ip_address(int(s.network_address) + 1))
                  for s in subs[::every]]
    if not quick:
        # 补齐其余官方段。已被 PRIORITY_RANGES 覆盖的段跳过：
        # 那些段已经按隔 N 取 1 取过了，再按 20 个 /24 抽一遍只是重复。
        prio_nets = [ipaddress.ip_network(c) for c, _ in PRIORITY_RANGES]
        for cidr in CF_RANGES_V4:
            net = ipaddress.ip_network(cidr)
            if any(net.subnet_of(p) or p.subnet_of(net) for p in prio_nets):
                continue
            subs = list(net.subnets(new_prefix=24))
            step = max(1, len(subs) // 20)
            cands += [str(ipaddress.ip_address(int(s.network_address) + 1))
                      for s in subs[::step][:20]]
    return sorted(set(cands), key=lambda s: tuple(int(x) for x in s.split(".")))


def scan(quick=True, top=12, want=3, verbose=True, final=None, strict_colo=None,
         domains=None):
    """返回 [{ip, rtt, p50, p90, p95, per_domain, colo, total, kbps, p95_reject}]。

    流程分两段：
      1) 粗筛：高并发短超时，只求把完全不通的 IP 筛掉，这里的 rtt 不可用于排序
      2) 域名实测轮：对粗筛前列的候选，用目标域名逐个做完整 HTTPS 请求，
         先淘汰 p95 触到超时惩罚值的（时断时续的 IP），再按 p50 排序

    排序口径：**先淘汰、再排序**。
      - 淘汰：最差域名的 p95 >= P95_REJECT_MS（999ms），即至少 5% 请求卡死
      - 排序：合格者按各域名 p50 的平均值（典型体感，样本多、最稳定）
      被淘汰的会带 p95_reject=True 垫在列表末尾，只有合格候选不足时才被取用。
    不拿 p95 做主排序键：它对个别超时过于敏感，会让排序随一次抖动跳变。

    domains：要实测的域名列表，默认 DEFAULT_DOMAINS（含 open-design.ai 系列）。
      每个域名单独走 TLS + 首字节，因为不同域名落到不同 CF 机房时，
      TCP 握手可能很快、HTTPS 却慢——只测 TCP 握手会漏掉这种差异。

    strict_colo（默认 None = 不启用）：
      传入 True 时只保留 colo 属于 NEAR_COLOS 的候选，远端机房根本不进实测轮。
      这是「机房硬过滤」——远端 IP 不是慢一点的问题，而是差一个数量级
      （实测同一条线路：HKG 约 500ms，LAX 可到 2600ms），让它参与排序只会
      污染结论。凑不够 want 个时会明确提示，而不是悄悄用远端 IP 顶上。
    """
    cands = build_candidates(quick)
    domains = list(domains) if domains else list(DEFAULT_DOMAINS)
    if verbose:
        print(f"  扫描 {len(cands)} 个 Cloudflare IP（粗筛并发 96）…", flush=True)
    t0 = time.perf_counter()
    hits = []

    def work(ip):
        rtt, loss = tcp_rtt(ip, tries=2, timeout=1.0)
        return ip, rtt, loss

    with ThreadPoolExecutor(max_workers=96) as pool:
        for ip, rtt, loss in pool.map(work, cands):
            if rtt is not None and loss < 100:
                hits.append({"ip": ip, "rtt": rtt, "loss": loss})
    # 粗筛阶段只按「有响应」排序，不做精细定序——粗筛 rtt 是 min() 出来的幸运值
    hits.sort(key=lambda r: r["rtt"])
    if verbose:
        print(f"  {len(hits)} 个有响应，耗时 {time.perf_counter() - t0:.0f}s；"
              f"识别前 {top} 个的落地机房…", flush=True)

    def probe(r):
        info = tls_trace(r["ip"])
        return {**r, "colo": info.get("colo", "?"),
                "total": info.get("total_ms"), "err": info.get("error")}

    with ThreadPoolExecutor(max_workers=10) as pool:
        probed = list(pool.map(probe, hits[:top]))

    # ---- 机房硬过滤：远端机房直接出局，不进入吞吐测试和决赛轮
    near = [r for r in probed if r.get("colo") in NEAR_COLOS and r.get("total")]
    rest = [r for r in probed if r not in near and r.get("total")]

    if strict_colo:
        # 区分「确认是远端机房」和「colo 没识别出来」。后者可能是 TLS 探测
        # 超时导致的，跟机房远近无关；混在一起报会误导排查。
        far = [r for r in rest if r.get("colo") not in ("?", None)]
        unknown = [r for r in rest if r.get("colo") in ("?", None)]
        if verbose:
            if far:
                names = ", ".join(sorted({str(r.get("colo")) for r in far}))
                print(f"  已剔除 {len(far)} 个远端机房候选（{names}）", flush=True)
            if unknown:
                ips = ", ".join(r["ip"] for r in unknown[:4])
                print(f"  已剔除 {len(unknown)} 个机房识别失败的候选"
                      f"（{ips}{'…' if len(unknown) > 4 else ''}）", flush=True)
        rest = []
        if verbose and len(near) < want:
            print(f"  [警告] 近端机房只找到 {len(near)} 个，少于期望的 {want} 个；"
                  f"不会用远端机房兜底。可加大 --top 或去掉硬过滤。", flush=True)

    with ThreadPoolExecutor(max_workers=6) as pool:
        speeds = list(pool.map(lambda r: throughput(r["ip"], kib=1024),
                               near + rest))
    for r, sp in zip(near + rest, speeds):
        r["kbps"] = sp

    # ---- 域名实测轮：每个 IP × 每个目标域名，带真实 SNI/Host 走完整 HTTPS
    # 用各域名 p95 的**最差值**作为该 IP 的评分：只要有一个域名慢，
    # 这个 IP 就不能算合格（用户在哪个域名上都会遇到卡顿）。
    n_final = final if final is not None else max(top, want * 3)
    near_pool = near[:n_final]
    rest_pool = rest[:max(0, n_final - len(near_pool))]
    # 两轮并成一轮执行。near_pool / rest_pool 在开跑前就已确定，第二轮不读
    # 第一轮的任何结果，拆成两个 20s 窗口纯粹是白等——曾经为了测 1~2 个兜底
    # IP 而多等满一整个窗口（约 20s）。
    #
    # 合并不会抬高链路压力：两个池子的总量受 n_final 约束，而 run_domain_round
    # 的候选间并发固定为 DOMAIN_WORKERS，峰值探测数不变。
    #
    # 排序结果不变：合并后只保留 run_domain_round 内部那一次排序，它用的
    # 规则是「合格组按 (p50, p95)，被淘汰组垫底按 (p95, p50)」。原先这里的
    # 全量重排把被淘汰组改成按 (p50, p95) 排——而按 p95 才是 run_domain_round
    # 注释所写的「最不坏的那些」，所以合并后生效的是原本的意图。
    # 这个差别只在「合格候选不足、必须降级取用淘汰项」时才可能影响名次，
    # 且 scan_verified 取用前会再按 (reject, p50) 稳一次序，最终选谁不变。
    ranked = run_domain_round(near_pool + rest_pool, domains, verbose=verbose)
    return ranked[:max(want, 6)]


def run_domain_round(cands, domains, verbose=True):
    """对所有候选 IP 并发跑「域名实测轮」，按各域名 p95 的最差值排序。

    候选之间的并发由 ThreadPoolExecutor 控制；单个 IP 内部，
    多个域名是并发的，但同一域名的采样保持节奏（见 domain_p95）。
    """
    if not cands:
        return []
    t0 = time.perf_counter()
    if verbose:
        print(f"  域名实测轮：{len(cands)} 个 IP × {len(domains)} 个域名，"
              f"每个组合采样 {FINAL_WINDOW_S:g}s"
              f"（超时记 {FINAL_TIMEOUT_MS}ms 计入 p95）…", flush=True)

    def work(r):
        per = probe_domains(r["ip"], domains)
        p95s = [v["p95"] for v in per.values() if v["p95"] is not None]
        p50s = [v["p50"] for v in per.values() if v["p50"] is not None]
        n_total = sum(v["n"] for v in per.values())
        to_total = sum(v["timeouts"] for v in per.values())
        return {**r,
                "per_domain": per,
                # 汇总口径：p95 取最差域名（有域名卡就算不合格），
                # p50 取平均（代表典型体感），样本数用于评估可信度
                "p95": max(p95s) if p95s else float(FINAL_TIMEOUT_MS),
                "p50": (sum(p50s) / len(p50s) if p50s
                        else float(FINAL_TIMEOUT_MS)),
                "n": n_total,
                "timeouts": to_total}

    with ThreadPoolExecutor(max_workers=DOMAIN_WORKERS) as pool:
        out = list(pool.map(work, cands))

    # ---- 硬淘汰：p95 触及惩罚值的 IP 直接出推荐池
    # 判定用「最差域名的 p95」，因为只要有一个域名卡，用户在访问它时就会遇到。
    # 这一步必须在排序之前——先淘汰再按 p50 排，才能既不被抖动带跑、
    # 又不会把「p50 好看但时不时卡死」的 IP 选出来。
    kept, rejected = [], []
    for r in out:
        if r["p95"] >= P95_REJECT_MS:
            r["p95_reject"] = True
            rejected.append(r)
        else:
            r["p95_reject"] = False
            kept.append(r)

    if verbose:
        if rejected:
            names = ", ".join(f"{r['ip']}(p95={r['p95']:.0f})" for r in rejected[:5])
            print(f"  已淘汰 {len(rejected)} 个有硬超时的 IP：{names}"
                  f"{'…' if len(rejected) > 5 else ''}", flush=True)
        if not kept:
            print(f"  [警告] 所有候选的 p95 都触到超时惩罚值，只能按 p95 兜底排序。",
                  flush=True)

    # 排序口径：先按典型体感（p50 平均）排——它样本多、最稳定；
    # p95 只作展示和「淘汰判据」，不参与主排序。
    # 原因：p95 对个别超时极其敏感，拿它排序会让排序结果随一次偶然抖动跳来跳去。
    def key(r):
        return (r["p50"], r["p95"])

    kept.sort(key=key)
    # 被淘汰的按 p95 升序垫在后面：只在调用方凑不够数量时才会被取到，
    # 且此时它们是「最不坏的」那些，而不是随机挑。
    rejected.sort(key=lambda r: (r["p95"], r["p50"]))
    out = kept + rejected

    if verbose:
        tot_n = sum(r["n"] for r in out)
        print(f"  域名实测轮完成，耗时 {time.perf_counter() - t0:.0f}s"
              f"（共 {tot_n} 个样本，合格 {len(kept)} 个）", flush=True)
    return out


def scan_verified(domains, want, quick=True, full_probe=40, verbose=True,
                  strict_colo=None):
    """扫描并只返回「近端机房 + 证书全过」的 IP，直到凑够 want 个。

    和 scan() 的区别：
      - 先把近端机房（HKG 等）的排前面，洛杉矶之类的只在凑不够时兜底
      - 证书校验不过的直接丢，不占用 want 名额
      - 需要更多候选时会补充扫描，而不是傻等前 12 个里挑
    strict_colo 透传给 scan()，启用时远端机房不参与候选。
    """
    tried = set()
    chosen = []
    want = max(1, want)
    top = 12

    while len(chosen) < want:
        ranked = scan(quick=quick, want=max(top, want * 2), verbose=verbose,
                      strict_colo=strict_colo)
        fresh = [r for r in ranked if r["ip"] not in tried]
        if not fresh:
            break
        # 合格的排前面：只有一个 IP 都没合格时才去碰被淘汰的。
        # run_domain_round 已把淘汰项垫在末尾，这里再显式稳一次序，
        # 防止调用方 want 很小、恰好只取到前面几个时无意中挑中坏 IP。
        fresh.sort(key=lambda r: (bool(r.get("p95_reject")), r.get("p50") or 0))
        for r in fresh:
            if len(chosen) >= want:
                break
            tried.add(r["ip"])
            # 近端机房优先；远端只在凑不够时补位（scan 已排好序）
            ip = r["ip"]
            bad = []
            for d in domains:
                ok, msg = cert_ok(ip, d)
                if not ok:
                    bad.append(f"{d}: {msg}")
            if bad:
                if verbose:
                    print(f"    {ip:<16}跳过  证书校验失败: {'; '.join(bad)[:70]}")
                continue
            if r.get("p95_reject") and verbose:
                print(f"    {ip:<16}[警告] 该 IP 的 p95={r.get('p95')}ms "
                      f"触到超时惩罚值，合格候选不足才降级选用")
            chosen.append({**r, "verified": True})
            if verbose:
                print(f"    {ip:<16}选用  机房={r.get('colo', '?'):<5} "
                      f"p50={r.get('p50', 0) or 0:.0f}ms "
                      f"p95={r.get('p95', 0) or 0:.0f}ms "
                      f"证书 {len(domains)}/{len(domains)} 通过")
        if len(chosen) >= want:
            break
        # 这一轮凑不够，加大候选池再试
        top += 12
        if top > full_probe:
            break
        if verbose:
            print(f"  仅凑到 {len(chosen)}/{want} 个，扩大候选池重扫…")

    return chosen


# ----------------------------------------------------------------- hosts
def hosts_path():
    if HOSTS_OVERRIDE:
        return HOSTS_OVERRIDE
    if os.name == "nt":
        return os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                            "System32", "drivers", "etc", "hosts")
    return "/etc/hosts"


def read_hosts():
    path = hosts_path()
    # newline="" 保留原始换行符（Windows hosts 是 CRLF），确保能逐字节还原
    with open(path, "r", encoding="utf-8", errors="replace", newline="") as fh:
        return fh.read()


def detect_eol(text):
    return "\r\n" if "\r\n" in text else "\n"


def strip_block(text):
    out, skipping = [], False
    for line in text.splitlines(keepends=True):
        if line.strip() == BEGIN_MARK:
            skipping = True
            continue
        if line.strip() == END_MARK:
            skipping = False
            continue
        if not skipping:
            out.append(line)
    return "".join(out)


def render_block(ips, domains, eol="\r\n"):
    lines = [BEGIN_MARK]
    for d in domains:
        for ip in ips:
            lines.append(f"{ip} {d}")
    lines.append(END_MARK)
    return eol.join(lines) + eol


def is_admin():
    if os.name != "nt":
        return os.geteuid() == 0
    import ctypes
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:                              # noqa: BLE001
        return False


def _replace_denied(exc):
    """判断 os.replace 失败是不是「暂时被占用」，值得重试。

    WinError 5  = ERROR_ACCESS_DENIED（文件正被短暂独占）
    WinError 32 = ERROR_SHARING_VIOLATION
    WinError 33 = ERROR_LOCK_VIOLATION
    这三种通常几十毫秒后自己就消失了，重试即可；其它错误照常抛出。"""
    return os.name == "nt" and getattr(exc, "winerror", None) in (5, 32, 33)


def write_hosts(new_text, path=None, backup=True):
    """写 hosts。返回实际走的写入方式："atomic" 或 "in-place"。

    hosts 是全系统被盯得最紧的文件之一，写入后有别的组件（DNS 客户端、
    杀软、索引器）会短暂打开它看一眼。这期间拿临时文件去顶替它，系统会
    直接返回 ERROR_ACCESS_DENIED —— 哪怕本进程已经是管理员、文件 ACL 也
    给了完全控制。旧版只调用一次 os.replace，撞上这个时间窗就把
    PermissionError 误报成「权限不足」，目录其实一点没毛病。

    所以这里先带退避重试原子替换（通常第 2 次就过），仍不行才退化成原地
    重写。两级都失败才向上抛，绝不会留下半截文件（写之前已备份）。
    """
    path = path or hosts_path()

    if backup and os.path.exists(path):
        stamp = time.strftime("%Y%m%d_%H%M%S")
        shutil.copy2(path, f"{path}.bak.{stamp}")

    tmp = path + ".cfpin.tmp"
    with open(tmp, "w", encoding="utf-8", newline="") as fh:
        fh.write(new_text)

    # 一级：原子替换，最多试 4 次，间隔 0.15s / 0.4s / 0.8s 递增
    for attempt, delay in enumerate((0.15, 0.4, 0.8, 1.5), start=1):
        try:
            os.replace(tmp, path)
            return "atomic"
        except OSError as exc:
            if not _replace_denied(exc):
                _unlink_quietly(tmp)
                raise
            if attempt < 4:
                time.sleep(delay)

    # 二级：原地重写。保留原文件的 ACL / 属性 / 硬链接，只是不再原子。
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(new_text)
    _unlink_quietly(tmp)
    return "in-place"


def _unlink_quietly(path):
    try:
        os.remove(path)
    except OSError:
        pass


def flush_dns():
    if os.name == "nt":
        try:
            subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=20)
            return True
        except Exception:                          # noqa: BLE001
            return False
    return False


def current_pin():
    """读出当前 hosts 里本工具写入的 IP 和域名"""
    text = read_hosts()
    ips, domains = [], []
    inside = False
    for line in text.splitlines():
        s = line.strip()
        if s == BEGIN_MARK:
            inside = True
            continue
        if s == END_MARK:
            inside = False
            continue
        if inside and s and not s.startswith("#"):
            parts = s.split()
            if len(parts) >= 2:
                ips.append(parts[0])
                domains.append(parts[1])
    return sorted(set(ips)), sorted(set(domains))


def resolve_now(domain):
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(
            domain, 443, socket.AF_INET, socket.SOCK_STREAM)})
    except OSError:
        return []


# ----------------------------------------------------------------- 命令
def cmd_scan(args):
    domains = (args.domains.split(",") if getattr(args, "domains", None)
               else DEFAULT_DOMAINS)
    domains = [d.strip() for d in domains if d.strip()]

    print("=" * 74)
    print("扫描 Cloudflare 优选 IP（不改动系统，任何设置）")
    print("=" * 74)
    print(f"  实测域名：{', '.join(domains)}")
    best = scan(quick=not args.full, want=args.want,
                final=getattr(args, "final", None),
                strict_colo=getattr(args, "strict_colo", None),
                domains=domains)
    if not best:
        print("没有扫到可用 IP，请检查网络。")
        return 1

    print(f"\n  {'IP':<16}{'机房':<6}{'典型p50':>9}{'最差p95':>9}"
          f"{'超时':>8}{'吞吐':>12}")
    print("  " + "-" * 74)
    for r in best:
        per = r.get("per_domain") or {}
        p95s = [v["p95"] for v in per.values() if v["p95"] is not None]
        worst = max(p95s) if p95s else None
        n = r.get("n") or 0
        to = r.get("timeouts")
        p50 = r.get("p50")
        p50_cell = f"{p50:.0f}ms" if p50 is not None else "—"
        worst_cell = f"{worst:.0f}ms" if worst is not None else "—"
        to_cell = f"{to}/{n}" if n else "—"
        spd_cell = (str(round(r["kbps"])) + " KB/s") if r.get("kbps") else "—"
        print(f"  {r['ip']:<16}{str(r.get('colo')):<6}"
              f"{p50_cell:>9}{worst_cell:>9}{to_cell:>8}{spd_cell:>12}")

    # 逐个域名的明细，方便看出是哪个域名拖后腿
    print("\n  各域名 p95 明细（↑ 为该 IP 最差项）：")
    hdr = f"  {'域名':<26}" + "".join(f"{r['ip'][:13]:>15}" for r in best[:5])
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for d in domains:
        cells = []
        for r in best[:5]:
            v = (r.get("per_domain") or {}).get(d) or {}
            p = v.get("p95")
            if p is None:
                cells.append(f"{'—':>15}")
            else:
                vals = [x["p95"] for x in (r.get("per_domain") or {}).values()
                        if x["p95"] is not None]
                mark = "↑" if vals and p == max(vals) else " "
                cells.append(f"{f'{p:.0f}ms{mark}':>15}")
        print(f"  {d:<26}" + "".join(cells))

    print("\n  排序依据：各域名 p50 的平均值（典型体感，样本多、最稳定）。")
    print("  p95 只作展示与淘汰判据——它对个别超时过于敏感，拿来排序会随抖动跳变。")
    json.dump(best, open("cf_choice.json", "w", encoding="utf-8"),
              ensure_ascii=False, indent=2)
    print("\n  结果已存 cf_choice.json。加参数 apply 可写入 hosts。")
    return 0


def cmd_apply(args):
    domains = args.domains.split(",") if args.domains else DEFAULT_DOMAINS
    domains = [d.strip() for d in domains if d.strip()]

    if not is_admin() and not args.dry_run and not HOSTS_OVERRIDE:
        print("[X] 改写 hosts 需要管理员权限。")
        print("    请双击运行「open-design优选IP.bat」（它会自动弹 UAC 提权），")
        print("    或在开始菜单搜「终端」→ 右键「以管理员身份运行」后重跑本命令。")
        return 2

    if args.ip:
        ips = [x.strip() for x in args.ip.split(",") if x.strip()]
        print(f"使用指定 IP：{', '.join(ips)}")
        print("\n" + "=" * 74)
        print("第 2 步：写入前的安全校验（逐个域名校验证书）")
        print("=" * 74)
        safe = []
        for ip in ips:
            bad = []
            for d in domains:
                ok, msg = cert_ok(ip, d)
                if not ok:
                    bad.append(f"{d}: {msg}")
            if bad:
                print(f"  {ip:<16}不通过  " + "; ".join(bad))
            else:
                print(f"  {ip:<16}通过    {len(domains)} 个域名的证书校验全部通过")
                safe.append(ip)
        if not safe:
            print("\n[X] 候选 IP 都没通过证书校验，为安全起见不写入 hosts。")
            return 1
    else:
        print("=" * 74)
        print("第 1 步：扫描优选 IP（优先近端机房，边扫边验证证书）")
        print("=" * 74)
        chosen = scan_verified(domains, args.redundant,
                               quick=not args.full, verbose=True,
                               strict_colo=getattr(args, "strict_colo", None))
        if not chosen:
            print("[X] 没扫到可用 IP，放弃写入。")
            return 1
        safe = [r["ip"] for r in chosen]
        print(f"\n  最终选定 {len(safe)} 个：{', '.join(safe)}")
        far = [r for r in chosen if r.get("colo") not in NEAR_COLOS]
        if far:
            print(f"  注意：其中 {len(far)} 个不是近端机房"
                  f"（{', '.join(str(r.get('colo')) for r in far)}），"
                  f"只是作为兜底")

    text = read_hosts()
    eol = detect_eol(text)
    base = strip_block(text)
    if base and not base.endswith(("\n", "\r")):
        base += eol
    new_text = base + render_block(safe, domains, eol)

    print("\n" + "=" * 74)
    print("第 3 步：写入 hosts")
    print("=" * 74)
    if args.dry_run:
        print("  （--dry-run 演练，不实际写入）将要追加的内容：")
        for line in render_block(safe, domains, eol).splitlines():
            print("   |", line)
    else:
        try:
            mode = write_hosts(new_text)
        except PermissionError:
            print("[X] 权限不足，写入失败（原文件未改动）。")
            return 2
        flush_dns()
        print(f"  已写入 {hosts_path()}")
        if mode == "in-place":
            print("  （该路径拒绝原子替换，已改为原地重写；结果等价）")
        print("  原文件已备份为 hosts.bak.<时间戳>，可用 revert 还原。")

    print("\n" + "=" * 74)
    print("第 4 步：验证效果")
    print("=" * 74)
    time.sleep(0.5)
    for d in domains:
        cur = resolve_now(d)
        print(f"  {d} 现在解析到: {cur or '（解析失败）'}")
    print()
    rtt, _ = tcp_rtt(safe[0], tries=6)
    info = tls_trace(safe[0])
    print(f"  优选 IP {safe[0]}（机房 {info.get('colo', '?')}）"
          f"实测延迟 {rtt and round(rtt)}ms、完整请求 {info.get('total_ms')}ms")
    print("\n  注意：香港机房的这些 IP 多数不回应 ICMP，所以 ping cloudflare.com")
    print("        会显示超时/不通，这属正常现象，网页访问走 TCP/TLS 不受影响。")
    print("        （延迟监测工具已会自动用 TCP 复核，并标注「ICMP过滤」）")
    print("\n  提示：浏览器如果开了「安全 DNS / DoH」，会绕过 hosts，")
    print("        需要在浏览器里关掉，或改用支持该 DoH 的方式。")
    return 0


def cmd_revert(args):
    if not is_admin() and not args.dry_run and not HOSTS_OVERRIDE:
        print("[X] 还原 hosts 需要管理员权限，请用管理员身份运行。")
        return 2
    text = read_hosts()
    if BEGIN_MARK not in text:
        print("hosts 里没有本工具写入的内容，无需还原。")
        return 0
    ips, domains = current_pin()
    new_text = strip_block(read_hosts())
    if args.dry_run:
        print("（--dry-run 演练）将删除以下内容：")
        for line in render_block(ips, sorted(set(domains)),
                                 detect_eol(read_hosts())).splitlines():
            print("   |", line)
        return 0
    try:
        mode = write_hosts(new_text)
    except PermissionError:
        print("[X] 权限不足，未改动。")
        return 2
    flush_dns()
    print(f"已删除 hosts 中的 Cloudflare 优选段（原为 {ips} → {domains}），并刷新 DNS 缓存。")
    if mode == "in-place":
        print("（该路径拒绝原子替换，已改为原地重写；结果等价）")
    return 0


def cmd_status(args):
    print("=" * 74)
    print("Cloudflare 优选状态")
    print("=" * 74)
    ips, domains = current_pin()
    if ips:
        print(f"  已启用优选：{', '.join(ips)}")
        print(f"  生效域名  ：{', '.join(domains)}")
    else:
        print("  当前未启用优选（hosts 里没有本工具写入的段）")

    print("\n  域名当前解析与实际延迟：")
    for d in DEFAULT_DOMAINS:
        cur = resolve_now(d)
        if not cur:
            print(f"    {d:<22} 解析失败")
            continue
        rtt, loss = tcp_rtt(cur[0], tries=5)
        info = tls_trace(cur[0])
        print(f"    {d:<22} {cur[0]:<16} 机房={info.get('colo', '?'):<5}"
              f"延迟={rtt and round(rtt)}ms 丢包={loss:.0f}% "
              f"完整请求={info.get('total_ms')}ms")

    if not ips:
        print("\n  想看优选能提升多少，先运行：scan")
    return 0


def cmd_menu(args):
    while True:
        print()
        print("=" * 74)
        print("  Cloudflare 优选 IP 工具")
        print("=" * 74)
        ips, domains = current_pin()
        print(f"  当前状态: {'已启用 ' + ','.join(ips) if ips else '未启用'}")
        print()
        print("  1. 扫描并查看优选 IP（不改动系统）")
        print("  2. 应用优选 IP 到 hosts（需要管理员权限）")
        print("  3. 还原 hosts（删除优选段）")
        print("  4. 查看当前状态")
        print("  0. 退出")
        try:
            choice = input("\n  请选择 [0-4]: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if choice == "1":
            cmd_scan(argparse.Namespace(full=False, want=6))
        elif choice == "2":
            rc = cmd_apply(argparse.Namespace(
                domains=None, ip=None, full=False, redundant=3, dry_run=False))
            if rc == 2:
                print("\n  提示：用「Cloudflare优选IP.bat」双击运行可自动提权。")
        elif choice == "3":
            cmd_revert(argparse.Namespace(dry_run=False))
        elif choice == "4":
            cmd_status(argparse.Namespace())
        elif choice == "0":
            return 0
        else:
            print("  请输入 0-4")


def main(argv=None):
    global HOSTS_OVERRIDE
    ap = argparse.ArgumentParser(
        description="Cloudflare 优选 IP 工具（扫描 / 写入 hosts / 还原）")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("scan", help="扫描优选 IP，不改动系统")
    p.add_argument("--full", action="store_true", help="扫描全部官方段（更慢更全）")
    p.add_argument("--want", type=int, default=6)
    p.add_argument("--final", type=int, metavar="N",
                   help=f"参与域名实测的候选数（默认约 want*3）")
    p.add_argument("--domains", metavar="LIST",
                   help="要实测的域名，逗号分隔"
                        f"（默认 {','.join(DEFAULT_DOMAINS)}）")
    p.add_argument("--strict-colo", action="store_true",
                   help=f"只考虑近端机房（{', '.join(NEAR_COLOS[:5])} 等），"
                        f"远端机房直接出局、不参与排序")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("apply", help="把优选 IP 写入 hosts")
    p.add_argument("--domains", help="要优选的域名，逗号分隔（默认 cloudflare.com,www.cloudflare.com）")
    p.add_argument("--ip", help="直接指定 IP，跳过扫描；可逗号分隔多个（如 1.2.3.4,5.6.7.8）")
    p.add_argument("--redundant", type=int, default=3, help="写几个备用 IP（默认 3）")
    p.add_argument("--full", action="store_true")
    p.add_argument("--strict-colo", action="store_true",
                   help="只考虑近端机房，远端机房不参与候选")
    p.add_argument("--dry-run", action="store_true", help="只演练不写入")
    p.add_argument("--hosts-file", help="（自测用）对副本文件操作，不动系统 hosts")
    p.set_defaults(func=cmd_apply)

    p = sub.add_parser("revert", help="删除 hosts 中的优选段")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--hosts-file", help="（自测用）对副本文件操作")
    p.set_defaults(func=cmd_revert)

    p = sub.add_parser("status", help="查看当前状态")
    p.add_argument("--hosts-file", help="（自测用）读副本文件")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("menu", help="交互式菜单")
    p.set_defaults(func=cmd_menu)

    args = ap.parse_args(argv)
    if getattr(args, "hosts_file", None):
        HOSTS_OVERRIDE = os.path.abspath(args.hosts_file)
    if not getattr(args, "func", None):
        return cmd_menu(args)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
