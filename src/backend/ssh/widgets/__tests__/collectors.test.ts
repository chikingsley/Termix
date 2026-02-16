import { describe, it, expect, vi, beforeEach } from "vitest";
import type { Client } from "ssh2";

// Mock the entire common-utils module before any imports
const execCommandMock = vi.fn();
const detectOSMock = vi.fn();

vi.mock("../common-utils.js", () => ({
  execCommand: (...args: unknown[]) => execCommandMock(...args),
  detectOS: (...args: unknown[]) => detectOSMock(...args),
  toFixedNum: (n: number | null | undefined, digits = 2) => {
    if (typeof n !== "number" || !Number.isFinite(n)) return null;
    return Number(n.toFixed(digits));
  },
  kibToGiB: (kib: number) => kib / (1024 * 1024),
}));

// Import collectors AFTER mock is set up
import { collectCpuMetrics } from "../cpu-collector.js";
import { collectMemoryMetrics } from "../memory-collector.js";
import { collectDiskMetrics } from "../disk-collector.js";
import { collectUptimeMetrics } from "../uptime-collector.js";
import { collectSystemMetrics } from "../system-collector.js";
import { collectNetworkMetrics } from "../network-collector.js";
import { collectProcessesMetrics } from "../processes-collector.js";
import { collectPortsMetrics } from "../ports-collector.js";
import { collectFirewallMetrics } from "../firewall-collector.js";

function ok(stdout: string) {
  return { stdout, stderr: "", code: 0 };
}

// ── Fixtures: real command outputs captured from macOS and Linux ──

const MACOS_TOP_CPU =
  "CPU usage: 12.47% user, 6.33% sys, 81.19% idle ";
const MACOS_LOADAVG = "{ 2.13 5.37 8.86 }";
const MACOS_NCPU = "10";

const LINUX_PROC_STAT_1 =
  "cpu  100000 2000 30000 800000 5000 1000 500 0 0 0\n";
const LINUX_PROC_STAT_2 =
  "cpu  100500 2050 30200 800800 5010 1010 510 0 0 0\n";
const LINUX_LOADAVG = "1.23 4.56 7.89 2/300 12345";
const LINUX_NPROC = "16";

const MACOS_VMSTAT = `Mach Virtual Memory Statistics: (page size of 16384 bytes)
Pages free:                              100000.
Pages active:                            200000.
Pages inactive:                          150000.
Pages speculative:                        50000.
Pages throttled:                              0.
Pages wired down:                         80000.
Pages purgeable:                          30000.
Pages stored in compressor:               40000.`;
const MACOS_MEMSIZE = "17179869184"; // 16 GiB
const MACOS_PAGESIZE = "16384";

const LINUX_MEMINFO = `MemTotal:       98304000 kB
MemAvailable:   32768000 kB
MemFree:        16384000 kB
Buffers:         1024000 kB
Cached:         15360000 kB`;

const MACOS_DF_H =
  "/dev/disk3s1s1   228Gi    11Gi    31Gi    28%    453k  321M    0%   /";
const MACOS_DF_K_P =
  "/dev/disk3s1s1   239362496  11981308  32054876    28%    /";
const LINUX_DF_H_P = "/dev/nvme0n1p2  1.8T  500G  1.2T  30%  /";
const LINUX_DF_K_P =
  "/dev/nvme0n1p2  1900000000  500000000  1200000000  30%  /";

const MACOS_UPTIME_BOOTTIME = "{ sec = 1739000000, usec = 0 }";
const LINUX_PROC_UPTIME = "123456.78 234567.89";

const MACOS_SW_VERS = "macOS\n15.2";
const LINUX_OS_RELEASE = "Arch Linux";

const MACOS_IFCONFIG = `lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\tinet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tinet 192.168.1.100 netmask 0xffffff00 broadcast 192.168.1.255
utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
\tinet 100.95.150.36 --> 100.95.150.36 netmask 0xffffffff`;

const LINUX_IP_ADDR =
  "eth0 192.168.1.50/24\ndocker0 172.17.0.1/16";
const LINUX_IP_LINK = "eth0 UP\ndocker0 DOWN\nlo UNKNOWN";

const MACOS_PS_HEADER =
  "USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND";
const MACOS_PS_ROW1 =
  "chiejimofor        123  45.0  2.3  1234567  98765 s000  R+   10:00AM   1:23.45 node server.js";
const MACOS_PS_ROW2 =
  "root               456  12.0  1.1   987654  54321   ??  Ss   9:00AM    0:45.67 /usr/sbin/syslogd";

const MACOS_LSOF = `COMMAND   PID           USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
node      123 chiejimofor    3u  IPv4 0x1234567890      0t0  TCP *:3000 (LISTEN)
node      456 chiejimofor    5u  IPv6 0x9876543210      0t0  TCP *:8080 (LISTEN)`;

const LINUX_SS = `Netid  State   Recv-Q  Send-Q   Local Address:Port    Peer Address:Port Process
tcp    LISTEN  0       128      0.0.0.0:22             0.0.0.0:*      users:(("sshd",pid=1234,fd=3))
tcp    LISTEN  0       128      0.0.0.0:8082           0.0.0.0:*      users:(("node",pid=5678,fd=22))`;

const MACOS_PFCTL = `pass in quick on lo0 all flags S/SA
block drop in on ! lo0 proto tcp from any to any port 22`;

const client = {} as Client;

// ── Tests ──

describe("CPU collector", () => {
  beforeEach(() => {
    execCommandMock.mockReset();
    detectOSMock.mockReset();
  });

  it("parses macOS CPU metrics", async () => {
    detectOSMock.mockResolvedValue("darwin");
    execCommandMock
      .mockResolvedValueOnce(ok(MACOS_TOP_CPU))
      .mockResolvedValueOnce(ok(MACOS_LOADAVG))
      .mockResolvedValueOnce(ok(MACOS_NCPU));

    const result = await collectCpuMetrics(client);

    expect(result.percent).toBe(19);
    expect(result.cores).toBe(10);
    expect(result.load).toEqual([2.13, 5.37, 8.86]);
  });

  it("parses Linux CPU metrics", async () => {
    detectOSMock.mockResolvedValue("linux");
    execCommandMock
      .mockResolvedValueOnce(ok(LINUX_PROC_STAT_1))
      .mockResolvedValueOnce(ok(LINUX_LOADAVG))
      .mockResolvedValueOnce(ok(LINUX_NPROC))
      .mockResolvedValueOnce(ok(LINUX_PROC_STAT_2));

    const result = await collectCpuMetrics(client);

    expect(result.percent).toBeTypeOf("number");
    expect(result.cores).toBe(16);
    expect(result.load).toEqual([1.23, 4.56, 7.89]);
  });
});

describe("Memory collector", () => {
  beforeEach(() => {
    execCommandMock.mockReset();
    detectOSMock.mockReset();
  });

  it("parses macOS memory metrics", async () => {
    detectOSMock.mockResolvedValue("darwin");
    execCommandMock
      .mockResolvedValueOnce(ok(MACOS_VMSTAT))
      .mockResolvedValueOnce(ok(MACOS_MEMSIZE))
      .mockResolvedValueOnce(ok(MACOS_PAGESIZE));

    const result = await collectMemoryMetrics(client);

    expect(result.totalGiB).toBe(16);
    expect(result.usedGiB).toBeTypeOf("number");
    expect(result.percent).toBeTypeOf("number");
    expect(result.percent!).toBeGreaterThan(0);
    expect(result.percent!).toBeLessThanOrEqual(100);
  });

  it("parses Linux memory metrics", async () => {
    detectOSMock.mockResolvedValue("linux");
    execCommandMock.mockResolvedValueOnce(ok(LINUX_MEMINFO));

    const result = await collectMemoryMetrics(client);

    expect(result.totalGiB).toBeCloseTo(93.75, 0);
    expect(result.usedGiB).toBeCloseTo(62.5, 0);
    expect(result.percent).toBe(67);
  });
});

describe("Disk collector", () => {
  beforeEach(() => {
    execCommandMock.mockReset();
    detectOSMock.mockReset();
  });

  it("parses macOS disk with human-readable sizes (not raw blocks)", async () => {
    detectOSMock.mockResolvedValue("darwin");
    execCommandMock
      .mockResolvedValueOnce(ok(MACOS_DF_H))
      .mockResolvedValueOnce(ok(MACOS_DF_K_P));

    const result = await collectDiskMetrics(client);

    expect(result.totalHuman).toBe("228Gi");
    expect(result.usedHuman).toBe("11Gi");
    expect(result.availableHuman).toBe("31Gi");
    expect(result.percent).toBeTypeOf("number");
    // The bug was: df -h -P on macOS showed "478724992" instead of "228Gi"
    expect(result.totalHuman).not.toMatch(/^\d{6,}$/);
  });

  it("parses Linux disk metrics", async () => {
    detectOSMock.mockResolvedValue("linux");
    execCommandMock
      .mockResolvedValueOnce(ok(LINUX_DF_H_P))
      .mockResolvedValueOnce(ok(LINUX_DF_K_P));

    const result = await collectDiskMetrics(client);

    expect(result.totalHuman).toBe("1.8T");
    expect(result.usedHuman).toBe("500G");
    expect(result.percent).toBeTypeOf("number");
  });
});

describe("Uptime collector", () => {
  beforeEach(() => {
    execCommandMock.mockReset();
    detectOSMock.mockReset();
  });

  it("parses macOS uptime from kern.boottime", async () => {
    detectOSMock.mockResolvedValue("darwin");
    execCommandMock.mockResolvedValueOnce(ok(MACOS_UPTIME_BOOTTIME));

    const result = await collectUptimeMetrics(client);

    expect(result.seconds).toBeTypeOf("number");
    expect(result.seconds!).toBeGreaterThan(0);
    expect(result.formatted).toMatch(/\d+d \d+h \d+m/);
  });

  it("parses Linux uptime from /proc/uptime", async () => {
    detectOSMock.mockResolvedValue("linux");
    execCommandMock.mockResolvedValueOnce(ok(LINUX_PROC_UPTIME));

    const result = await collectUptimeMetrics(client);

    expect(result.seconds).toBe(123456.78);
    expect(result.formatted).toBe("1d 10h 17m");
  });
});

describe("System collector", () => {
  beforeEach(() => {
    execCommandMock.mockReset();
    detectOSMock.mockReset();
  });

  it("parses macOS system info from sw_vers", async () => {
    detectOSMock.mockResolvedValue("darwin");
    execCommandMock
      .mockResolvedValueOnce(ok("work-mac.local"))
      .mockResolvedValueOnce(ok("24.2.0"))
      .mockResolvedValueOnce(ok(MACOS_SW_VERS));

    const result = await collectSystemMetrics(client);

    expect(result.hostname).toBe("work-mac.local");
    expect(result.kernel).toBe("24.2.0");
    expect(result.os).toBe("macOS 15.2");
  });

  it("parses Linux system info", async () => {
    detectOSMock.mockResolvedValue("linux");
    execCommandMock
      .mockResolvedValueOnce(ok("gmk-server"))
      .mockResolvedValueOnce(ok("6.12.1-arch1-1"))
      .mockResolvedValueOnce(ok(LINUX_OS_RELEASE));

    const result = await collectSystemMetrics(client);

    expect(result.hostname).toBe("gmk-server");
    expect(result.os).toBe("Arch Linux");
  });
});

describe("Network collector", () => {
  beforeEach(() => {
    execCommandMock.mockReset();
    detectOSMock.mockReset();
  });

  it("parses macOS ifconfig output, excludes lo0", async () => {
    detectOSMock.mockResolvedValue("darwin");
    execCommandMock.mockResolvedValueOnce(ok(MACOS_IFCONFIG));

    const result = await collectNetworkMetrics(client);

    expect(result.interfaces.length).toBeGreaterThan(0);
    const en0 = result.interfaces.find((i) => i.name === "en0");
    expect(en0).toBeDefined();
    expect(en0!.ip).toBe("192.168.1.100");
    expect(en0!.state).toBe("UP");
    expect(result.interfaces.find((i) => i.name === "lo0")).toBeUndefined();
  });

  it("parses Linux ip command output", async () => {
    detectOSMock.mockResolvedValue("linux");
    execCommandMock
      .mockResolvedValueOnce(ok(LINUX_IP_ADDR))
      .mockResolvedValueOnce(ok(LINUX_IP_LINK));

    const result = await collectNetworkMetrics(client);

    const eth0 = result.interfaces.find((i) => i.name === "eth0");
    expect(eth0).toBeDefined();
    expect(eth0!.ip).toBe("192.168.1.50");
    expect(eth0!.state).toBe("UP");
  });
});

describe("Processes collector", () => {
  beforeEach(() => {
    execCommandMock.mockReset();
    detectOSMock.mockReset();
  });

  it("parses macOS ps output (BSD flags)", async () => {
    detectOSMock.mockResolvedValue("darwin");
    const psOutput = [MACOS_PS_HEADER, MACOS_PS_ROW1, MACOS_PS_ROW2].join(
      "\n",
    );
    execCommandMock
      .mockResolvedValueOnce(ok(psOutput))
      .mockResolvedValueOnce(ok("150"))
      .mockResolvedValueOnce(ok("3"));

    const result = await collectProcessesMetrics(client);

    expect(result.top.length).toBe(2);
    expect(result.top[0].cpu).toBe("45");
    expect(result.top[0].command).toContain("node");
    expect(result.total).toBe(149);
  });
});

describe("Ports collector", () => {
  beforeEach(() => {
    execCommandMock.mockReset();
    detectOSMock.mockReset();
  });

  it("parses macOS lsof output", async () => {
    detectOSMock.mockResolvedValue("darwin");
    execCommandMock.mockResolvedValueOnce(ok(MACOS_LSOF));

    const result = await collectPortsMetrics(client);

    expect(result.source).toBe("lsof");
    expect(result.ports.length).toBe(2);
    expect(result.ports[0].localPort).toBe(3000);
    expect(result.ports[0].process).toBe("node");
    expect(result.ports[1].localPort).toBe(8080);
  });

  it("parses Linux ss output", async () => {
    detectOSMock.mockResolvedValue("linux");
    execCommandMock.mockResolvedValueOnce(ok(LINUX_SS));

    const result = await collectPortsMetrics(client);

    expect(result.source).toBe("ss");
    expect(result.ports.length).toBe(2);
    expect(result.ports[0].localPort).toBe(22);
    expect(result.ports[1].localPort).toBe(8082);
  });
});

describe("Firewall collector", () => {
  beforeEach(() => {
    execCommandMock.mockReset();
    detectOSMock.mockReset();
  });

  it("parses macOS pfctl output", async () => {
    detectOSMock.mockResolvedValue("darwin");
    execCommandMock.mockResolvedValueOnce(ok(MACOS_PFCTL));

    const result = await collectFirewallMetrics(client);

    expect(result.type).toBe("pf");
    expect(result.status).toBe("active");
    expect(result.chains.length).toBeGreaterThan(0);
  });

  it("returns inactive when iptables has no rules", async () => {
    detectOSMock.mockResolvedValue("linux");
    execCommandMock
      .mockResolvedValueOnce(ok("")) // iptables empty
      .mockResolvedValueOnce(ok("")); // nftables empty

    const result = await collectFirewallMetrics(client);

    expect(result.type).toBe("none");
  });
});
