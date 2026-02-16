import type { Client } from "ssh2";
import { execCommand, toFixedNum, detectOS } from "./common-utils.js";

function parseCpuLine(
  cpuLine: string,
): { total: number; idle: number } | undefined {
  const parts = cpuLine.trim().split(/\s+/);
  if (parts[0] !== "cpu") return undefined;
  const nums = parts
    .slice(1)
    .map((n) => Number(n))
    .filter((n) => Number.isFinite(n));
  if (nums.length < 4) return undefined;
  const idle = (nums[3] ?? 0) + (nums[4] ?? 0);
  const total = nums.reduce((a, b) => a + b, 0);
  return { total, idle };
}

async function collectCpuLinux(client: Client): Promise<{
  percent: number | null;
  cores: number | null;
  load: [number, number, number] | null;
}> {
  let cpuPercent: number | null = null;
  let cores: number | null = null;
  let loadTriplet: [number, number, number] | null = null;

  const [stat1, loadAvgOut, coresOut] = await Promise.race([
    Promise.all([
      execCommand(client, "cat /proc/stat"),
      execCommand(client, "cat /proc/loadavg"),
      execCommand(
        client,
        "nproc 2>/dev/null || grep -c ^processor /proc/cpuinfo",
      ),
    ]),
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error("CPU metrics collection timeout")),
        25000,
      ),
    ),
  ]);

  await new Promise((r) => setTimeout(r, 500));
  const stat2 = await execCommand(client, "cat /proc/stat");

  const cpuLine1 = (
    stat1.stdout.split("\n").find((l) => l.startsWith("cpu ")) || ""
  ).trim();
  const cpuLine2 = (
    stat2.stdout.split("\n").find((l) => l.startsWith("cpu ")) || ""
  ).trim();
  const a = parseCpuLine(cpuLine1);
  const b = parseCpuLine(cpuLine2);
  if (a && b) {
    const totalDiff = b.total - a.total;
    const idleDiff = b.idle - a.idle;
    const used = totalDiff - idleDiff;
    if (totalDiff > 0)
      cpuPercent = Math.max(0, Math.min(100, (used / totalDiff) * 100));
  }

  const laParts = loadAvgOut.stdout.trim().split(/\s+/);
  if (laParts.length >= 3) {
    loadTriplet = [
      Number(laParts[0]),
      Number(laParts[1]),
      Number(laParts[2]),
    ].map((v) => (Number.isFinite(v) ? Number(v) : 0)) as [
      number,
      number,
      number,
    ];
  }

  const coresNum = Number((coresOut.stdout || "").trim());
  cores = Number.isFinite(coresNum) && coresNum > 0 ? coresNum : null;

  return {
    percent: toFixedNum(cpuPercent, 0),
    cores,
    load: loadTriplet,
  };
}

async function collectCpuDarwin(client: Client): Promise<{
  percent: number | null;
  cores: number | null;
  load: [number, number, number] | null;
}> {
  let cpuPercent: number | null = null;
  let cores: number | null = null;
  let loadTriplet: [number, number, number] | null = null;

  const [topOut, loadOut, coresOut] = await Promise.race([
    Promise.all([
      execCommand(
        client,
        "top -l 2 -n 0 -s 1 | grep -A1 'CPU usage' | tail -1",
        15000,
      ),
      execCommand(client, "sysctl -n vm.loadavg"),
      execCommand(client, "sysctl -n hw.ncpu"),
    ]),
    new Promise<never>((_, reject) =>
      setTimeout(
        () => reject(new Error("CPU metrics collection timeout")),
        25000,
      ),
    ),
  ]);

  // Parse "CPU usage: 5.26% user, 10.52% sys, 84.21% idle"
  const cpuMatch = topOut.stdout.match(
    /(\d+\.?\d*)%\s+user.*?(\d+\.?\d*)%\s+sys.*?(\d+\.?\d*)%\s+idle/,
  );
  if (cpuMatch) {
    const user = Number(cpuMatch[1]);
    const sys = Number(cpuMatch[2]);
    cpuPercent = user + sys;
  }

  // Parse "{ 1.23 4.56 7.89 }"
  const loadMatch = loadOut.stdout.match(
    /\{\s*(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+\.?\d*)\s*\}/,
  );
  if (loadMatch) {
    loadTriplet = [
      Number(loadMatch[1]),
      Number(loadMatch[2]),
      Number(loadMatch[3]),
    ] as [number, number, number];
  }

  const coresNum = Number(coresOut.stdout.trim());
  cores = Number.isFinite(coresNum) && coresNum > 0 ? coresNum : null;

  return {
    percent: toFixedNum(cpuPercent, 0),
    cores,
    load: loadTriplet,
  };
}

export async function collectCpuMetrics(client: Client): Promise<{
  percent: number | null;
  cores: number | null;
  load: [number, number, number] | null;
}> {
  try {
    const os = await detectOS(client);
    if (os === "darwin") return await collectCpuDarwin(client);
    return await collectCpuLinux(client);
  } catch {
    return { percent: null, cores: null, load: null };
  }
}
