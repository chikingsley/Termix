import type { Client } from "ssh2";
import { execCommand, toFixedNum, kibToGiB, detectOS } from "./common-utils.js";

async function collectMemoryLinux(client: Client): Promise<{
  percent: number | null;
  usedGiB: number | null;
  totalGiB: number | null;
}> {
  const memInfo = await execCommand(client, "cat /proc/meminfo");
  const lines = memInfo.stdout.split("\n");
  const getVal = (key: string) => {
    const line = lines.find((l) => l.startsWith(key));
    if (!line) return null;
    const m = line.match(/\d+/);
    return m ? Number(m[0]) : null;
  };
  const totalKb = getVal("MemTotal:");
  const availKb = getVal("MemAvailable:");
  if (totalKb && availKb && totalKb > 0) {
    const usedKb = totalKb - availKb;
    const memPercent = Math.max(0, Math.min(100, (usedKb / totalKb) * 100));
    return {
      percent: toFixedNum(memPercent, 0),
      usedGiB: toFixedNum(kibToGiB(usedKb), 2),
      totalGiB: toFixedNum(kibToGiB(totalKb), 2),
    };
  }
  return { percent: null, usedGiB: null, totalGiB: null };
}

async function collectMemoryDarwin(client: Client): Promise<{
  percent: number | null;
  usedGiB: number | null;
  totalGiB: number | null;
}> {
  const [vmStatOut, memSizeOut, pageSizeOut] = await Promise.all([
    execCommand(client, "vm_stat"),
    execCommand(client, "sysctl -n hw.memsize"),
    execCommand(client, "pagesize"),
  ]);

  const totalBytes = Number(memSizeOut.stdout.trim());
  if (!Number.isFinite(totalBytes) || totalBytes <= 0) {
    return { percent: null, usedGiB: null, totalGiB: null };
  }

  const pageSize = Number(pageSizeOut.stdout.trim()) || 4096;
  const lines = vmStatOut.stdout.split("\n");
  const getPages = (key: string): number => {
    const line = lines.find((l) => l.includes(key));
    if (!line) return 0;
    const m = line.match(/(\d+)/);
    return m ? Number(m[1]) : 0;
  };

  const free = getPages("Pages free");
  const speculative = getPages("Pages speculative");
  const purgeable = getPages("Pages purgeable");
  const availableBytes = (free + speculative + purgeable) * pageSize;
  const usedBytes = totalBytes - availableBytes;

  const memPercent = Math.max(0, Math.min(100, (usedBytes / totalBytes) * 100));
  const totalGiB = totalBytes / (1024 * 1024 * 1024);
  const usedGiB = usedBytes / (1024 * 1024 * 1024);

  return {
    percent: toFixedNum(memPercent, 0),
    usedGiB: toFixedNum(usedGiB, 2),
    totalGiB: toFixedNum(totalGiB, 2),
  };
}

export async function collectMemoryMetrics(client: Client): Promise<{
  percent: number | null;
  usedGiB: number | null;
  totalGiB: number | null;
}> {
  try {
    const os = await detectOS(client);
    if (os === "darwin") return await collectMemoryDarwin(client);
    return await collectMemoryLinux(client);
  } catch {
    return { percent: null, usedGiB: null, totalGiB: null };
  }
}
