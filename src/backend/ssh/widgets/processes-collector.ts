import type { Client } from "ssh2";
import { execCommand, detectOS } from "./common-utils.js";

export async function collectProcessesMetrics(client: Client): Promise<{
  total: number | null;
  running: number | null;
  top: Array<{
    pid: string;
    user: string;
    cpu: string;
    mem: string;
    command: string;
  }>;
}> {
  let totalProcesses: number | null = null;
  let runningProcesses: number | null = null;
  const topProcesses: Array<{
    pid: string;
    user: string;
    cpu: string;
    mem: string;
    command: string;
  }> = [];

  try {
    const os = await detectOS(client);

    // macOS BSD ps doesn't support --sort, use -r (sort by CPU descending)
    const psCmd =
      os === "darwin"
        ? "ps aux -r | head -n 11"
        : "ps aux --sort=-%cpu | head -n 11";

    const psOut = await execCommand(client, psCmd);
    const psLines = psOut.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);
    if (psLines.length > 1) {
      for (let i = 1; i < Math.min(psLines.length, 11); i++) {
        const parts = psLines[i].split(/\s+/);
        if (parts.length >= 11) {
          const cpuVal = Number(parts[2]);
          const memVal = Number(parts[3]);
          topProcesses.push({
            pid: parts[1],
            user: parts[0],
            cpu: Number.isFinite(cpuVal) ? cpuVal.toString() : "0",
            mem: Number.isFinite(memVal) ? memVal.toString() : "0",
            command: parts.slice(10).join(" ").substring(0, 50),
          });
        }
      }
    }

    const [procCountOut, runningCountOut] = await Promise.all([
      execCommand(client, "ps aux | wc -l"),
      execCommand(client, "ps aux | grep -c ' R '"),
    ]);

    const totalCount = Number(procCountOut.stdout.trim()) - 1;
    totalProcesses = Number.isFinite(totalCount) ? totalCount : null;

    const runningCount = Number(runningCountOut.stdout.trim());
    runningProcesses = Number.isFinite(runningCount) ? runningCount : null;
  } catch {}

  return {
    total: totalProcesses,
    running: runningProcesses,
    top: topProcesses,
  };
}
