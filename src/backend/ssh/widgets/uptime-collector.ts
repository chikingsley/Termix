import type { Client } from "ssh2";
import { execCommand, detectOS } from "./common-utils.js";

function formatUptime(seconds: number): string {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  return `${days}d ${hours}h ${minutes}m`;
}

export async function collectUptimeMetrics(client: Client): Promise<{
  seconds: number | null;
  formatted: string | null;
}> {
  try {
    const os = await detectOS(client);
    let uptimeSeconds: number | null = null;

    if (os === "darwin") {
      // sysctl kern.boottime returns: { sec = 1234567890, usec = 0 } ...
      const result = await execCommand(client, "sysctl -n kern.boottime");
      const secMatch = result.stdout.match(/sec\s*=\s*(\d+)/);
      if (secMatch) {
        const bootEpoch = Number(secMatch[1]);
        uptimeSeconds = Math.floor(Date.now() / 1000) - bootEpoch;
      }
    } else {
      const uptimeOut = await execCommand(client, "cat /proc/uptime");
      const uptimeParts = uptimeOut.stdout.trim().split(/\s+/);
      if (uptimeParts.length >= 1) {
        uptimeSeconds = Number(uptimeParts[0]);
      }
    }

    if (uptimeSeconds !== null && Number.isFinite(uptimeSeconds)) {
      return {
        seconds: uptimeSeconds,
        formatted: formatUptime(uptimeSeconds),
      };
    }
  } catch {}

  return { seconds: null, formatted: null };
}
