import type { Client } from "ssh2";
import { execCommand, toFixedNum, detectOS } from "./common-utils.js";

export async function collectDiskMetrics(client: Client): Promise<{
  percent: number | null;
  usedHuman: string | null;
  totalHuman: string | null;
  availableHuman: string | null;
}> {
  try {
    const os = await detectOS(client);

    // macOS: df -h -P together drops -h, so use df -h without -P
    // Linux: df -h -P works correctly
    const humanCmd =
      os === "darwin" ? "df -h / | tail -n +2" : "df -h -P / | tail -n +2";

    const [diskOutHuman, diskOutKiB] = await Promise.all([
      execCommand(client, humanCmd),
      execCommand(client, "df -k -P / | tail -n +2"),
    ]);

    const humanLine =
      diskOutHuman.stdout
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)[0] || "";
    const kibLine =
      diskOutKiB.stdout
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean)[0] || "";

    const humanParts = humanLine.split(/\s+/);
    const kibParts = kibLine.split(/\s+/);

    // macOS df -h (no -P): Filesystem Size Used Avail Capacity iused ifree %iused Mounted
    // Linux df -h -P:      Filesystem Size Used Avail Use% Mounted
    // Both have Size/Used/Avail at indices 1/2/3
    if (humanParts.length >= 5 && kibParts.length >= 5) {
      const totalHuman = humanParts[1] || null;
      const usedHuman = humanParts[2] || null;
      const availableHuman = humanParts[3] || null;

      const totalKiB = Number(kibParts[1]);
      const usedKiB = Number(kibParts[2]);

      let diskPercent: number | null = null;
      if (
        Number.isFinite(totalKiB) &&
        Number.isFinite(usedKiB) &&
        totalKiB > 0
      ) {
        diskPercent = Math.max(0, Math.min(100, (usedKiB / totalKiB) * 100));
      }

      return {
        percent: toFixedNum(diskPercent, 0),
        usedHuman,
        totalHuman,
        availableHuman,
      };
    }
  } catch {}

  return {
    percent: null,
    usedHuman: null,
    totalHuman: null,
    availableHuman: null,
  };
}
