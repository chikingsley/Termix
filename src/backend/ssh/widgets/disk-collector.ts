import type { Client } from "ssh2";
import { execCommand, toFixedNum } from "./common-utils.js";

export async function collectDiskMetrics(client: Client): Promise<{
  percent: number | null;
  usedHuman: string | null;
  totalHuman: string | null;
  availableHuman: string | null;
}> {
  try {
    const [diskOutHuman, diskOutKiB] = await Promise.all([
      execCommand(client, "df -h -P / | tail -n +2"),
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

    if (humanParts.length >= 6 && kibParts.length >= 6) {
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
