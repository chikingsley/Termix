import type { Client } from "ssh2";
import { execCommand, detectOS } from "./common-utils.js";

export interface LoginRecord {
  user: string;
  ip: string;
  time: string;
  status: "success" | "failed";
}

export interface LoginStats {
  recentLogins: LoginRecord[];
  failedLogins: LoginRecord[];
  totalLogins: number;
  uniqueIPs: number;
}

function parseTime(timeStr: string): string {
  try {
    const date = new Date(timeStr);
    return isNaN(date.getTime())
      ? new Date().toISOString()
      : date.toISOString();
  } catch {
    return new Date().toISOString();
  }
}

async function collectLoginStatsLinux(client: Client): Promise<LoginStats> {
  const recentLogins: LoginRecord[] = [];
  const failedLogins: LoginRecord[] = [];
  const ipSet = new Set<string>();

  try {
    const lastOut = await execCommand(
      client,
      "last -n 20 -F -w | grep -v 'reboot' | grep -v 'wtmp' | head -20",
    );

    const lastLines = lastOut.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);

    for (const line of lastLines) {
      const parts = line.split(/\s+/);
      if (parts.length >= 10) {
        const user = parts[0];
        const tty = parts[1];
        const ip =
          parts[2] === ":" || parts[2].startsWith(":") ? "local" : parts[2];

        const timeStart = parts.indexOf(
          parts.find((p) => /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/.test(p)) || "",
        );
        if (timeStart > 0 && parts.length > timeStart + 4) {
          const timeStr = parts.slice(timeStart, timeStart + 5).join(" ");

          if (user && user !== "wtmp" && tty !== "system") {
            recentLogins.push({
              user,
              ip,
              time: parseTime(timeStr),
              status: "success",
            });
            if (ip !== "local") ipSet.add(ip);
          }
        }
      }
    }
  } catch {}

  try {
    const failedOut = await execCommand(
      client,
      "grep 'Failed password' /var/log/auth.log 2>/dev/null | tail -10 || grep 'authentication failure' /var/log/secure 2>/dev/null | tail -10 || echo ''",
    );

    const failedLines = failedOut.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);

    for (const line of failedLines) {
      let user = "unknown";
      let ip = "unknown";
      let timeStr = "";

      const userMatch = line.match(/for (?:invalid user )?(\S+)/);
      if (userMatch) user = userMatch[1];

      const ipMatch = line.match(/from (\d+\.\d+\.\d+\.\d+)/);
      if (ipMatch) ip = ipMatch[1];

      const dateMatch = line.match(/^(\w+\s+\d+\s+\d+:\d+:\d+)/);
      if (dateMatch) {
        const currentYear = new Date().getFullYear();
        timeStr = `${currentYear} ${dateMatch[1]}`;
      }

      if (user && ip) {
        failedLogins.push({
          user,
          ip,
          time: parseTime(timeStr || new Date().toISOString()),
          status: "failed",
        });
        if (ip !== "unknown") ipSet.add(ip);
      }
    }
  } catch {}

  return {
    recentLogins: recentLogins.slice(0, 10),
    failedLogins: failedLogins.slice(0, 10),
    totalLogins: recentLogins.length,
    uniqueIPs: ipSet.size,
  };
}

async function collectLoginStatsDarwin(client: Client): Promise<LoginStats> {
  const recentLogins: LoginRecord[] = [];
  const failedLogins: LoginRecord[] = [];
  const ipSet = new Set<string>();

  try {
    // macOS `last` doesn't support -F or -w, just use -20 for count
    const lastOut = await execCommand(
      client,
      "last -20 | grep -v 'reboot' | grep -v 'shutdown' | grep -v 'wtmp' | head -20",
    );

    const lastLines = lastOut.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);

    for (const line of lastLines) {
      const parts = line.split(/\s+/);
      if (parts.length >= 6) {
        const user = parts[0];
        const tty = parts[1];
        const ip =
          parts[2] === ":" || parts[2].startsWith(":") ? "local" : parts[2];

        // macOS last format: user tty [host] Day Mon DD HH:MM - HH:MM (duration)
        const timeStart = parts.indexOf(
          parts.find((p) => /^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)/.test(p)) || "",
        );
        if (timeStart > 0 && parts.length > timeStart + 3) {
          const timeStr = parts.slice(timeStart, timeStart + 4).join(" ");

          if (user && user !== "wtmp" && tty !== "system") {
            recentLogins.push({
              user,
              ip,
              time: parseTime(timeStr),
              status: "success",
            });
            if (ip !== "local") ipSet.add(ip);
          }
        }
      }
    }
  } catch {}

  try {
    // macOS uses unified logging for auth failures
    const failedOut = await execCommand(
      client,
      "log show --predicate 'eventMessage contains \"Failed\"' --style syslog --last 1h 2>/dev/null | grep -i 'auth\\|ssh\\|login' | tail -10 || echo ''",
      15000,
    );

    const failedLines = failedOut.stdout
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean);

    for (const line of failedLines) {
      let user = "unknown";
      let ip = "unknown";

      const userMatch = line.match(/for (?:invalid user )?(\S+)/);
      if (userMatch) user = userMatch[1];

      const ipMatch = line.match(/from (\d+\.\d+\.\d+\.\d+)/);
      if (ipMatch) ip = ipMatch[1];

      // macOS log show format: "2024-01-15 10:30:45.123456-0500 ..."
      const dateMatch = line.match(/^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})/);
      const timeStr = dateMatch ? dateMatch[1] : new Date().toISOString();

      if (user && ip) {
        failedLogins.push({
          user,
          ip,
          time: parseTime(timeStr),
          status: "failed",
        });
        if (ip !== "unknown") ipSet.add(ip);
      }
    }
  } catch {}

  return {
    recentLogins: recentLogins.slice(0, 10),
    failedLogins: failedLogins.slice(0, 10),
    totalLogins: recentLogins.length,
    uniqueIPs: ipSet.size,
  };
}

export async function collectLoginStats(client: Client): Promise<LoginStats> {
  try {
    const os = await detectOS(client);
    if (os === "darwin") return await collectLoginStatsDarwin(client);
    return await collectLoginStatsLinux(client);
  } catch {
    return {
      recentLogins: [],
      failedLogins: [],
      totalLogins: 0,
      uniqueIPs: 0,
    };
  }
}
