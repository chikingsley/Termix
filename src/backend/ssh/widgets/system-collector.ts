import type { Client } from "ssh2";
import { execCommand, detectOS } from "./common-utils.js";

export async function collectSystemMetrics(client: Client): Promise<{
  hostname: string | null;
  kernel: string | null;
  os: string | null;
}> {
  try {
    const osType = await detectOS(client);

    const osCmd =
      osType === "darwin"
        ? "sw_vers -productName && sw_vers -productVersion"
        : "cat /etc/os-release | grep '^PRETTY_NAME=' | cut -d'\"' -f2";

    const [hostnameOut, kernelOut, osOut] = await Promise.all([
      execCommand(client, "hostname"),
      execCommand(client, "uname -r"),
      execCommand(client, osCmd),
    ]);

    let osStr: string | null = null;
    if (osType === "darwin") {
      // sw_vers outputs two lines: "macOS\n15.2" → "macOS 15.2"
      const parts = osOut.stdout
        .split("\n")
        .map((l) => l.trim())
        .filter(Boolean);
      osStr = parts.join(" ") || null;
    } else {
      osStr = osOut.stdout.trim() || null;
    }

    return {
      hostname: hostnameOut.stdout.trim() || null,
      kernel: kernelOut.stdout.trim() || null,
      os: osStr,
    };
  } catch {
    return { hostname: null, kernel: null, os: null };
  }
}
