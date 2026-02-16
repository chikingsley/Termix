import type { Client } from "ssh2";
import { execCommand, detectOS } from "./common-utils.js";

interface NetworkInterface {
  name: string;
  ip: string;
  state: string;
  rxBytes: string | null;
  txBytes: string | null;
}

interface NetworkMetrics {
  interfaces: NetworkInterface[];
}

async function collectNetworkLinux(client: Client): Promise<NetworkMetrics> {
  const interfaces: NetworkInterface[] = [];

  const [ifconfigOut, netStatOut] = await Promise.all([
    execCommand(
      client,
      "ip -o addr show | awk '{print $2,$4}' | grep -v '^lo'",
    ),
    execCommand(
      client,
      "ip -o link show | awk '{gsub(/:/, \"\", $2); print $2,$9}'",
    ),
  ]);

  const addrs = ifconfigOut.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);
  const states = netStatOut.stdout
    .split("\n")
    .map((l) => l.trim())
    .filter(Boolean);

  const ifMap = new Map<string, { ip: string; state: string }>();
  for (const line of addrs) {
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      const name = parts[0];
      const ip = parts[1].split("/")[0];
      if (!ifMap.has(name)) ifMap.set(name, { ip, state: "UNKNOWN" });
    }
  }
  for (const line of states) {
    const parts = line.split(/\s+/);
    if (parts.length >= 2) {
      const name = parts[0];
      const state = parts[1];
      const existing = ifMap.get(name);
      if (existing) {
        existing.state = state;
      }
    }
  }

  for (const [name, data] of ifMap.entries()) {
    interfaces.push({
      name,
      ip: data.ip,
      state: data.state,
      rxBytes: null,
      txBytes: null,
    });
  }

  return { interfaces };
}

async function collectNetworkDarwin(client: Client): Promise<NetworkMetrics> {
  const interfaces: NetworkInterface[] = [];

  const ifconfigOut = await execCommand(client, "ifconfig -a");
  const lines = ifconfigOut.stdout.split("\n");

  let currentIf: string | null = null;
  let currentIp: string | null = null;
  let currentState = "UNKNOWN";

  for (const line of lines) {
    // Interface header: "en0: flags=8863<UP,BROADCAST,..."
    const ifMatch = line.match(/^(\w+):\s+flags=\d+<([^>]*)>/);
    if (ifMatch) {
      // Save previous interface
      if (currentIf && currentIf !== "lo0" && currentIp) {
        interfaces.push({
          name: currentIf,
          ip: currentIp,
          state: currentState,
          rxBytes: null,
          txBytes: null,
        });
      }
      currentIf = ifMatch[1];
      currentIp = null;
      const flags = ifMatch[2];
      currentState = flags.includes("UP") ? "UP" : "DOWN";
      continue;
    }

    // IPv4 address: "	inet 192.168.1.100 netmask ..."
    const inetMatch = line.match(/^\s+inet\s+(\d+\.\d+\.\d+\.\d+)/);
    if (inetMatch && currentIf && !currentIp) {
      currentIp = inetMatch[1];
    }
  }

  // Don't forget the last interface
  if (currentIf && currentIf !== "lo0" && currentIp) {
    interfaces.push({
      name: currentIf,
      ip: currentIp,
      state: currentState,
      rxBytes: null,
      txBytes: null,
    });
  }

  return { interfaces };
}

export async function collectNetworkMetrics(
  client: Client,
): Promise<NetworkMetrics> {
  try {
    const os = await detectOS(client);
    if (os === "darwin") return await collectNetworkDarwin(client);
    return await collectNetworkLinux(client);
  } catch {
    return { interfaces: [] };
  }
}
