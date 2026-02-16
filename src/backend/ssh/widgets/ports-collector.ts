import type { Client } from "ssh2";
import { execCommand, detectOS } from "./common-utils.js";
import type {
  PortsMetrics,
  ListeningPort,
} from "../../../types/stats-widgets.js";

function parseSsOutput(output: string): ListeningPort[] {
  const ports: ListeningPort[] = [];
  const lines = output.split("\n").slice(1);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const parts = trimmed.split(/\s+/);
    if (parts.length < 5) continue;

    const protocol = parts[0]?.toLowerCase();
    if (protocol !== "tcp" && protocol !== "udp") continue;

    const state = parts[1];
    const localAddr = parts[4];

    if (!localAddr) continue;

    const lastColon = localAddr.lastIndexOf(":");
    if (lastColon === -1) continue;

    const address = localAddr.substring(0, lastColon);
    const portStr = localAddr.substring(lastColon + 1);
    const port = parseInt(portStr, 10);

    if (isNaN(port)) continue;

    const portEntry: ListeningPort = {
      protocol: protocol as "tcp" | "udp",
      localAddress: address.replace(/^\[|\]$/g, ""),
      localPort: port,
      state: protocol === "tcp" ? state : undefined,
    };

    const processInfo = parts[6];
    if (processInfo && processInfo.startsWith("users:")) {
      const pidMatch = processInfo.match(/pid=(\d+)/);
      const nameMatch = processInfo.match(/\("([^"]+)"/);
      if (pidMatch) portEntry.pid = parseInt(pidMatch[1], 10);
      if (nameMatch) portEntry.process = nameMatch[1];
    }

    ports.push(portEntry);
  }

  return ports;
}

function parseNetstatOutput(output: string): ListeningPort[] {
  const ports: ListeningPort[] = [];
  const lines = output.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    const parts = trimmed.split(/\s+/);
    if (parts.length < 4) continue;

    const proto = parts[0]?.toLowerCase();
    if (!proto) continue;

    let protocol: "tcp" | "udp";
    if (proto.startsWith("tcp")) {
      protocol = "tcp";
    } else if (proto.startsWith("udp")) {
      protocol = "udp";
    } else {
      continue;
    }

    const localAddr = parts[3];
    if (!localAddr) continue;

    const lastColon = localAddr.lastIndexOf(":");
    if (lastColon === -1) continue;

    const address = localAddr.substring(0, lastColon);
    const portStr = localAddr.substring(lastColon + 1);
    const port = parseInt(portStr, 10);

    if (isNaN(port)) continue;

    const portEntry: ListeningPort = {
      protocol,
      localAddress: address,
      localPort: port,
    };

    if (protocol === "tcp" && parts.length >= 6) {
      portEntry.state = parts[5];
    }

    const pidProgram = parts[parts.length - 1];
    if (pidProgram && pidProgram.includes("/")) {
      const [pidStr, process] = pidProgram.split("/");
      const pid = parseInt(pidStr, 10);
      if (!isNaN(pid)) portEntry.pid = pid;
      if (process) portEntry.process = process;
    }

    ports.push(portEntry);
  }

  return ports;
}

function parseLsofOutput(output: string): ListeningPort[] {
  const ports: ListeningPort[] = [];
  const lines = output.split("\n");

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    // lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    const parts = trimmed.split(/\s+/);
    if (parts.length < 10) continue;

    const command = parts[0];
    const pid = parseInt(parts[1], 10);
    const name = parts[parts.length - 1]; // e.g. "*:8080" or "127.0.0.1:3000"

    if (!name || !name.includes(":")) continue;

    const lastColon = name.lastIndexOf(":");
    const address = name.substring(0, lastColon);
    const portStr = name.substring(lastColon + 1);
    const port = parseInt(portStr, 10);

    if (isNaN(port)) continue;

    // Check for "(LISTEN)" in the line
    if (!trimmed.includes("LISTEN")) continue;

    const portEntry: ListeningPort = {
      protocol: "tcp",
      localAddress: address === "*" ? "0.0.0.0" : address,
      localPort: port,
      state: "LISTEN",
    };

    if (!isNaN(pid)) portEntry.pid = pid;
    if (command) portEntry.process = command;

    ports.push(portEntry);
  }

  return ports;
}

export async function collectPortsMetrics(
  client: Client,
): Promise<PortsMetrics> {
  try {
    const os = await detectOS(client);

    if (os === "darwin") {
      const lsofResult = await execCommand(
        client,
        "lsof -iTCP -sTCP:LISTEN -nP 2>/dev/null",
        15000,
      );

      if (lsofResult.stdout && lsofResult.stdout.includes("COMMAND")) {
        const ports = parseLsofOutput(lsofResult.stdout);
        return {
          source: "lsof",
          ports: ports.sort((a, b) => a.localPort - b.localPort),
        };
      }

      return { source: "none", ports: [] };
    }

    // Linux: try ss first, then netstat
    const ssResult = await execCommand(client, "ss -tulnp 2>/dev/null", 15000);

    if (ssResult.stdout && ssResult.stdout.includes("Local")) {
      const ports = parseSsOutput(ssResult.stdout);
      return {
        source: "ss",
        ports: ports.sort((a, b) => a.localPort - b.localPort),
      };
    }

    const netstatResult = await execCommand(
      client,
      "netstat -tulnp 2>/dev/null",
      15000,
    );

    if (netstatResult.stdout && netstatResult.stdout.includes("Local")) {
      const ports = parseNetstatOutput(netstatResult.stdout);
      return {
        source: "netstat",
        ports: ports.sort((a, b) => a.localPort - b.localPort),
      };
    }

    return { source: "none", ports: [] };
  } catch {
    return { source: "none", ports: [] };
  }
}
