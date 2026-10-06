/**
 * Static classification lists and helpers for the network-detect NET rules.
 * Everything here is a deterministic pattern over real connection/port
 * telemetry — nothing is extrapolated or fabricated.
 *
 * Port roles mirror the engine's `classify_address` output:
 * LOCAL / LOOPBACK / PRIVATE / LINK_LOCAL / REMOTE / UNKNOWN.
 */

/** Remote-endpoint roles that are NOT the public internet. */
const NON_REMOTE_ROLES = new Set(["LOCAL", "LOOPBACK", "PRIVATE", "LINK_LOCAL", "UNKNOWN", ""]);

/**
 * Remote ports commonly associated with offensive tooling and implant C2
 * channels (Metasploit, RATs, IRC bots, reverse shells). This is a *pattern*
 * list, not attribution: a detection is always labelled as such and expected
 * to be correlated with local context before action is taken.
 */
const KNOWN_TOOL_PORTS = new Set<number>([
  23, // Telnet (tunnelled C2)
  1337, // Elite / common hacker listener
  4444, // Metasploit meterpreter default
  4445, // Metasploit alternate
  5555, // ADB reverse / backdoor default
  6666, // IRC botnet channel
  6667, // IRC botnet channel
  8888, // Common proxy / reverse shell
  9001, // Tor / netcat reverse shell
  9999, // Common reverse-shell / backdoor wildcard
  12345, // NetBus / classic RAT
  31337, // Back Orifice / "elite" rootkit
  54321, // Common trojan / custom C2
]);

/** True when the address role represents an actual remote (public) endpoint.
 * In LAB / DEMO mode (ARGUS_MODE=LAB or ALLOW_PRIVATE_RANGES_IN_DETECTION=true),
 * non-loopback private network endpoints (e.g. Kali VM on 192.168.x.x or 10.x.x.x)
 * are permitted to be evaluated by remote network rules. Loopback is strictly excluded.
 */
export function isRemoteRole(role: string | null | undefined, remoteAddr?: string | null): boolean {
  const isLabMode =
    process.env.ARGUS_MODE === "LAB" ||
    process.env.ALLOW_PRIVATE_RANGES_IN_DETECTION === "true" ||
    process.env.ARGUS_ALLOW_PRIVATE_RANGES === "true";

  if (isLabMode) {
    if (remoteAddr && (STRICT_LOCAL_ADDRS.has(remoteAddr) || remoteAddr.startsWith("127."))) {
      return false;
    }
    if (role && STRICT_LOCAL_ROLES.has(role.toUpperCase())) {
      return false;
    }
    // If it's a private address role or unspecified role with non-loopback remote address, allow in lab mode
    return true;
  }

  return typeof role === "string" && !NON_REMOTE_ROLES.has(role.toUpperCase());
}

/** Loopback / local machine addresses that are never external endpoints. */
export const STRICT_LOCAL_ROLES = new Set(["LOCAL", "LOOPBACK"]);
export const STRICT_LOCAL_ADDRS = new Set(["127.0.0.1", "::1", "0.0.0.0", "localhost", ""]);

/**
 * Returns true if the address represents an external device (either public internet
 * OR a private network host such as a virtual Kali VM, LAN attacker, or rogue gateway).
 */
export function isExternalOrPrivateRole(
  role: string | null | undefined,
  remoteAddr?: string | null
): boolean {
  if (remoteAddr && (STRICT_LOCAL_ADDRS.has(remoteAddr) || remoteAddr.startsWith("127."))) {
    return false;
  }
  if (!role) return Boolean(remoteAddr && !STRICT_LOCAL_ADDRS.has(remoteAddr));
  return !STRICT_LOCAL_ROLES.has(role.toUpperCase());
}

/** True when the port is on the known offensive-tooling list. */
export function isKnownToolPort(port: number | null | undefined): boolean {
  return typeof port === "number" && KNOWN_TOOL_PORTS.has(port);
}

/** Stable list to document in the rule catalog / reports. */
export const KNOWN_TOOL_PORT_LIST = [...KNOWN_TOOL_PORTS].sort((a, b) => a - b);

/** Wildcard binding markers emitted by the engine for 0.0.0.0 / :: / *. */
const WILDCARD_ADDRS = new Set(["0.0.0.0", "::", "*", ":"]);

/** True when a listener is bound to all interfaces (wildcard). */
export function isWildcardBinding(
  localAddr: string | null | undefined,
  bindingType: string | null | undefined,
): boolean {
  if (typeof bindingType === "string" && bindingType.toUpperCase() === "WILDCARD") return true;
  return typeof localAddr === "string" && WILDCARD_ADDRS.has(localAddr);
}