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
  4444, // Metasploit meterpreter default
  4445, // Metasploit alternate
  5555, // ADB reverse / backdoor default
  6666, // IRC botnet channel
  6667, // IRC botnet channel
  9999, // Common reverse-shell / backdoor wildcard
  12345, // NetBus / classic RAT
  31337, // Back Orifice / "elite" rootkit
  54321, // Common trojan / custom C2
]);

/** True when the address role represents an actual remote (public) endpoint. */
export function isRemoteRole(role: string | null | undefined): boolean {
  return typeof role === "string" && !NON_REMOTE_ROLES.has(role);
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