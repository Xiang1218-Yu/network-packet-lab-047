import type { EndpointDirection, Protocol } from './types.js';

/**
 * Single source of truth for endpoint direction.
 *
 * The simulated lab topology has two hosts:
 *   client  10.0.0.24:51842
 *   server  10.0.0.8:443
 *
 * Direction is always derived from the packet content itself, never from the
 * scenario selector: an HTTP start line tells request vs response, and the TCP
 * raw route ("TCP src > dst | …") is the unique source for TCP. When the
 * endpoints cannot be inferred, callers receive an explicit unknown state
 * instead of a silently assumed fixed value.
 */
export const CLIENT_ENDPOINT = '10.0.0.24:51842';
export const SERVER_ENDPOINT = '10.0.0.8:443';

export interface EndpointInfo {
  direction: EndpointDirection;
  /** Sender, or null when not derivable. */
  source: string | null;
  /** Receiver, or null when not derivable. */
  destination: string | null;
  /** Raw endpoint parsed for the source side, even if its role is unknown. */
  rawSource: string | null;
  /** Raw endpoint parsed for the destination side, even if its role is unknown. */
  rawDestination: string | null;
}

const UNKNOWN_ENDPOINT: EndpointInfo = {
  direction: 'unknown',
  source: null,
  destination: null,
  rawSource: null,
  rawDestination: null
};

export type HttpMessageKind = 'request' | 'response' | 'unknown';

/** Classify an HTTP message from its start line. */
export function classifyHttpMessage(raw: string): HttpMessageKind {
  const startLine = raw.split(/\r?\n/, 1)[0]?.trim() ?? '';
  if (!startLine) return 'unknown';
  if (startLine.startsWith('HTTP/')) return 'response';
  if (/^[!-~]+[ \t]+\S+[ \t]+HTTP\/\d(?:\.\d)?$/.test(startLine)) return 'request';
  return 'unknown';
}

function endpointsForHttp(raw: string): EndpointInfo {
  switch (classifyHttpMessage(raw)) {
    case 'request':
      return {
        direction: 'client-to-server',
        source: CLIENT_ENDPOINT,
        destination: SERVER_ENDPOINT,
        rawSource: CLIENT_ENDPOINT,
        rawDestination: SERVER_ENDPOINT
      };
    case 'response':
      return {
        direction: 'server-to-client',
        source: SERVER_ENDPOINT,
        destination: CLIENT_ENDPOINT,
        rawSource: SERVER_ENDPOINT,
        rawDestination: CLIENT_ENDPOINT
      };
    default:
      return UNKNOWN_ENDPOINT;
  }
}

/**
 * Parse the raw TCP route. The raw route is the unique source of TCP
 * endpoints; nothing else may supply or override them.
 */
export function parseTcpRoute(raw: string): { source: string; destination: string } | null {
  const route = raw.split(' | ', 1)[0]?.trim() ?? '';
  const match = /^TCP\s+(\S+)\s+>\s+(\S+)$/.exec(route);
  if (!match) return null;
  return { source: match[1], destination: match[2] };
}

function endpointsForTcp(raw: string): EndpointInfo {
  const route = parseTcpRoute(raw);
  if (!route) return UNKNOWN_ENDPOINT;
  let direction: EndpointDirection = 'unknown';
  if (route.source === CLIENT_ENDPOINT && route.destination === SERVER_ENDPOINT) {
    direction = 'client-to-server';
  } else if (route.source === SERVER_ENDPOINT && route.destination === CLIENT_ENDPOINT) {
    direction = 'server-to-client';
  }
  // Raw endpoints are reported as-is; the role mapping stays unknown when the
  // route does not match the simulated topology, instead of being forced into
  // a client/server label.
  const mapped =
    direction === 'unknown'
      ? { source: null as string | null, destination: null as string | null }
      : { source: route.source, destination: route.destination };
  return {
    direction,
    ...mapped,
    rawSource: route.source,
    rawDestination: route.destination
  };
}

/** Derive endpoint direction for a packet. One rule set for every consumer. */
export function deriveEndpoints(protocol: Protocol, raw: string): EndpointInfo {
  return protocol === 'HTTP' ? endpointsForHttp(raw) : endpointsForTcp(raw);
}
