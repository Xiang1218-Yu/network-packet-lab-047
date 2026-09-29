export type Protocol = 'HTTP' | 'TCP';
export type PacketScenario = 'request' | 'response' | 'handshake';

/**
 * Endpoint flow direction, derived from the packet content itself.
 * - client-to-server: request traffic (client is source, server is destination)
 * - server-to-client: response traffic (server is source, client is destination)
 * - unknown: direction cannot be inferred from the available data
 */
export type EndpointDirection = 'client-to-server' | 'server-to-client' | 'unknown';

export interface HexRow {
  offset: string;
  bytes: string[];
  ascii: string;
}

export interface ProtocolField {
  id: string;
  key: string;
  value: string;
  description: string;
  children?: ProtocolField[];
}

export interface TimelineEvent {
  id: string;
  timestamp: string;
  label: string;
  phase: 'ingress' | 'parse' | 'transport' | 'application' | 'egress';
  detail: string;
}

export interface SimulatedPacket {
  id: string;
  protocol: Protocol;
  scenario: PacketScenario;
  summary: string;
  raw: string;
  hex: HexRow[];
  fields: ProtocolField[];
  timeline: TimelineEvent[];
  metadata: {
    capturedAt: string;
    /** Direction shared by the summary card, field tree, timeline and this metadata. */
    direction: EndpointDirection;
    /** Sender endpoint, or null when it cannot be derived from the packet. */
    source: string | null;
    /** Receiver endpoint, or null when it cannot be derived from the packet. */
    destination: string | null;
    length: number;
    checksum: string;
  };
}

export interface ParseRequest {
  protocol: Protocol;
  scenario: PacketScenario;
  raw: string;
}
