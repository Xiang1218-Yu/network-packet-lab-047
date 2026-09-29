import express, { type Request, type Response } from 'express';
import type {
  EndpointDirection,
  HexRow,
  PacketScenario,
  ParseRequest,
  Protocol,
  ProtocolField,
  SimulatedPacket,
  TimelineEvent
} from '../shared/types.js';

const app = express();
const port = Number(process.env.PORT ?? 3001);

app.use(express.json({ limit: '1mb' }));
app.use((request, response, next) => {
  response.header('Access-Control-Allow-Origin', '*');
  response.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept');
  response.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (request.method === 'OPTIONS') return response.sendStatus(204);
  next();
});

const HTTP_SAMPLES: Record<PacketScenario, string> = {
  request: 'GET /api/devices?status=online HTTP/1.1\r\nHost: lab.local\r\nAccept: application/json\r\nUser-Agent: PacketLab/1.0\r\nX-Trace-Id: 7f3a9c\r\n\r\n',
  response: 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 47\r\nCache-Control: no-store\r\n\r\n{"devices":[{"id":"edge-01","status":"online"}]}',
  handshake: 'GET / HTTP/1.1\r\nHost: lab.local\r\nConnection: keep-alive\r\n\r\n'
};

const TCP_SAMPLES: Record<PacketScenario, string> = {
  request: 'TCP 10.0.0.24:51842 > 10.0.0.8:443 | Seq=18492031 Ack=77120102 | Flags=ACK,PSH | Win=64240 | Len=128',
  response: 'TCP 10.0.0.8:443 > 10.0.0.24:51842 | Seq=77120102 Ack=18492159 | Flags=ACK,PSH | Win=28960 | Len=512',
  handshake: 'TCP 10.0.0.24:51842 > 10.0.0.8:443 | Seq=0 Ack=0 | Flags=SYN | Win=64240 | MSS=1460 | WS=7'
};

const UNKNOWN_ENDPOINT = 'unknown';
const CLIENT_ENDPOINT = '10.0.0.24:51842';
const SERVER_ENDPOINT = '10.0.0.8:443';
const MAC_BY_IP = new Map([
  ['10.0.0.24', '02:42:ac:11:00:24'],
  ['10.0.0.8', '02:42:ac:11:00:08']
]);

type HttpMessageKind = 'request' | 'response' | 'unknown';

interface ResolvedEndpoints {
  source: string;
  destination: string;
  orientation: EndpointDirection;
  httpKind: HttpMessageKind | null;
}

function hexDump(value: string): HexRow[] {
  const bytes = Array.from(Buffer.from(value, 'utf8'));
  const rows: HexRow[] = [];
  for (let index = 0; index < bytes.length; index += 16) {
    const slice = bytes.slice(index, index + 16);
    rows.push({
      offset: index.toString(16).padStart(4, '0'),
      bytes: slice.map((byte) => byte.toString(16).padStart(2, '0')),
      ascii: slice.map((byte) => (byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')).join('')
    });
  }
  return rows;
}

function field(id: string, key: string, value: string, description: string, children?: ProtocolField[]): ProtocolField {
  return { id, key, value, description, ...(children ? { children } : {}) };
}

function parseHttpStartLine(raw: string): { startLine: string; kind: HttpMessageKind } {
  const startLine = raw.split(/\r?\n/)[0] ?? '';
  const isRequest = /^(GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) \S+ HTTP\/\d(?:\.\d)?$/.test(startLine);
  const isResponse = /^HTTP\/\d(?:\.\d)? [1-5]\d{2}(?: .*)?$/.test(startLine);
  return {
    startLine,
    kind: isResponse ? 'response' : isRequest ? 'request' : 'unknown'
  };
}

function parseTcpRoute(raw: string): { source: string; destination: string; protocol: string } {
  const route = raw.split(' | ')[0] ?? '';
  const match = /^([A-Za-z0-9]+) (\S+) > (\S+)$/.exec(route);
  const endpoint = (value: string | undefined): string => {
    if (!value) return UNKNOWN_ENDPOINT;
    const endpointMatch = /^((?:\d{1,3}\.){3}\d{1,3}):(\d+)$/.exec(value);
    if (!endpointMatch) return UNKNOWN_ENDPOINT;
    const octets = endpointMatch[1].split('.').map(Number);
    const port = Number(endpointMatch[2]);
    return octets.every((octet) => octet <= 255) && port <= 65535 ? value : UNKNOWN_ENDPOINT;
  };
  return {
    protocol: match?.[1] ?? UNKNOWN_ENDPOINT,
    source: endpoint(match?.[2]),
    destination: endpoint(match?.[3])
  };
}

function resolveEndpoints(protocol: Protocol, raw: string): ResolvedEndpoints {
  if (protocol === 'HTTP') {
    const { kind } = parseHttpStartLine(raw);
    if (kind === 'request') {
      return { source: CLIENT_ENDPOINT, destination: SERVER_ENDPOINT, orientation: 'client-to-server', httpKind: kind };
    }
    if (kind === 'response') {
      return { source: SERVER_ENDPOINT, destination: CLIENT_ENDPOINT, orientation: 'server-to-client', httpKind: kind };
    }
    return { source: UNKNOWN_ENDPOINT, destination: UNKNOWN_ENDPOINT, orientation: 'unknown', httpKind: kind };
  }

  const route = parseTcpRoute(raw);
  const knownDirection = route.protocol === 'TCP' && route.source === CLIENT_ENDPOINT && route.destination === SERVER_ENDPOINT
    ? 'client-to-server'
    : route.protocol === 'TCP' && route.source === SERVER_ENDPOINT && route.destination === CLIENT_ENDPOINT
      ? 'server-to-client'
      : 'unknown';
  return { source: route.source, destination: route.destination, orientation: knownDirection, httpKind: null };
}

function orientationLabel(orientation: EndpointDirection): string {
  if (orientation === 'client-to-server') return 'client → server';
  if (orientation === 'server-to-client') return 'server → client';
  return 'unknown';
}

function endpointMac(endpoint: string): string {
  const ip = endpoint.split(':')[0];
  return (ip && MAC_BY_IP.get(ip)) ?? UNKNOWN_ENDPOINT;
}

function parseHttpFields(raw: string, endpoints: ResolvedEndpoints): ProtocolField[] {
  const [head, body = ''] = raw.split(/\r?\n\r?\n/);
  const lines = head.split(/\r?\n/);
  const { startLine, kind } = parseHttpStartLine(raw);
  lines.shift();
  const headers = lines.map((line, index) => {
    const separator = line.indexOf(':');
    const key = separator > -1 ? line.slice(0, separator).trim() : `Header-${index + 1}`;
    const value = separator > -1 ? line.slice(separator + 1).trim() : line.trim();
    return field(`header-${index}`, key, value || '(empty)', `HTTP header carried by the ${kind === 'response' ? 'response' : kind === 'request' ? 'request' : 'HTTP message'}`);
  });
  const [first, second, third] = startLine.split(' ');
  const isResponse = kind === 'response';
  const startLineDescription = kind === 'response'
    ? 'Status line identifies a response: server → client'
    : kind === 'request'
      ? 'Request line identifies a request: client → server'
      : 'Start line does not identify a valid request or response direction';
  return [
    field('http-start-line', isResponse ? 'Status-Line' : kind === 'request' ? 'Request-Line' : 'Start-Line', startLine || UNKNOWN_ENDPOINT, startLineDescription, [
      field('http-direction', 'Direction', orientationLabel(endpoints.orientation), 'Direction derived from the HTTP start line and simulated topology'),
      field('http-part-1', isResponse ? 'Version' : kind === 'request' ? 'Method' : 'Token', first ?? '—', isResponse ? 'Protocol version' : kind === 'request' ? 'HTTP request method' : 'Unknown start-line token'),
      field('http-part-2', isResponse ? 'Status' : kind === 'request' ? 'Target' : 'Token', second ?? '—', isResponse ? 'Status code' : kind === 'request' ? 'Request target' : 'Unknown start-line token'),
      field('http-part-3', isResponse ? 'Reason' : kind === 'request' ? 'Version' : 'Token', third ?? '—', isResponse ? 'Reason phrase' : kind === 'request' ? 'Protocol version' : 'Unknown start-line token')
    ]),
    field('http-headers', 'Headers', `${headers.length} fields`, kind === 'response' ? 'Metadata carried by the server response' : kind === 'request' ? 'Metadata carried by the client request' : 'HTTP header fields; message direction is unknown', headers),
    field('http-body', 'Payload', body || '(empty)', kind === 'response' ? 'Payload returned from server to client' : kind === 'request' ? 'Payload sent from client to server' : 'Application payload with unknown direction')
  ];
}

function parseTcpFields(raw: string, endpoints: ResolvedEndpoints): ProtocolField[] {
  const [route = '', ...parts] = raw.split(' | ');
  const [protocol = UNKNOWN_ENDPOINT] = route.split(' ');
  const values = new Map(parts.map((part) => {
    const separator = part.indexOf('=');
    return separator > -1 ? [part.slice(0, separator), part.slice(separator + 1)] : [part, 'true'];
  }));
  const sourceMac = endpointMac(endpoints.source);
  const destinationMac = endpointMac(endpoints.destination);
  const sourceRole = endpoints.orientation === 'client-to-server' ? 'Client sender' : endpoints.orientation === 'server-to-client' ? 'Server sender' : 'Raw packet sender';
  const destinationRole = endpoints.orientation === 'client-to-server' ? 'Server recipient' : endpoints.orientation === 'server-to-client' ? 'Client recipient' : 'Raw packet recipient';
  return [
    field('ethernet', 'Link Layer', 'Ethernet II', 'Frame envelope', [
      field('ethernet-src', 'Source MAC', sourceMac, `${sourceRole} link-layer address; derived from the raw route`),
      field('ethernet-dst', 'Destination MAC', destinationMac, `${destinationRole} link-layer address; derived from the raw route`),
      field('ethernet-type', 'Type', '0x0800 · IPv4', 'Network protocol identifier')
    ]),
    field('ipv4', 'Internet Layer', 'IPv4', 'Logical addressing and delivery', [
      field('ipv4-direction', 'Direction', orientationLabel(endpoints.orientation), 'Direction derived solely from the raw TCP route'),
      field('ipv4-source', 'Source', endpoints.source, `${sourceRole} IP and port from the raw TCP route`),
      field('ipv4-destination', 'Destination', endpoints.destination, `${destinationRole} IP and port from the raw TCP route`),
      field('ipv4-protocol', 'Next Protocol', protocol === 'TCP' ? 'TCP' : UNKNOWN_ENDPOINT, 'Transport protocol parsed from the raw route')
    ]),
    field('tcp', 'Transport Layer', 'TCP', 'Reliable stream transport', [
      field('tcp-seq', 'Sequence', values.get('Seq') ?? '—', 'Byte sequence position'),
      field('tcp-ack', 'Acknowledgement', values.get('Ack') ?? '—', 'Next expected byte'),
      field('tcp-flags', 'Flags', values.get('Flags') ?? '—', 'Control bits'),
      field('tcp-window', 'Window', values.get('Win') ?? '—', 'Receive window size'),
      field('tcp-length', 'Payload Length', values.get('Len') ?? '0', 'TCP segment data length')
    ]),
    field('tcp-payload', 'Payload', values.get('Len') === '0' ? '(empty)' : 'Encrypted application data', `Data carried ${orientationLabel(endpoints.orientation)}`)
  ];
}

function timelineFor(protocol: Protocol, endpoints: ResolvedEndpoints): TimelineEvent[] {
  const prefix = protocol === 'HTTP' ? 'HTTP' : 'TCP';
  const direction = orientationLabel(endpoints.orientation);
  const endpointPath = endpoints.orientation === 'unknown'
    ? 'direction unknown'
    : `${endpoints.source} → ${endpoints.destination}`;
  const steps = protocol === 'HTTP'
    ? [
        ['ingress', 'Frame captured', endpoints.orientation === 'unknown'
          ? 'No valid HTTP request line or status line was found; endpoint direction is unknown'
          : `Application frame captured: ${direction} (${endpointPath})`],
        ['parse', 'Headers indexed', endpoints.httpKind === 'response'
          ? 'Status line identifies a server response; headers are indexed in server → client direction'
          : endpoints.httpKind === 'request'
            ? 'Request line identifies a client request; headers are indexed in client → server direction'
            : 'Start line cannot establish a request or response direction'],
        ['application', `${prefix} payload decoded`, endpoints.httpKind === 'response'
          ? 'Response body decoded for delivery from server to client'
          : endpoints.httpKind === 'request'
            ? 'Request target and metadata decoded for delivery from client to server'
            : 'HTTP payload direction remains unknown'],
        ['egress', 'Inspector ready', `Structured representation emitted using ${direction} endpoint direction`]
      ]
    : [
        ['ingress', 'Segment captured', endpoints.orientation === 'unknown'
          ? 'Raw route does not identify a source and destination; endpoint direction is unknown'
          : `Transport segment captured from raw route: ${endpointPath}`],
        ['transport', 'TCP header decoded', endpoints.orientation === 'unknown'
          ? 'Sequence, acknowledgement and flags extracted; raw endpoint direction remains unknown'
          : `Sequence, acknowledgement and flags decoded for ${direction}`],
        ['parse', 'Layer tree assembled', endpoints.orientation === 'unknown'
          ? 'Ethernet → IPv4 → TCP hierarchy created without inferring missing endpoints'
          : `Ethernet → IPv4 → TCP hierarchy assembled for ${endpoints.source} → ${endpoints.destination}`],
        ['egress', 'Inspector ready', `Structured representation emitted using raw-route direction ${direction}`]
      ];
  return steps.map(([phase, label, detail], index) => ({
    id: `${prefix.toLowerCase()}-${index}`,
    timestamp: `00:00:0${index}.${(index * 37 + 12).toString().padStart(2, '0')}`,
    label,
    phase: phase as TimelineEvent['phase'],
    detail
  }));
}

function checksum(raw: string): string {
  let hash = 0;
  for (const byte of Buffer.from(raw, 'utf8')) hash = (hash + byte * 31) % 65535;
  return `0x${hash.toString(16).padStart(4, '0').toUpperCase()}`;
}

function buildPacket(protocol: Protocol, scenario: PacketScenario, raw: string): SimulatedPacket {
  const safeRaw = raw.trim() ? raw : (protocol === 'HTTP' ? HTTP_SAMPLES[scenario] : TCP_SAMPLES[scenario]);
  const isHttp = protocol === 'HTTP';
  const endpoints = resolveEndpoints(protocol, safeRaw);
  const startLine = safeRaw.split(/\r?\n/)[0] ?? '';
  const messageLabel = endpoints.httpKind === 'response'
    ? 'server response'
    : endpoints.httpKind === 'request'
      ? 'client request'
      : 'unknown HTTP message';
  return {
    id: `${protocol.toLowerCase()}-${scenario}-${Date.now().toString(36).slice(-6)}`,
    protocol,
    scenario,
    summary: isHttp
      ? `${startLine || UNKNOWN_ENDPOINT} · ${messageLabel} · ${orientationLabel(endpoints.orientation)}`
      : `${scenario === 'handshake' ? 'TCP connection handshake' : 'TCP data segment'} · ${safeRaw.split(' | ')[0] || UNKNOWN_ENDPOINT} · ${orientationLabel(endpoints.orientation)}`,
    raw: safeRaw,
    hex: hexDump(safeRaw),
    fields: isHttp ? parseHttpFields(safeRaw, endpoints) : parseTcpFields(safeRaw, endpoints),
    timeline: timelineFor(protocol, endpoints),
    metadata: {
      capturedAt: new Date().toISOString().replace('T', ' ').replace('Z', ' UTC'),
      direction: endpoints.orientation,
      source: endpoints.source,
      destination: endpoints.destination,
      length: Buffer.byteLength(safeRaw, 'utf8'),
      checksum: checksum(safeRaw)
    }
  };
}

function isProtocol(value: unknown): value is Protocol { return value === 'HTTP' || value === 'TCP'; }
function isScenario(value: unknown): value is PacketScenario { return value === 'request' || value === 'response' || value === 'handshake'; }

app.get('/api/health', (_request, response) => response.json({ ok: true, service: 'network-packet-lab-api' }));

app.get('/api/simulate', (request, response) => {
  const protocol = isProtocol(request.query.protocol) ? request.query.protocol : 'HTTP';
  const scenario = isScenario(request.query.scenario) ? request.query.scenario : (protocol === 'HTTP' ? 'request' : 'handshake');
  response.json({ data: buildPacket(protocol, scenario, '') });
});

app.get('/api/packets', (request, response) => {
  const protocol = isProtocol(request.query.protocol) ? request.query.protocol : 'HTTP';
  const scenarios: PacketScenario[] = protocol === 'HTTP' ? ['request', 'response'] : ['handshake', 'request', 'response'];
  response.json({ data: scenarios.map((scenario) => buildPacket(protocol, scenario, '')) });
});

app.post('/api/parse', (request: Request<unknown, unknown, Partial<ParseRequest>>, response: Response) => {
  const protocol = isProtocol(request.body?.protocol) ? request.body.protocol : 'HTTP';
  const scenario = isScenario(request.body?.scenario) ? request.body.scenario : 'request';
  const raw = typeof request.body?.raw === 'string' ? request.body.raw : '';
  if (!raw.trim()) return response.status(400).json({ error: 'raw is required' });
  response.json({ data: buildPacket(protocol, scenario, raw) });
});

app.listen(port, () => {
  console.log(`Network Packet Lab API listening on http://localhost:${port}`);
});
