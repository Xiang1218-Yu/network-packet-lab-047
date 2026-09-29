import express, { type Request, type Response } from 'express';
import {
  classifyHttpMessage,
  deriveEndpoints,
  parseTcpRoute,
  type EndpointInfo
} from '../shared/endpoints.js';
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

function parseHttpFields(raw: string, endpoints: EndpointInfo): ProtocolField[] {
  const [head, body = ''] = raw.split(/\r?\n\r?\n/);
  const lines = head.split(/\r?\n/);
  const startLine = lines.shift() ?? '';
  const headers = lines.map((line, index) => {
    const separator = line.indexOf(':');
    const key = separator > -1 ? line.slice(0, separator).trim() : `Header-${index + 1}`;
    const value = separator > -1 ? line.slice(separator + 1).trim() : line.trim();
    return field(`header-${index}`, key, value || '(empty)', 'HTTP header field');
  });
  const messageKind = classifyHttpMessage(raw);
  const isResponse = messageKind === 'response';
  const [first, second, third] = startLine.split(' ');
  return [
    field('http-start-line', isResponse ? 'Status-Line' : 'Request-Line', startLine || '—', isResponse ? 'HTTP version and response status (server → client)' : messageKind === 'request' ? 'HTTP method, target and version (client → server)' : 'Unrecognized HTTP start line; direction unknown', [
      field('http-part-1', isResponse ? 'Version' : 'Method', first ?? '—', isResponse ? 'Protocol version' : 'HTTP request method'),
      field('http-part-2', isResponse ? 'Status' : 'Target', second ?? '—', isResponse ? 'Status code' : 'Request target'),
      field('http-part-3', isResponse ? 'Reason' : 'Version', third ?? '—', isResponse ? 'Reason phrase' : 'Protocol version')
    ]),
    field('http-endpoints', 'Endpoints', formatDirection(endpoints.direction), 'Direction derived from the start line', [
      field('http-source', 'Source', endpoints.source ?? '—', endpoints.source ? endpointRole(endpoints, 'source') : 'Sender cannot be derived from this packet'),
      field('http-destination', 'Destination', endpoints.destination ?? '—', endpoints.destination ? endpointRole(endpoints, 'destination') : 'Receiver cannot be derived from this packet')
    ]),
    field('http-headers', 'Headers', `${headers.length} fields`, 'Metadata carried by the application layer', headers),
    field('http-body', 'Payload', body || '(empty)', 'Application payload after the header terminator')
  ];
}

function parseTcpFields(raw: string, endpoints: EndpointInfo): ProtocolField[] {
  const values = new Map(raw.split(' | ').slice(1).map((part) => {
    const separator = part.indexOf('=');
    return separator > -1 ? [part.slice(0, separator), part.slice(separator + 1)] : [part, 'true'];
  }));
  return [
    field('ethernet', 'Link Layer', 'Ethernet II', 'Frame envelope', [
      field('ethernet-src', 'Source MAC', '02:42:ac:11:00:24', 'Simulated interface address'),
      field('ethernet-dst', 'Destination MAC', '02:42:ac:11:00:08', 'Simulated gateway address'),
      field('ethernet-type', 'Type', '0x0800 · IPv4', 'Network protocol identifier')
    ]),
    field('ipv4', 'Internet Layer', 'IPv4', 'Logical addressing and delivery', [
      field('ipv4-source', 'Source', endpoints.rawSource ?? '—', endpoints.source ? `Origin IP and port (${endpointRole(endpoints, 'source')})` : endpoints.rawSource ? 'Raw route present but role unknown in simulated topology' : 'Cannot be derived: raw TCP route unparseable'),
      field('ipv4-destination', 'Destination', endpoints.rawDestination ?? '—', endpoints.destination ? `Target IP and port (${endpointRole(endpoints, 'destination')})` : endpoints.rawDestination ? 'Raw route present but role unknown in simulated topology' : 'Cannot be derived: raw TCP route unparseable'),
      field('ipv4-protocol', 'Next Protocol', 'TCP', 'Transport protocol')
    ]),
    field('tcp', 'Transport Layer', 'TCP', 'Reliable stream transport', [
      field('tcp-direction', 'Direction', formatDirection(endpoints.direction), 'Derived solely from the raw TCP route'),
      field('tcp-seq', 'Sequence', values.get('Seq') ?? '—', 'Byte sequence position'),
      field('tcp-ack', 'Acknowledgement', values.get('Ack') ?? '—', 'Next expected byte'),
      field('tcp-flags', 'Flags', values.get('Flags') ?? '—', 'Control bits'),
      field('tcp-window', 'Window', values.get('Win') ?? '—', 'Receive window size'),
      field('tcp-length', 'Payload Length', values.get('Len') ?? '0', 'TCP segment data length')
    ]),
    field('tcp-payload', 'Payload', values.get('Len') === '0' ? '(empty)' : 'Encrypted application data', 'Data carried by the segment')
  ];
}

function formatDirection(direction: EndpointDirection): string {
  if (direction === 'client-to-server') return 'client → server';
  if (direction === 'server-to-client') return 'server → client';
  return 'unknown';
}

function endpointRole(endpoints: EndpointInfo, side: 'source' | 'destination'): string {
  if (endpoints.direction === 'unknown') return 'role unknown';
  const isClient =
    (side === 'source' && endpoints.direction === 'client-to-server') ||
    (side === 'destination' && endpoints.direction === 'server-to-client');
  return isClient ? 'simulated client' : 'simulated server';
}

function timelineFor(protocol: Protocol, endpoints: EndpointInfo): TimelineEvent[] {
  const prefix = protocol === 'HTTP' ? 'HTTP' : 'TCP';
  const flow = formatDirection(endpoints.direction);
  const steps = protocol === 'HTTP'
    ? [
        ['ingress', 'Frame captured', endpoints.direction === 'unknown'
          ? 'NIC received an application frame; endpoint direction unknown'
          : `NIC received an application frame (${flow})`],
        ['parse', 'Headers indexed', endpoints.direction === 'unknown'
          ? 'Start line unrecognized; request/response role could not be determined'
          : `Start line and header fields identified (${flow})`],
        ['application', `${prefix} payload decoded`, endpoints.direction === 'server-to-client'
          ? 'Response body is ready for inspection'
          : endpoints.direction === 'client-to-server'
            ? 'Request target and metadata extracted'
            : 'Payload decoded, but message direction is unknown'],
        ['egress', 'Inspector ready', 'Structured representation emitted by parse API']
      ]
    : [
        ['ingress', 'Segment captured', endpoints.direction === 'unknown'
          ? 'Transport segment received from the simulated wire; endpoints not derivable from raw route'
          : `Transport segment received from the simulated wire (${flow})`],
        ['transport', 'TCP header decoded', 'Sequence, acknowledgement and flags extracted'],
        ['parse', 'Layer tree assembled', 'Ethernet → IPv4 → TCP hierarchy created'],
        ['egress', 'Inspector ready', 'Structured representation emitted by parse API']
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
  const endpoints = deriveEndpoints(protocol, safeRaw);
  const httpRole = isHttp ? classifyHttpMessage(safeRaw) : null;
  const httpRoleLabel = httpRole === 'response'
    ? 'server response'
    : httpRole === 'request'
      ? 'client request'
      : 'unknown HTTP message';
  return {
    id: `${protocol.toLowerCase()}-${scenario}-${Date.now().toString(36).slice(-6)}`,
    protocol,
    scenario,
    summary: isHttp
      ? `${safeRaw.split(/\r?\n/)[0]} · ${httpRoleLabel}`
      : `${scenario === 'handshake' ? 'TCP connection handshake' : 'TCP data segment'} · ${parseTcpRoute(safeRaw) ? `${endpoints.rawSource} > ${endpoints.rawDestination}` : 'route unknown'}`,
    raw: safeRaw,
    hex: hexDump(safeRaw),
    fields: isHttp ? parseHttpFields(safeRaw, endpoints) : parseTcpFields(safeRaw, endpoints),
    timeline: timelineFor(protocol, endpoints),
    metadata: {
      capturedAt: new Date().toISOString().replace('T', ' ').replace('Z', ' UTC'),
      direction: endpoints.direction,
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
