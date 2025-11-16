// dns.js - DNS server: block all except whitelist
const dgram = require('dgram');
const packet = require('dns-packet');

const LISTEN_ADDR = '0.0.0.0';
const PORT = 53;

// IP to return for blocked domains
const BLOCKED_IP = '0.0.0.0';

// Whitelist: domains that resolve to allowed IP
const WHITELIST = {
  'example.com': '192.168.100.10',
  'youtube.com': '192.168.100.20'
};

// helpers
function makeResponseFromQuery(queryBuf, answers) {
  const req = packet.decode(queryBuf);
  const res = {
    id: req.id,
    type: 'response',
    flags: packet.RECURSION_DESIRED ? 0 : 0,
    questions: req.questions,
    answers: answers || []
  };
  return packet.encode(res);
}

// UDP server
const server = dgram.createSocket('udp4');

server.on('error', (err) => {
  console.error('Server error:', err);
  process.exit(1);
});

server.on('message', (msg, rinfo) => {
  let req;
  try {
    req = packet.decode(msg);
  } catch (e) {
    return;
  }

  if (!req.questions || !req.questions.length) return;

  const q = req.questions[0];
  const qname = (q.name || '').toLowerCase();
  const qtype = q.type || 'A';

  console.log(`Query: ${qname} (${qtype}) from ${rinfo.address}:${rinfo.port}`);

  // Determine IP: whitelist → allowed, else blocked
  const ip = WHITELIST[qname] || BLOCKED_IP;

  // Build response
  const answers = [{
    name: qname,
    type: 'A',
    ttl: 300,
    data: ip
  }];

  const responseBuf = makeResponseFromQuery(msg, answers);
  server.send(responseBuf, 0, responseBuf.length, rinfo.port, rinfo.address);
});

server.bind(PORT, LISTEN_ADDR, () => {
  console.log(`✅ DNS server listening on ${LISTEN_ADDR}:${PORT}`);
  console.log(` - All queries blocked → ${BLOCKED_IP}`);
  console.log(` - Whitelisted domains:`);
  for (const k in WHITELIST) {
    console.log(`   ${k} → ${WHITELIST[k]}`);
  }
});