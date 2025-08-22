const express = require('express');
const https = require('https');
const fs = require('fs');
const dgram = require('dgram');
const tls = require('tls');
const net = require('net');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;
const DNS_PORT = 53;
const DOT_PORT = 853; // DNS-over-TLS port

app.use(bodyParser.json());
app.use(express.static('public'));

// Load blocklist and allowed devices
let blocklist = new Set(
  fs.readFileSync('blocklist.txt', 'utf8')
    .split('\n')
    .filter(domain => domain && !domain.startsWith('#'))
);

let allowedDevices = [];
try {
  allowedDevices = JSON.parse(fs.readFileSync('allowed-devices.json', 'utf8'));
} catch (e) {
  allowedDevices = [];
}

// Save allowed devices to file
function saveAllowedDevices() {
  fs.writeFileSync('allowed-devices.json', JSON.stringify(allowedDevices, null, 2));
}

// Custom DNS-over-HTTPS resolver
async function resolveWithDoh(domain) {
  try {
    const response = await fetch('https://cloudflare-dns.com/dns-query?name=' + domain + '&type=A', {
      headers: {
        'Accept': 'application/dns-json'
      }
    });
    
    const data = await response.json();
    return data.Answer ? data.Answer.map(a => a.data) : [];
  } catch (error) {
    console.error('DoH resolution error:', error);
    return [];
  }
}

// DNS server implementation (UDP)
const udpServer = dgram.createSocket('udp4');

udpServer.on('message', async (msg, rinfo) => {
  try {
    // Simple DNS message parsing
    const query = msg.toString('utf8', 12);
    let domain = '';
    let pos = 0;
    
    while (pos < query.length && query.charCodeAt(pos) !== 0) {
      const length = query.charCodeAt(pos);
      if (length === 0) break;
      
      if (domain.length > 0) domain += '.';
      domain += query.substring(pos + 1, pos + 1 + length);
      pos += length + 1;
    }
    
    // Check if domain is in blocklist
    if (blocklist.has(domain)) {
      // Create response with null IP (0.0.0.0)
      const response = Buffer.alloc(32);
      msg.copy(response, 0, 0, 2);
      response[2] = 0x81;
      response[3] = 0x80;
      response[4] = 0x00;
      response[5] = 0x01;
      response[6] = 0x00;
      response[7] = 0x01;
      
      msg.copy(response, 12, 12, msg.length);
      
      const answerOffset = 12 + (msg.length - 12);
      response[answerOffset] = 0xc0;
      response[answerOffset + 1] = 0x0c;
      response[answerOffset + 2] = 0x00;
      response[answerOffset + 3] = 0x01;
      response[answerOffset + 4] = 0x00;
      response[answerOffset + 5] = 0x01;
      response[answerOffset + 6] = 0x00;
      response[answerOffset + 7] = 0x00;
      response[answerOffset + 8] = 0x00;
      response[answerOffset + 9] = 0x3c;
      response[answerOffset + 10] = 0x00;
      response[answerOffset + 11] = 0x04;
      response[answerOffset + 12] = 0x00;
      response[answerOffset + 13] = 0x00;
      response[answerOffset + 14] = 0x00;
      response[answerOffset + 15] = 0x00;
      
      udpServer.send(response, 0, answerOffset + 16, rinfo.port, rinfo.address);
      return;
    }
    
    // Forward query to DoH resolver
    const addresses = await resolveWithDoh(domain);
    
    if (addresses.length > 0) {
      // Create response with resolved IPs
      const response = Buffer.alloc(1024);
      msg.copy(response, 0, 0, 2);
      response[2] = 0x81;
      response[3] = 0x80;
      response[4] = 0x00;
      response[5] = 0x01;
      response[6] = 0x00;
      response[7] = 0x01;
      
      msg.copy(response, 12, 12, msg.length);
      
      const answerOffset = 12 + (msg.length - 12);
      response[answerOffset] = 0xc0;
      response[answerOffset + 1] = 0x0c;
      response[answerOffset + 2] = 0x00;
      response[answerOffset + 3] = 0x01;
      response[answerOffset + 4] = 0x00;
      response[answerOffset + 5] = 0x01;
      response[answerOffset + 6] = 0x00;
      response[answerOffset + 7] = 0x00;
      response[answerOffset + 8] = 0x00;
      response[answerOffset + 9] = 0x3c;
      response[answerOffset + 10] = 0x00;
      response[answerOffset + 11] = 0x04;
      
      const ipParts = addresses[0].split('.');
      response[answerOffset + 12] = parseInt(ipParts[0]);
      response[answerOffset + 13] = parseInt(ipParts[1]);
      response[answerOffset + 14] = parseInt(ipParts[2]);
      response[answerOffset + 15] = parseInt(ipParts[3]);
      
      udpServer.send(response, 0, answerOffset + 16, rinfo.port, rinfo.address);
    } else {
      udpServer.send(msg, rinfo.port, rinfo.address);
    }
  } catch (error) {
    console.error('DNS processing error:', error);
    udpServer.send(msg, rinfo.port, rinfo.address);
  }
});

udpServer.on('listening', () => {
  const address = udpServer.address();
  console.log(`DNS server listening on ${address.address}:${address.port}`);
});

udpServer.bind(DNS_PORT);

// DNS-over-TLS (DoT) Server
const tlsOptions = {
  key: fs.readFileSync('ssl/key.pem'),
  cert: fs.readFileSync('ssl/cert.pem'),
  // Require client certificate authentication if needed
  requestCert: false,
  rejectUnauthorized: false
};

const dotServer = tls.createServer(tlsOptions, (socket) => {
  console.log('DoT client connected');
  
  socket.on('data', async (data) => {
    try {
      // Simple DNS message parsing for DoT
      // This is a simplified implementation - real DoT would need proper DNS message parsing
      const domain = extractDomainFromDnsMessage(data);
      
      if (domain && blocklist.has(domain)) {
        // Create blocked response
        const response = createDnsResponse(data, '0.0.0.0');
        socket.write(response);
        return;
      }
      
      // Forward to DoH resolver
      if (domain) {
        const addresses = await resolveWithDoh(domain);
        if (addresses.length > 0) {
          const response = createDnsResponse(data, addresses[0]);
          socket.write(response);
        } else {
          socket.write(data); // Echo back if no resolution
        }
      } else {
        socket.write(data); // Echo back if not a DNS query we understand
      }
    } catch (error) {
      console.error('DoT processing error:', error);
      socket.write(data); // Echo back on error
    }
  });
  
  socket.on('end', () => {
    console.log('DoT client disconnected');
  });
  
  socket.on('error', (err) => {
    console.error('DoT socket error:', err);
  });
});

dotServer.listen(DOT_PORT, () => {
  console.log(`DNS-over-TLS server listening on port ${DOT_PORT}`);
});

// Helper function to extract domain from DNS message (simplified)
function extractDomainFromDnsMessage(data) {
  try {
    // Skip DNS header (12 bytes) and try to extract domain
    if (data.length < 12) return null;
    
    let domain = '';
    let pos = 12; // Start after header
    
    while (pos < data.length && data[pos] !== 0) {
      const length = data[pos];
      if (length === 0) break;
      
      if (domain.length > 0) domain += '.';
      domain += data.toString('utf8', pos + 1, pos + 1 + length);
      pos += length + 1;
    }
    
    return domain;
  } catch (e) {
    return null;
  }
}

// Helper function to create DNS response
function createDnsResponse(query, ip) {
  // This is a simplified DNS response creation
  // In a real implementation, you'd properly parse the query and create a response
  const response = Buffer.alloc(1024);
  query.copy(response, 0, 0, 2); // Copy transaction ID
  response[2] = 0x81; // Response flags
  response[3] = 0x80;
  response[4] = 0x00; // Questions
  response[5] = 0x01;
  response[6] = 0x00; // Answer RRs
  response[7] = 0x01;
  
  // Copy question section
  const questionLength = query.length - 12;
  query.copy(response, 12, 12, query.length);
  
  // Add answer section
  const answerOffset = 12 + questionLength;
  response[answerOffset] = 0xc0;
  response[answerOffset + 1] = 0x0c;
  response[answerOffset + 2] = 0x00; // Type A
  response[answerOffset + 3] = 0x01;
  response[answerOffset + 4] = 0x00; // Class IN
  response[answerOffset + 5] = 0x01;
  response[answerOffset + 6] = 0x00; // TTL
  response[answerOffset + 7] = 0x00;
  response[answerOffset + 8] = 0x00;
  response[answerOffset + 9] = 0x3c;
  response[answerOffset + 10] = 0x00; // Data length
  response[answerOffset + 11] = 0x04;
  
  const ipParts = ip.split('.');
  response[answerOffset + 12] = parseInt(ipParts[0]);
  response[answerOffset + 13] = parseInt(ipParts[1]);
  response[answerOffset + 14] = parseInt(ipParts[2]);
  response[answerOffset + 15] = parseInt(ipParts[3]);
  
  return response.slice(0, answerOffset + 16);
}

// Admin API endpoints
app.get('/api/devices', (req, res) => {
  res.json(allowedDevices);
});

app.post('/api/devices', (req, res) => {
  const { name, ip } = req.body;
  if (!name || !ip) {
    return res.status(400).json({ error: 'Name and IP are required' });
  }
  
  allowedDevices.push({ name, ip, added: new Date().toISOString() });
  saveAllowedDevices();
  res.json({ success: true });
});

app.delete('/api/devices/:ip', (req, res) => {
  const ip = req.params.ip;
  allowedDevices = allowedDevices.filter(device => device.ip !== ip);
  saveAllowedDevices();
  res.json({ success: true });
});

app.get('/api/blocklist', (req, res) => {
  res.json(Array.from(blocklist));
});

app.post('/api/blocklist', (req, res) => {
  const { domain } = req.body;
  if (!domain) {
    return res.status(400).json({ error: 'Domain is required' });
  }
  
  blocklist.add(domain);
  fs.writeFileSync('blocklist.txt', Array.from(blocklist).join('\n'));
  res.json({ success: true });
});

// Load SSL certificates for admin interface
const httpsOptions = {
  key: fs.readFileSync('ssl/key.pem'),
  cert: fs.readFileSync('ssl/cert.pem')
};

// Start HTTPS server
https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`Admin server listening on https://localhost:${PORT}`);
});

// DNS-over-HTTPS endpoint
app.get('/dns-query', async (req, res) => {
  const name = req.query.name;
  const type = req.query.type || 'A';
  
  if (!name) {
    return res.status(400).json({ error: 'Name parameter required' });
  }
  
  try {
    // Check if domain is blocked
    if (blocklist.has(name)) {
      return res.json({
        Status: 0,
        Answer: [{
          name: name,
          type: 1, // A record
          TTL: 300,
          data: '0.0.0.0'
        }]
      });
    }
    
    // Forward to upstream DoH resolver
    const response = await fetch(`https://cloudflare-dns.com/dns-query?name=${name}&type=${type}`, {
      headers: {
        'Accept': 'application/dns-json'
      }
    });
    
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('DoH proxy error:', error);
    res.status(500).json({ error: 'DNS query failed' });
  }
});