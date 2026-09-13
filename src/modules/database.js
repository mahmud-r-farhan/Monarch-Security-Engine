import net from 'node:net';

/**
 * Database protocol handshakes and connection probes.
 */
export async function testDbConnection({
  type = 'postgres',
  host = 'localhost',
  port = null,
  database = 'postgres',
  username = '',
  password = '',
  timeoutMs = 4000,
}) {
  const targetPort = Number(port) || getDefaultPort(type);
  const started = Date.now();

  return new Promise(resolve => {
    const socket = new net.Socket();
    let bannerData = Buffer.alloc(0);
    let resolved = false;

    socket.setTimeout(timeoutMs);

    const finish = (result) => {
      if (resolved) return;
      resolved = true;
      socket.destroy();
      resolve({
        type,
        host,
        port: targetPort,
        latencyMs: Date.now() - started,
        ...result,
      });
    };

    socket.on('connect', () => {
      // Protocol-specific probe
      if (type === 'mysql') {
        // MySQL server greets the client first with Initial Handshake Packet
      } else if (type === 'redis') {
        socket.write('*1\r\n$4\r\nPING\r\n');
      } else if (type === 'postgres') {
        // Send SSLRequest: length (8), code 80877103
        const sslReq = Buffer.from([0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f]);
        socket.write(sslReq);
      } else if (type === 'mongodb') {
        // OP_MSG or connect check
        socket.write(Buffer.from([0x3a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd4, 0x07, 0x00, 0x00]));
      } else {
        socket.write('\r\n');
      }
    });

    socket.on('data', data => {
      bannerData = Buffer.concat([bannerData, data]);

      if (type === 'mysql') {
        // Parse MySQL Handshake: protocol version at byte 4, server version null-terminated string
        if (bannerData.length > 5) {
          const proto = bannerData[4];
          const nullIdx = bannerData.indexOf(0, 5);
          const serverVersion = nullIdx > 5 ? bannerData.toString('ascii', 5, nullIdx) : 'Unknown';
          finish({
            connected: true,
            status: 'Online',
            serverVersion: `MySQL (protocol ${proto}) - ${serverVersion}`,
            details: 'Received MySQL initial handshake packet successfully.',
          });
        }
      } else if (type === 'redis') {
        const text = bannerData.toString('utf8');
        if (text.includes('PONG') || text.includes('NOAUTH') || text.includes('ERR')) {
          finish({
            connected: true,
            status: 'Online',
            serverVersion: 'Redis Server',
            authRequired: text.includes('NOAUTH'),
            details: text.trim(),
          });
        }
      } else if (type === 'postgres') {
        // Postgres responds 'S' (SSL supported) or 'N' (SSL not supported)
        const responseChar = String.fromCharCode(bannerData[0]);
        const sslSupported = responseChar === 'S';
        finish({
          connected: true,
          status: 'Online',
          serverVersion: 'PostgreSQL Server',
          sslSupported,
          details: `PostgreSQL server acknowledged connection (SSL response: '${responseChar}').`,
        });
      } else if (type === 'mongodb') {
        finish({
          connected: true,
          status: 'Online',
          serverVersion: 'MongoDB Server',
          details: 'MongoDB wire protocol listener responded to handshake.',
        });
      } else {
        finish({
          connected: true,
          status: 'Online',
          serverVersion: 'Generic Database / Socket',
          details: `Connected to ${host}:${targetPort}`,
        });
      }
    });

    socket.on('timeout', () => {
      finish({
        connected: false,
        status: 'Timeout',
        error: `Connection timed out after ${timeoutMs}ms`,
      });
    });

    socket.on('error', err => {
      finish({
        connected: false,
        status: 'Offline / Refused',
        error: err.message || err.code,
      });
    });

    try {
      socket.connect(targetPort, host);
    } catch (err) {
      finish({
        connected: false,
        status: 'Error',
        error: err.message,
      });
    }

    // Fallback if connected but no data returned within 1000ms
    setTimeout(() => {
      if (!resolved && socket.writable) {
        finish({
          connected: true,
          status: 'Online (Port Open)',
          serverVersion: `${type.toUpperCase()} (Port ${targetPort} listening)`,
          details: 'Port is open and accepting TCP connections.',
        });
      }
    }, 1000);
  });
}

function getDefaultPort(type) {
  switch (type?.toLowerCase()) {
    case 'postgres':
    case 'postgresql':
      return 5432;
    case 'mysql':
      return 3306;
    case 'mongodb':
      return 27017;
    case 'redis':
      return 6379;
    case 'mssql':
      return 1433;
    default:
      return 5432;
  }
}

/**
 * Runs a concurrent connection load test on a database target.
 */
export async function runDbLoadTest({ type, host, port, concurrency = 10, totalQueries = 30 }) {
  const started = Date.now();
  const latencies = [];
  let successful = 0;
  let failed = 0;
  let active = 0;

  const runOne = async () => {
    const res = await testDbConnection({ type, host, port, timeoutMs: 3000 });
    latencies.push(res.latencyMs);
    if (res.connected) successful++;
    else failed++;
  };

  const queue = Array.from({ length: totalQueries });
  const worker = async () => {
    while (queue.length) {
      queue.pop();
      await runOne();
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, totalQueries) }, () => worker()));

  const totalTimeMs = Date.now() - started;
  latencies.sort((a, b) => a - b);
  const avg = latencies.length ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length) : 0;

  return {
    type,
    host,
    port: Number(port) || getDefaultPort(type),
    totalAttempts: totalQueries,
    successful,
    failed,
    totalTimeMs,
    avgLatencyMs: avg,
    minLatencyMs: latencies[0] || 0,
    maxLatencyMs: latencies[latencies.length - 1] || 0,
  };
}
