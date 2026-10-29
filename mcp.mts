import {serveStdio, StdioServerTransport} from '@modelcontextprotocol/server/stdio';
import {createMcpAdapter, readMcpEnvironment} from './lib/mcp-adapter.mts';

// Never load .env, start Fabric, open a browser, or print configuration. The
// operator provides one existing scoped client grant through the environment.
try {
  if(process.argv.length!==2)throw new Error('Invalid MCP environment.');
  const env=readMcpEnvironment();
  const handle=serveStdio(()=>createMcpAdapter({env:{FABRIC_ENDPOINT:env.endpoint,FABRIC_CLIENT_TOKEN:env.token}}),{
    legacy:'serve',
    transport:new StdioServerTransport(process.stdin,process.stdout,{maxBufferSize:128*1024}),
    onerror:()=>{console.error('Fabric MCP transport rejected a message.');},
  });
  process.once('SIGINT',()=>{void handle.close();});
  process.once('SIGTERM',()=>{void handle.close();});
} catch {
  console.error('Invalid MCP environment. Provide a scoped FABRIC_CLIENT_TOKEN and a loopback FABRIC_ENDPOINT; no command arguments are accepted.');
  process.exitCode=1;
}
