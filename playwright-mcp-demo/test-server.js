import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Test script to verify MCP server functionality
async function testMCPServer() {
  console.log('Testing MCP server tools...\n');
  
  // Test injection attacks first (fastest test)
  console.log('🧪 Testing SQL injection detection...');
  try {
    const result = await execAsync('echo \'{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "test_injection_attacks", "arguments": {"url": "https://thyaga.lk/"}}}\' | node build/index.js');
    console.log('✅ SQL injection test completed');
    console.log(result.stdout.substring(0, 200) + '...\n');
  } catch (error) {
    console.log('❌ SQL injection test failed:', error.message);
  }
  
  // Test XSS detection
  console.log('🧪 Testing XSS detection...');
  try {
    const result = await execAsync('echo \'{"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "test_xss", "arguments": {"url": "https://thyaga.lk/"}}}\' | node build/index.js');
    console.log('✅ XSS test completed');
    console.log(result.stdout.substring(0, 200) + '...\n');
  } catch (error) {
    console.log('❌ XSS test failed:', error.message);
  }
}

testMCPServer().catch(console.error);
