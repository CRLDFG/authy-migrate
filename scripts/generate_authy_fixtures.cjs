// PUBLIC SYNTHETIC FIXTURES ONLY. Node crypto is independent of the Python decoder.
// Fixed salts/IVs are for reproducible test vectors, never for real encryption.
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const backupPassword = ' Authy backup synthétique 🔑 ';
const inputs = [
  ['Example', 'demo@example.invalid', '12345678901234567890', 'base32', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'SHA1', 6, 30, 100000],
  ['Démo & Co', 'élève+test@example.invalid', '12345678901234567890123456789012', 'hex', null, 'SHA256', 8, 15, 132000],
  ['Example', 'demo@example.invalid', '1234567890123456789012345678901234567890123456789012345678901234', 'raw', null, 'SHA512', 8, 60, 70000],
  ['Example', 'demo@example.invalid', '12345678901234567890', 'base32', 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ', 'SHA1', 6, 30, 100000],
];
const rows = inputs.map(([issuer, name, secret, encoding, b32, algorithm, digits, period, iterations], i) => {
  const salt = `PUBLIC synthetic salt ${i}, é`;
  const iv = Buffer.alloc(16, i + 1);
  const key = crypto.pbkdf2Sync(backupPassword, salt, iterations, 32, 'sha1');
  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  const text = encoding === 'raw' ? secret : encoding === 'hex' ? Buffer.from(secret).toString('hex') : b32;
  const ciphertext = Buffer.concat([cipher.update(Buffer.from(text)), cipher.final()]);
  return {account_type:'authenticator', unique_id:`public-${i+1}`, name, issuer, algorithm, digits, period,
          encrypted_seed:ciphertext.toString('base64'), salt, unique_iv:iv.toString('hex'), key_derivation_iterations:iterations};
});
const directory = path.join(__dirname, '..', 'tests', 'fixtures');
const json = JSON.stringify({authenticator_tokens:rows, authy_tokens:[]}, null, 2) + '\n';
const headers = Object.keys(rows[0]).map(k => k === 'unique_iv' ? 'iv' : k);
const csvCell = value => '"' + String(value).replaceAll('"','""') + '"';
const csv = [headers.map(csvCell).join(','), ...rows.map(row => headers.map(k => csvCell(row[k === 'iv' ? 'unique_iv' : k])).join(','))].join('\r\n') + '\r\n';
for (const [filename, data] of [['authy-synthetic.json',json],['authy-synthetic.csv',csv]]) {
  fs.writeFileSync(path.join(directory,filename),data);
  const parameters = {version:1,source_sha256:crypto.createHash('sha256').update(data).digest('hex'),
     records:inputs.map((row,i)=>({row:i+1,otp_type:'TOTP',secret_encoding:row[3]}))};
  fs.writeFileSync(path.join(directory,filename+'.parameters.json'), JSON.stringify(parameters,null,2)+'\n');
}
console.log('Generated four PUBLIC Node-crypto test records in JSON and CSV. No real input accepted.');
