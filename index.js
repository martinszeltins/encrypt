import crypto from 'crypto';
import fs from 'fs';
import path from 'path';

const ALGORITHM = 'aes-256-cbc';
const SALT_LENGTH = 8;
const KEY_LENGTH = 32;
const IV_LENGTH = 16;
const PBKDF2_ITERATIONS = 10000;

// Function to get password from user
function getPassword() {
    return new Promise((resolve) => {
        const stdin = process.stdin;
        
        stdin.resume();
        stdin.setEncoding('utf8');

        let password = '';
        process.stdout.write('enter aes-256-cbc encryption password: ');

        if (stdin.isTTY) {
            // TTY mode - hide password input and read character by character
            stdin.setRawMode(true);
            
            const onData = (char) => {
                const charStr = char.toString('utf8');
                
                if (charStr === '\n' || charStr === '\r' || charStr === '\u0004') {
                    stdin.setRawMode(false);
                    stdin.removeListener('data', onData);
                    stdin.pause();
                    process.stdout.write('\n');
                    resolve(password);
                } else if (charStr === '\u0003') {
                    // Ctrl+C
                    process.exit(1);
                } else if (charStr === '\u007f' || charStr === '\b') {
                    // Backspace
                    if (password.length > 0) {
                        password = password.slice(0, -1);
                    }
                } else {
                    password += charStr;
                }
            };
            
            stdin.on('data', onData);
        } else {
            // Non-TTY mode - read entire line (for piped input)
            const onData = (data) => {
                password += data;
                if (password.includes('\n')) {
                    password = password.split('\n')[0];
                    stdin.removeListener('data', onData);
                    stdin.pause();
                    resolve(password);
                }
            };
            
            stdin.on('data', onData);
        }
    });
}

// Derive key and IV from password using PBKDF2 (matching OpenSSL's behavior)
function deriveKeyAndIV(password, salt) {
    const key = crypto.pbkdf2Sync(password, salt, PBKDF2_ITERATIONS, KEY_LENGTH + IV_LENGTH, 'sha256');
    return {
        key: key.slice(0, KEY_LENGTH),
        iv: key.slice(KEY_LENGTH, KEY_LENGTH + IV_LENGTH)
    };
}

// Function to encrypt text and output base64
async function encryptText(plainText) {
    try {
        const password = await getPassword();
        const salt = crypto.randomBytes(SALT_LENGTH);
        const { key, iv } = deriveKeyAndIV(password, salt);

        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        
        // Create buffer with "Salted__" header + salt + encrypted data (matching OpenSSL format)
        const encrypted = Buffer.concat([cipher.update(plainText, 'utf8'), cipher.final()]);
        const result = Buffer.concat([
            Buffer.from('Salted__', 'utf8'),
            salt,
            encrypted
        ]);

        console.log('');
        process.stdout.write(result.toString('base64'));
        console.log('');
        console.log('');
    } catch (error) {
        console.error('Encryption failed:', error.message);
        process.exit(1);
    }
}

// Function to encrypt a file and output the path of the encrypted file
async function encryptFile(inputFile) {
    try {
        const password = await getPassword();
        const outputFile = `${inputFile}.enc`;
        const salt = crypto.randomBytes(SALT_LENGTH);
        const { key, iv } = deriveKeyAndIV(password, salt);

        const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
        
        const input = fs.createReadStream(inputFile);
        const output = fs.createWriteStream(outputFile);

        // Write OpenSSL-compatible header
        output.write(Buffer.from('Salted__', 'utf8'));
        output.write(salt);

        input.pipe(cipher).pipe(output);

        output.on('finish', () => {
            console.log('');
            console.log(`👉 Encrypted file: ${path.resolve(outputFile)}`);
            console.log('');
        });

        output.on('error', (error) => {
            console.error('Encryption failed:', error.message);
            process.exit(1);
        });
    } catch (error) {
        console.error('Encryption failed:', error.message);
        process.exit(1);
    }
}

export { encryptText, encryptFile };
