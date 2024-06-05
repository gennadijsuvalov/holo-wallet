const crypto = require('crypto');

class HoloWallet {
    constructor() {
        this.keys = this.generateKeys();
        this.balance = 0;
    }

    generateKeys() {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
            modulusLength: 2048,
            publicKeyEncoding: {
                type: 'spki',
                format: 'pem'
            },
            privateKeyEncoding: {
                type: 'pkcs8',
                format: 'pem'
            }
        });
        return { publicKey, privateKey };
    }

    encryptData(data) {
        const buffer = Buffer.from(data, 'utf8');
        const encrypted = crypto.publicEncrypt(this.keys.publicKey, buffer);
        return encrypted.toString('hex');
    }

    decryptData(encryptedData) {
        const buffer = Buffer.from(encryptedData, 'hex');
        const decrypted = crypto.privateDecrypt(this.keys.privateKey, buffer);
        return decrypted.toString('utf8');
    }

    signTransaction(transaction) {
        const sign = crypto.createSign('SHA256');
        sign.update(transaction);
        sign.end();
        const signature = sign.sign(this.keys.privateKey, 'hex');
        return signature;
    }

    verifyTransaction(transaction, signature, publicKey) {
        const verify = crypto.createVerify('SHA256');
        verify.update(transaction);
        verify.end();
        return verify.verify(publicKey, signature, 'hex');
    }

    addFunds(amount) {
        this.balance += amount;
    }

    transferFunds(amount, recipientPublicKey) {
        if (this.balance < amount) {
            throw new Error('Insufficient balance');
        }
        this.balance -= amount;
        const transaction = `Transfer ${amount} to ${recipientPublicKey}`;
        const signature = this.signTransaction(transaction);
        return { transaction, signature };
    }
}

module.exports = HoloWallet;
