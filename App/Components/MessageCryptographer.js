let tripicore = require('tripicore-lib');
let _ = tripicore.deps._;
let PrivateKey = tripicore.PrivateKey;
let PublicKey = tripicore.PublicKey;
let Address = tripicore.Address;
let BufferWriter = tripicore.encoding.BufferWriter;
let ECDSA = tripicore.crypto.ECDSA;
let Signature = tripicore.crypto.Signature;
let sha256sha256 = tripicore.crypto.Hash.sha256sha256;
let $ = tripicore.util.preconditions;

class MessageCryptographer {

    constructor(message) {

        $.checkArgument(_.isString(message), 'First argument should be a string');

        this.message = message;

        return this;
    }

    hash() {
        let messageBuffer = new Buffer(this.message);
        let prefix = BufferWriter.varintBufNum(messageBuffer.length);
        let buf = Buffer.concat([prefix, messageBuffer]);
        let hash = sha256sha256(buf);
        return hash;
    };

    _sign(privateKey) {
        $.checkArgument(privateKey instanceof PrivateKey,
            'First argument should be an instance of PrivateKey');
        let hash = this.hash();
        let ecdsa = new ECDSA();
        ecdsa.hashbuf = hash;
        ecdsa.privkey = privateKey;
        ecdsa.pubkey = privateKey.toPublicKey();
        ecdsa.signRandomK();
        ecdsa.calci();
        return ecdsa.sig;
    }

    sign(privateKey) {
        let signature = this._sign(privateKey);
        return signature.toCompact().toString('hex');
    }

    _verify(publicKey, signature) {
        $.checkArgument(publicKey instanceof PublicKey, 'First argument should be an instance of PublicKey');
        $.checkArgument(signature instanceof Signature, 'Second argument should be an instance of Signature');
        let hash = this.hash();
        let verified = ECDSA.verify(hash, signature, publicKey);
        if (!verified) {
            this.error = 'The signature was invalid';
        }
        return verified;
    }

    verify(address, signatureString) {
        $.checkArgument(address);
        $.checkArgument(signatureString && _.isString(signatureString));

        if (_.isString(address)) {
            address = Address.fromString(address);
        }
        let signature = Signature.fromCompact(new Buffer(signatureString, 'hex'));

        // recover the public key
        let ecdsa = new ECDSA();
        ecdsa.hashbuf = this.hash();
        ecdsa.sig = signature;
        let publicKey = ecdsa.toPublicKey();

        let signatureAddress = Address.fromPublicKey(publicKey, address.network);

        // check that the recovered address and specified address match
        if (address.toString() !== signatureAddress.toString()) {
            this.error = 'The signature did not match the message digest';
            return false;
        }

        return this._verify(publicKey, signature);
    }

    static fromString(str) {
        return new MessageCryptographer(str);
    }

}

module.exports = MessageCryptographer;