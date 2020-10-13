const express = require('express')
const bodyParser = require('body-parser')
const secp256k1 = require('secp256k1')
const app = express()
const port = 3000

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({extended: false}))

// parse application/json
app.use(bodyParser.json())

app.post('/crypto/ecdsa-recover', (req, res) => {

    const signature = req.body['signature'];
    if (signature === undefined || signature.length !== 128) {
        res.json({result: "fail", info: "invalid signature"});
        return;
    }
    const message_hash = req.body['message_hash'];
    if (message_hash === undefined || message_hash.length !== 64) {
        res.json({result: "fail", info: "invalid message_hash"});
        return;
    }
    const v = req.body['v'];
    if (v === undefined || parseInt(v) >= 3 || parseInt(v) < 0) {
        res.json({result: "fail", info: "invalid v"});
        return;
    }

    const b_signature = Uint8Array.from(Buffer.from(signature, 'hex'));
    const b_message_hash = Uint8Array.from(Buffer.from(message_hash, 'hex'));
    const i_v = parseInt(v);
    const public_key = new Uint8Array(65);
    try {
        secp256k1.ecdsaRecover(b_signature, i_v, b_message_hash, false, public_key);
    } catch (err) {
        res.json({result: "fail", info: err.message});
        return;
    }

    const hex_public_key = Buffer.from(public_key).toString('hex');
    res.json({result: "success", public_key: hex_public_key.slice(2)});


})

app.listen(port, () => {
    console.log(`newchain-service listening at http://localhost:${port}`)
})
