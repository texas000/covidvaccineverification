const express = require('express');
const zlib = require('zlib')
const axios = require('axios').default;
const jose = require('node-jose');
const cvx = require('./cvx.json')
const port = process.env.PORT || 1234
const server = express();
server.use(express.urlencoded({ extended: true }));
server.use(express.json())

server.get('/card', async (req, res) => {
    const shcRawData = req.query.shc;
    function parseJwtHeader(header) {
        const headerData = Buffer.from(header, "base64");
        return JSON.parse(headerData)
    }
    function parseJwtPayload(payload) {
        const buffer = Buffer.from(payload, "base64");
        const payloadJson = zlib.inflateRawSync(buffer)
        return JSON.parse(payloadJson);
    }
    async function verifySignature(jwt, issuer) {        
            const response = await axios.get(`${issuer}/.well-known/jwks.json`)
            const jwks = response.data;
            const keys = await jose.JWK.asKeyStore(jwks)
            const result = await jose.JWS.createVerify(keys).verify(jwt)
            return result
    }
    async function parseShc(raw) {
        const jwt = numericShcToJwt(raw)
        
        const splited = jwt.split(".")
        if(splited.length!=3) {
            return {code: 401, data:'Invalid Code'}
        }
        const header = parseJwtHeader(splited[0])
        const payload = parseJwtPayload(splited[1]);
        const verifications = await verifySignature(jwt, payload.iss)
        const entries = payload.vc.credentialSubject.fhirBundle.entry || [];
        const vaccine = entries.filter(e => e.resource.resourceType === 'Immunization')
        .map(e => {
            let resource = e.resource;
            const a =cvx.findIndex(ga=> ga.CVXCode==resource.vaccineCode.coding[0].code)
            return {...resource, vaccineInfo: cvx[a]};
        });
        const patient = entries.filter(e => e.resource.resourceType === 'Patient')
        .map(e => {
            let resource = e.resource;
            return resource;
        });
        return {code:200, data:{vaccine, patient}}
    }

    function numericShcToJwt(rawSHC) {
        if (rawSHC.startsWith('shc:/')) {
            rawSHC = rawSHC.split('/')[1];
        }     
        return rawSHC
            .match(/(..?)/g)
            .map((number) => String.fromCharCode(parseInt(number, 10) + 45))
            .join("")
    }
    try {
        const data = await parseShc(shcRawData);
        res.status(data.code).send(
            data.data
        );
    } catch (e) {
        console.log(e)
        res.status(400).send('400 Bad Request');
    }
});
server.listen(port);
console.log(`Listening on localhost:${port}`)