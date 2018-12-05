const express   = require('express');
const utils     = require('../utils');
const config    = require('../config.json');
const base64url = require('base64url');
const router    = express.Router();
const database  = require('./db');

router.post('/register', (request, response) => {
    if(!request.body || !request.body.username || !request.body.name || !request.body.password) {
        response.json({
            'status': 'failed',
            'message': 'Request missing name or username or password field!'
        })

        return
    }

    let username = request.body.username;
    let name     = request.body.name;
    let password = request.body.password;

    if(database[username] && database[username].registered) {
        response.json({
            'status': 'failed',
            'message': `Username ${username} already exists`
        })

        return
    }

    database[username] = {
        'name': name,
        'password': password,
        'registered': false,
        'id': utils.randomBase64URLBuffer(),
        'authenticators': []
    }

    let challengeMakeCred    = utils.generateServerMakeCredRequest(username, name, database[username].id)
    challengeMakeCred.status = 'ok'

    request.session.challenge = challengeMakeCred.challenge;
    request.session.username  = username;

    let text = "Sending Challenge and Relying party Id to user \"" + username + "\"\n";
    text += "<strong>Challenge = " + challengeMakeCred.challenge + "</strong>\n";
    text += "Relying party Id = " + challengeMakeCred.rp.name + "\n";

    utils.sendToObs('Server',text);

    response.json(challengeMakeCred)
})

router.post('/login', (request, response) => {
    if(!request.body || !request.body.username || !request.body.password) {
        response.json({
            'status': 'failed',
            'message': 'Request missing username or password field!'
        })

        return
    }

    let username = request.body.username;
    let password = request.body.password;

    if(!database[username] || !database[username].registered || database[username].password !== password) {
        response.json({
            'status': 'failed',
            'message': `User ${username} does not exist or invalid password !`
        })

        return
    }

    let getAssertion    = utils.generateServerGetAssertion(database[username].authenticators)
    getAssertion.status = 'ok'

    request.session.challenge = getAssertion.challenge;
    request.session.username  = username;

    let text = "Sending challenge and credentialId\n";
    text += "<strong>Challenge = " + getAssertion.challenge + "</strong>\n";
    text += "CredentialId = " + getAssertion.allowCredentials[0].id + "\n";

    utils.sendToObs('Server',text);

    response.json(getAssertion)
})

router.post('/response', (request, response) => {
    if(!request.body       || !request.body.id
    || !request.body.rawId || !request.body.response
    || !request.body.type  || request.body.type !== 'public-key' ) {
        response.json({
            'status': 'failed',
            'message': 'Response missing one or more of id/rawId/response/type fields, or type is not public-key!'
        })

        return
    }

    let webauthnResp = request.body
    let clientData   = JSON.parse(base64url.decode(webauthnResp.response.clientDataJSON));

    /* Check challenge... */
    if(clientData.challenge !== request.session.challenge) {
        response.json({
            'status': 'failed',
            'message': 'Challenges don\'t match!'
        })
    }

    /* ...and origin
    if(clientData.origin !== config.origin) {
        response.json({
            'status': 'failed',
            'message': 'Origins don\'t match!'
        })
    } */

    let result;
    if(webauthnResp.response.attestationObject !== undefined) {
        /* This is create cred */
        result = utils.verifyAuthenticatorAttestationResponse(webauthnResp);

        if(result.verified) {
            database[request.session.username].authenticators.push(result.authrInfo);
            database[request.session.username].registered = true
        }
    } else if(webauthnResp.response.authenticatorData !== undefined) {
        /* This is get assertion */
        result = utils.verifyAuthenticatorAssertionResponse(webauthnResp, database[request.session.username].authenticators);
    } else {
        response.json({
            'status': 'failed',
            'message': 'Can not determine type of response!'
        })
    }

    if(result.verified) {
        request.session.loggedIn = true;
        response.json({ 'status': 'ok' })
    } else {
        response.json({
            'status': 'failed',
            'message': 'Can not authenticate signature!'
        })
    }
})

module.exports = router;
