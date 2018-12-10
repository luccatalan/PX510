'use strict';

let getMakeCredentialsChallenge = (formBody) => {
    return fetch('/webauthn/register', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The message is: ${response.message}`);

        return response
    })
}

let sendWebAuthnResponse = (body) => {
    return fetch('/webauthn/response', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The message is: ${response.message}`);

        return response
    })
}

/* Handle for register form submission */
$('#register').submit(function(event) {
    event.preventDefault();

    let text = "<center> <h4> <strong> Begin Registration </strong> </h4> </center>\n";

    sendToObs('Client', text);

    let username = this.username.value;
    let name     = this.name.value;
    let password = this.password.value;

    if(!username || !name || !password) {
        alert('Name or username or password is missing!')
        return
    }

    text = "Asking for registration\n";
    text += "Username = " + username + "\n";

    sendToObs('Client', text);

    let publicKey;
    getMakeCredentialsChallenge({username, name, password})
        .then((response) => {
            let text = "Waiting for user \""+ username + "\" to authenticate himself\n";

            sendToObs('Client', text);

            publicKey = preformatMakeCredReq(response);
            return navigator.credentials.create({ publicKey })
        })
        .then((response) => {
            let text = "User \""+ username + "\" presence detected\n";

            sendToObs('Client', text);

            let makeCredResponse = publicKeyCredentialToJSON(response);

            return sendWebAuthnResponse(makeCredResponse)
        })
        .then((response) => {
            if(response.status === 'ok') {
                let text = "<center> <h4> <strong> End Registration </strong> </h4> </center>\n";

                sendToObs('Client', text);

                loadMainContainer()
            } else {
                alert(`Server responed with error. The message is: ${response.message}`);
            }
        })
        .catch((error) => alert(error))
})

let getGetAssertionChallenge = (formBody) => {
    return fetch('/webauthn/login', {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formBody)
    })
    .then((response) => response.json())
    .then((response) => {
        if(response.status !== 'ok')
            throw new Error(`Server responed with error. The message is: ${response.message}`);

        return response
    })
}

/* Handle for login form submission */
$('#login').submit(function(event) {
    event.preventDefault();

    let text = "<center> <h4> <strong> Begin Login </strong> </h4> </center>\n";

    sendToObs('Client', text);

    let username = this.username.value;
    let password = this.password.value;

    if(!username || !password) {
        alert('Username or password is missing!')
        return
    }

    text = "Asking for authentication\n";
    text += "Username = " + username + "\n";

    sendToObs('Client', text);

    getGetAssertionChallenge({username, password})
        .then((response) => {
            let text = "Waiting for user \""+ username + "\" to authenticate himself\n";

            sendToObs('Client', text);

            let publicKey = preformatGetAssertReq(response);
            return navigator.credentials.get({ publicKey })
        })
        .then((response) => {
            let text = "User \""+ username + "\" presence detected\n";

            sendToObs('Client', text);

            let getAssertionResponse = publicKeyCredentialToJSON(response);
            return sendWebAuthnResponse(getAssertionResponse)
        })
        .then((response) => {
            if(response.status === 'ok') {
                let text = "<center> <h4> <strong> End Login </strong> </h4> </center>\n";

                sendToObs('Client', text);

                loadMainContainer()
            } else {
                alert(`Server responed with error. The message is: ${response.message}`);
            }
        })
        .catch((error) => alert(error))
})
