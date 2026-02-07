import express from 'express';
import bodyPaser from 'body-parser';
import cookieParser from 'cookie-parser';
import {randomBytes, createHash} from 'crypto';
import { SignJWT, exportJWK , importPKCS8 } from 'jose';

const app = express();
app.use(bodyPaser.urlencoded({extended: false}));
app.use(bodyPaser.json());
app.use(cookieParser());



const clients = new Map()
const authorizationCodes =  new Map();
const refreshTokens = new Map();

clients.set("demo-client",{
    client_id:"demo-client",
    redirecturis: ["http://localhost:4000/callback"],
});

const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1+fWIcPm15A8+raZ4dp+/ObU31yrf0etiq4UbAHZ9bv+Lx
yBD4UfitqRiS/nF8M2fLM7wNegxDN3SdyCS48LgL/myIgQIhKaBurH8AAKa4r4A6
wcWPQeKpxYefZmspDjYWQqT/IaezR8pZFWR96vjlAW/GrKw87ZQffYQzOjIkVaa5
nL9RVNYW5JuIAstQEPsvvaxmBnqW2x+4BQqjJuL+SdanQgjXmnMWV+e5TCLWz184
mhYTsoPQQvP3X5nwn/VgwGqfRo7M6kfRu/4UP8DW1mHkWENbXz7i5OZtP0qBhJfO
8ykHKHLhAgMBAAECggEABfV8LEP5LVSvJxKj1KPwC6KxLxXvjPLNgtXJCJxJJdqH
kVQFZKzF7Qp9vBGKZ627AwkcjZNKCquJHH7VaKZEKvF0cLxdEzjKxNBvKU8W8kYm
xhc8kCKXvLdXJqKxJxKj1KPwC6KxLxXvjPLNgtXJCJxJJdqHkVQFZKzF7Qp9vBGK
Z627AwkcjZNKCquJHH7VaKZEKvF0cLxdEzjKxNBvKU8W8kYmxhc8kCKXvLdXJqKx
JxKj1KPwC6KxLxXvjPLNgtXJCJxJJdqHkVQFZKzF7Qp9vBGKZ627AwkcjZNKCquJ
HH7VaKZEKvF0cLxdEzjKxNBvKU8W8kYmxhc8kCKXvLdXJqKxJxKj1KPwC6KxLxXv
jPLNgtXJCJxJJdqHkVQFZKzF7Qp9vBGKZ627AwkcjZNKCquJHH7VaKZEKvF0cLxd
EzjKxNBvKU8W8kYmxhc8kCKXvLdXJqKxJxKj1KPwC6KxLxXvjPLNgtXJCJxJJdqH
kVQFZKzF7Qp9vBGKZ627AwkcjZNKCquJHH7VaKZEKvF0cLxdEzjKxNBvKU8W8kYm
xhc8kCKXvLdXJqKxJxKj1KPwC6KxLxXvjPLNgtXJCJxJJdqHkVQFZKzF7Qp9vBGK
Z627AwkcjZNKCquJHH7VaKZEKvF0cLxdEzjKxNBvKU8W8kYmxhc8kCKXvLdXJqKx
JxKj1KPwC6KxLxXvjPLNgtXJCJxJJdqHkVQFZKzF7Qp9vBGKZ627AwkcjZNKCquJ
HH7VaKZEKvF0cLxdEzjKxNBvKU8W8kYmxhc8kCKXvLdXJqKxJxKj1KPwC6KxLxXv
jPLNgtXJCJxJJdqHkVQFZKzF7Qp9vBGKZ627AwkcjZNKCquJHH7VaKZEKvF0cLxd
EzjKxNBvKU8W8kYmxhc8kCKXvLdXJqKxJxKj1KPwC6KxLxXvjPLNgtXJCJxJJdqH
kVQFZKzF7Qp9vBGKZ627AwkcjZNKCquJHH7VaKZEKvF0cLxdEzjKxNBvKU8W8kYm
xhc8kCKXvLdXJqKxJxKj1KPwC6KxLxXvjPLNgtXJCJxJJdqHkVQFZKzF7Qp9vBGK
Z627AwkcjZNKCquJHH7VaKZEKvF0cLxdEzjKxNBvKU8W8kYmxhc8kCKXvLdXJqKx
JxKj1KPwC6KxLxXvjPLNgtXJCJxJJdqHkVQFZKzF7Qp9vBGKZ627AwkcjZNKCquJ
HH7VaKZEKvF0cLxdEzjKxNBvKU8W8kYmxhc8kCKXvLdXJqKA==
-----END PRIVATE KEY-----`;

const ISSUER = "http://localhost:3000";
const KEY_ID = "demo-key-1";

function base64url(input) {
    return input.toString("base64").replace(/\+/g,"-").replace(/\//g, "_").replace(/=+$/g,"");
}

function sha256Base64url(str){
    const hash = createHash("sha256").update(str).digest();
    return base64url(hash);
}

function generateCode () {
    return base64url(randomBytes(32));
}

function getDemoUser() {
    return {sub:"ggnoheals",name:"gg",email:"gg@example.com"};
}

app.get("/authorize",(req,res) => {
    const {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        code_challenge,
        code_challenge_method,
    } = req.query;

// basic validation
const client = clients.get(client_id);
if (!client) return res.status(400).send("Unknown client_id");
if (!client.redirecturis.includes(redirect_uri)) return res.status(400).send("Invalid redirect_uri");
if (response_type !== "code" ) return res.status(400).send("Invalid response_type");
if (!code_challenge || !code_challenge_method || code_challenge_method !== "S256"){
    return res.status(400).send("PKCE required: provide code_challenge and code_challenge_method=S256");

}

// Normally: show login + consent UI.
// for tutorial simplicity: auto-login + auto-consent.
const user = getDemoUser();

const code = generateCode();
authorizationCodes.set(code, {
    clientId: client_id,
    redirectUri: redirect_uri,
    codeChallenge: code_challenge,
    scope,
    user,
    expiresAt: Date.now() + 5 * 60 * 1000,//5 minutes
});

 const redirect = new URL(redirect_uri);
 redirect.searchParams.set("code", code);
 if (state) redirect.searchParams.set("state", state);

 res.redirect(redirect.toString());
});

/**
 * post /tokem
 * supports:
 * - grant_type=authorization_code
 * - grant_type=refresh_token
*/

app.post("/token", async (req,res)=>{
    const {grant_type} = req.body;

    if(grant_type === "authorization_code"){
        const {code, code_verifier, redirect_uri, client_id} = req.body;

        const record = authorizationCodes.get(code);
        if (!record) return res.status(400).json({ error:"Invalid_grant",error_description:"unknown code "});
        if (record.expiresAt < Date.now()){
            authorizationCodes.delete(code);
            return res.status(400).json({error:"invalid_grant", error_description:"code expired"});
        }
        if (record.clientId !== client_id || record.redirectUri !== redirect_uri){
            return res.status(400).json({error:"invalid_grant", error_description:"mismatching client_id "});
        }

        //pkce validation 
        const computedChallenge = sha256Base64url(code_verifier);
        if (computedChallenge !== record.codeChallenge){
            return res.status(400).json({error:"invalid_grant", error_description:"PKCE validation failed"});
        }

        //One-time use code
        authorizationCodes.delete(code);

        //Create JWT access token
        const privatekey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");
        
        const accessToken = await new SignJWT({
            scope:record.scope,
            name:record.user.name,
            email:record.user.email
        })
        .setProtectedHeader({alg:"RS256", kid:KEY_ID})
        .setIssuer(ISSUER)
        .setAudience(client_id)
        .setSubject(record.user.sub)
        .setIssuedAt()
        .setExpirationTime("15m")
        .sign(privatekey);

        const refresh_token = generateCode();
        refreshTokens.set(refresh_token,{
            sub:record.user.sub,
            scope:record.scope,
            clientId:client_id,
        });

        return res.json({
            access_token:accessToken,
            refresh_token:refresh_token,
            token_type:"Bearer",
            expires_in:900,
            scope:record.scope
        });
    }
    if (grant_type==="refresh_token"){
        const {refresh_token, scope, client_id} = req.body;

        const record = refreshTokens.get(refresh_token);
        if (!record) return res.status(400).json({ error:"Invalid grant"});
        if (record.clientId !== client_id)return res.status(400).json({error:"invalid grant"});
        
        const privatekey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

        const accessToken = await new SignJWT({ scope: record.scope})
        .setProtectedHeader({alg:"RS256", kid:KEY_ID})
        .setIssuer(ISSUER)
        .setAudience(client_id)
        .setSubject(record.sub)
        .setIssuedAt()
        .setExpirationTime("15m")
        .sign(privatekey);
    
    return res.json({
        access_token:accessToken,
        token_type:"Bearer",
        expires_in:900,
    });
    }

    res.status(400).json({error:"unsupported_grant_type"});
});

/**
 * jwks endpoint:
 * Resource servers fetch public keys here to validate JWT sigin
 */
app.get("/.well-known/jwks.json",async(req,res)=>{
    const privatekey = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

    // jose exports JWK from a key object, but we need pun=blic JWKS
    // for tutorial simplicity, jose can export from private key
    const jwk = await exportJWK(privatekey);
    jwk.use = "sig";
    jwk.alg = "RS256";
    jwk.kid = KEY_ID;

    res.json({keys:[jwk]});
  
});

app.listen(3000,()=>{
    console.log("Auth server running on http://localhost:3000");
});
