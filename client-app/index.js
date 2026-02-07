import express from "express";
import cookieParser from "cookie-parser";
import axios from "axios";
import {randomBytes,createHash} from "crypto";

const app = express();
app.use(cookieParser());

const AUTH_SERVER = "http://localhost:3000";
const RESOURCE_SERVER = "http://localhost:5000";

const CLIENT_ID = "demo-client";
const REDIRECT_URI = "http://localhost:4000/callback";

//helpers
function base64url(input){
    return input.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function generateverifier(){
    return base64url(randomBytes(32));
}

function codeChallengeS256(verifier){
    const hash = createHash("sha256").update(verifier).digest();
    return base64url(hash);
}

function generateState(){
    return base64url(randomBytes(16));
}

app.get("/",(req,res)=>{
    res.send(`
        <h2>Client App</h2>
        <p>This app uses Authorization Code +PKCE.</p>
        <a href="/login">login</a>
        `);
});
        
app.get("/login",(req,res)=>{
            const code_verifier = generateverifier();
            const code_challenge = codeChallengeS256(code_verifier);
            const state = generateState();

            //store state and code_verifier in session
            res.cookie("oauth_state",state);
            res.cookie("code_verifier",code_verifier);

            const authorizeUrl = new URL(`${AUTH_SERVER}/authorize`);
            authorizeUrl.searchParams.append("response_type","code");
            authorizeUrl.searchParams.append("client_id",CLIENT_ID);
            authorizeUrl.searchParams.append("redirect_uri",REDIRECT_URI);
            authorizeUrl.searchParams.append("scope","api.read write");
            authorizeUrl.searchParams.append("state",state);
            authorizeUrl.searchParams.append("code_challenge",code_challenge);
            authorizeUrl.searchParams.append("code_challenge_method","S256");

            res.redirect(authorizeUrl.toString());
});

app.get("/callback",async (req,res)=>{
            const { code,state} = req.query;
            const storedState = req.cookies.oauth_state;
            const code_verifier = req.cookies.code_verifier;

            if(!code) return res.status(400).send("Missing code");
            if(!state || state !== storedState) return res.status(400).send("state misimatch");

            //exchange code for token
            const tokenRes = await axios.post(
                `${AUTH_SERVER}/token`,
            new URLSearchParams({
                grant_type: "authorization_code",
                code: code,
                redirect_uri: REDIRECT_URI,
                client_id: CLIENT_ID,
                code_verifier: code_verifier
            }).toString(),
            {
                headers: {"content-Type": "application/x-www-form-urlencoded"}}
            );

            const {access_token, refresh_token,expires_in}=tokenRes.data;

            res.cookie("access_token",access_token,{httpOnly:true});
            res.cookie("refresh_token", refresh_token, {httpOnly:true});

            res.send(`
                <h3>logged in</h3>
                <p>Acess token expires in ${expires_in} seconds.</p>
                <a href="/profile">Call Protected API</a>
                <br /><br/>
                <a href="/refresh">Refresh tokens</a>
                `);
});

app.get("/profile",async (req,res)=>{
            const token = req.cookies.access_token;
            if(!token) return res.redirect("/");

            try{
                const apiRes = await axios.get(`${RESOURCE_SERVER}/api/profile`,{
                    headers:{Authorization:`Bearer ${token}`}
                });

                res.send(`<pre>${JSON.stringify(apiRes.data,null,2)}</pre>`);
            }catch(err){
                const msg = err?.response?.data?JSON.stringify(err.response.data) : err.message
                res.status(500).send(`API call failed:${msg}`);
            }
});

app.get("/refresh",async(req,res)=>{
    const refreshToken = req.cookies.refresh_token;
    if (!refreshToken) return res.redirect("/");

    const tokenRes = await axios.post(
        `${AUTH_SERVER}/token`,
        new URLSearchParams({
            grant_type: "refresh_token",
            refresh_token: refreshToken,
            client_id: CLIENT_ID
        }).toString(),
        {
            headers: {"content-type":"application/x-www-form-urlencoded"}}
        
        );

        res.cookie("access_token", tokenRes.data.access_token,{httpOnly:true});
        
        res.send(`
            <h3>Token refreshed</h3>
            <p>New access token set in cookies</p>
            <a href="/profile">Call Protected API</a>
        `);
        });

        app.listen(4000,()=>{
            console.log("Client App running on http://localhost:4000");
        });
