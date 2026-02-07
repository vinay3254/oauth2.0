# OAuth 2.0 with PKCE Demo

## Step 1: Install Dependencies

Before running the servers, install dependencies for each folder.

### Install Auth Server Dependencies
```bash
cd c:\Users\Admin\Desktop\Oauth2.0\auth-server
npm install
```

### Install Resource Server Dependencies
```bash
cd c:\Users\Admin\Desktop\Oauth2.0\resource-server
npm install
```

### Install Client App Dependencies
```bash
cd c:\Users\Admin\Desktop\Oauth2.0\client-app
npm install
```

## Step 2: Run the Servers

You need to run all three servers in separate terminal windows.

### Terminal 1 - Run Auth Server
```bash
cd c:\Users\Admin\Desktop\Oauth2.0\auth-server
node index.js
```

### Terminal 2 - Run Resource Server
```bash
cd c:\Users\Admin\Desktop\Oauth2.0\resource-server
node index.js
```

### Terminal 3 - Run Client App
```bash
cd c:\Users\Admin\Desktop\Oauth2.0\client-app
node index.js
```

## Step 3: Test the Application

Open your browser and go to: **http://localhost:4000**

Click "login" and follow the OAuth flow.

## Commands Summary

### Run All Servers (PowerShell)
```powershell
start cmd /k "cd auth-server && node index.js"; start cmd /k "cd resource-server && node index.js"; start cmd /k "cd client-app && node index.js"
```
Run from: `c:\Users\Admin\Desktop\Oauth2.0`

### Individual Commands
- **Auth Server**: `cd auth-server && node index.js`
- **Resource Server**: `cd resource-server && node index.js`
- **Client App**: `cd client-app && node index.js`
