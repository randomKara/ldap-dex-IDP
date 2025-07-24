# Access Guide: OAuth2 PEP for Zero Trust Access

This guide provides step-by-step instructions for running the project, logging in, and troubleshooting common issues.

---

## 🚀 **1. System Requirements**

- **Docker** and **Docker Compose** must be installed on your system.
- An internet connection is required to pull the base Docker images.
- A web browser or a command-line tool like `curl`.

---

## 🏁 **2. Quick Start**

### **Step 1: Build and Start the Services**

Open a terminal in the project's root directory and run the following command:

```bash
docker compose up --build -d
```
This command will build all the service images and start them in detached mode.

### **Step 2: Access the Application**

The main entry point for the application is the **Policy Enforcement Point (PEP)**.

- **Open your web browser and navigate to:**
  ```
  http://172.25.0.40
  ```

- **⚠️ IMPORTANT:**
  - **Do NOT use `localhost:5000`**. The system is intentionally configured to reject requests from `localhost` to protect against CSRF attacks. You must use the service's static IP address.
  - If you are running Docker on a remote machine, ensure you can access the `172.25.0.0/24` subnet.

### **Step 3: Authenticate**

1.  You will be automatically redirected to the **Dex OIDC provider's** login page, served via the Apache reverse proxy.
2.  Click the **"Login with LDAP"** button.
3.  Use one of the pre-configured test accounts to log in.

#### **Test Accounts:**

| Username | Password |
|---|---|
| `user1` | `password1` |
| `user2` | `password2` |
| `user3` | `password3` |
| `user4` | `password4` |

### **Step 4: View the Protected Application**

After a successful login, you will be redirected to the backend Flask application, which will display a personalized welcome message with your user information. This information was securely injected into HTTP headers by the PEP.

---

## 🚨 **3. Troubleshooting**

Here are solutions to common issues you might encounter.

### **Issue: "Internal Server Error" or "403 Forbidden" on `http://172.25.0.40`**

- **Cause**: This is the expected behavior if you try to access the application from `localhost` or an untrusted IP address. The security policies (CSRF, IP whitelisting) are correctly blocking the request.
- **✅ Solution**: Ensure you are using the correct IP address: `http://172.25.0.40`.

### **Issue: "Login error: failed to connect: LDAP Result Code 200..."**

- **Cause**: The Dex container cannot establish a connection with the OpenLDAP container.
- **✅ Solution**:
  1.  **Check Container Status**: Ensure all containers are running with `docker compose ps`.
  2.  **Verify Network**: Confirm that the `dex-server` and `ldap-server` are on the same `secure-network`.
  3.  **Check Logs**: Review the logs for both services for more detailed errors:
      ```bash
      docker compose logs dex-server
      docker compose logs ldap-server
      ```

### **Issue: Services are not starting or are exiting unexpectedly.**

- **Cause**: This could be due to a port conflict on your host machine or a misconfiguration.
- **✅ Solution**:
  1.  **Check Ports**: Make sure ports `80`, `5000`, `1389`, and `1636` are not in use by other applications on your host.
  2.  **View Logs**: Check the logs of the failing container for specific error messages: `docker compose logs <service-name>`.
  3.  **Clean Up**: If issues persist, stop and remove all services and volumes, then try again:
      ```bash
      docker compose down -v
      docker compose up --build -d
      ```

---

## 🛠️ **4. Monitoring and Management**

### **View Service Status**

To check the status of all running containers:
```bash
docker compose ps
```

### **View Service Logs**

To view the real-time logs for a specific service (e.g., the PEP):
```bash
docker compose logs -f pep
```
Replace `pep` with `apache-proxy`, `dex-server`, `ldap-server`, or `flask-app` as needed.

### **Stop the Services**

To stop all running services without deleting data:
```bash
docker compose stop
```

To stop and remove the containers and network:
```bash
docker compose down
```

To perform a full cleanup, including removing volumes (this will delete LDAP data):
```bash
docker compose down -v
``` 