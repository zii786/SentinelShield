# SentinelShield WAF (Web Application Firewall)

A real-time Web Application Firewall that monitors, analyzes, and actively blocks malicious traffic to protect web applications.

---

## 🚀 Features

- **Real-time Traffic Monitoring**  
  Analyzes actual web traffic from Nginx logs

- **Active Threat Detection**  
  Detects rate limiting violations, suspicious user agents, and other attack patterns

- **IP Blocking / Unblocking**  
  Administrators can manually block or unblock IP addresses

- **Live Dashboard**  
  Real-time statistics and event monitoring

- **Docker-based Architecture**  
  Easy deployment using Docker Compose

- **Reverse Proxy Protection**  
  Nginx acts as a reverse proxy to protect the target application

---

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────────┐    ┌─────────────────┐
│   Normal User   │───▶│  SentinelShield WAF │───▶│ Target Website  │
│   (Port 80)     │    │                     │    │   (Port 5001)   │
└─────────────────┘    │  [Nginx + Python]   │    └─────────────────┘
                       └─────────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │ Admin Dashboard │
                       │   (Port 8080)   │
                       └─────────────────┘
```

---

## 📋 Prerequisites

- Docker
- Docker Compose
- At least **2GB RAM**
- Ports **80** and **8080** available

---

## 🛠️ Installation & Setup

### 1. Clone the Repository

```bash
git clone <repository-url>
cd SentinelShield
```

---

### 2. Configure Environment Variables

The `.env` file is located in:

```
backend/.env
```

Example configuration:

```env
# Admin Authentication
ADMIN_USERNAME=admin
ADMIN_PASSWORD=password123
SECRET_KEY=your-super-secret-key-change-this-in-production

# Email Alerts (Optional)
EMAIL_ALERTS_ENABLED=False
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
EMAIL_FROM=your-email@gmail.com
EMAIL_TO=admin@yourdomain.com
```

---

### 3. Start the Services

```bash
docker-compose up -d
```

---

### 4. Access the Applications

| Service | URL |
|------|------|
| Target Website | http://localhost |
| Admin Dashboard | http://localhost:8080 |

**Admin Login**

```
Username: admin
Password: password123
```

---

# 🔧 How It Works

## Traffic Flow

1. **User Request**  
   User visits the target website on port **80**

2. **Nginx Processing**  
   Nginx receives the request, logs it, and forwards it to the target app

3. **Log Analysis**  
   Python service continuously reads **Nginx logs**

4. **Threat Detection**  
   Suspicious patterns trigger security events

5. **Active Response**  
   Admin can block malicious IP addresses from the dashboard

---

# 🔐 Security Features

### Rate Limiting
Detects IPs making excessive requests

### Suspicious User Agents
Detects known attack tools such as:

- sqlmap
- nmap
- nikto
- dirbuster

### Manual IP Blocking
Admins can block or unblock IPs in real-time.

### Event Logging
All security events are logged and displayed in the dashboard.

---

# 📊 Dashboard Features

## Main Dashboard

- Real-time request statistics
- Recent security events
- Quick blocking actions

---

## Logs Page

- Detailed view of security events
- Search and filtering options

---

## Blacklist Management

- View blocked IPs
- Unblock IPs instantly
- Block IPs manually from events

---

## History

- Historical traffic analysis
- Trend visualization

---

# 🚨 Security Events

SentinelShield detects and logs:

- **Rate Limit Exceeded**  
  IP making too many requests

- **Suspicious User-Agent**  
  Attack tools detected

- **Manual IP Block**  
  Admin manually blocks an IP

- **Manual IP Unblock**  
  Admin removes an IP from blacklist

---

# 🔍 Monitoring & Health Checks

## Health Check Endpoint

```bash
curl http://localhost:8080/health
```

Returns system status including:

- Log processing status
- Blacklist status
- Request statistics

---

# 📂 Log Files

| Log Type | Location |
|--------|--------|
| Nginx Access Logs | `/var/log/nginx/access.log` |
| Security Events | `backend/events.json` |
| Application Logs | `backend/logs.json` |

---

# 🛡️ Production Considerations

## Security

- Change default credentials
- Use a strong `SECRET_KEY`
- Enable HTTPS with SSL certificates
- Restrict access to admin dashboard

---

## Performance

- Configure Docker resource limits
- Enable log rotation
- Monitor health endpoint

---

## Scaling

Possible improvements:

- Load balancing multiple Nginx instances
- Replace JSON logs with a database
- Add Redis caching for faster performance

---

# 🐛 Troubleshooting

## Dashboard Not Loading

Check containers:

```bash
docker-compose ps
```

Check logs:

```bash
docker-compose logs sentinelshield_app
```

Verify port **8080** availability.

---

## Target Website Not Accessible

Check Nginx logs:

```bash
docker-compose logs nginx
```

Check target application:

```bash
docker-compose logs target_app
```

Ensure port **80** is available.

---

## IP Blocking Not Working

- Verify Docker socket mounting
- Check `blacklist.conf` permissions
- Validate Nginx configuration

---

# 🧰 Useful Commands

### View all container logs

```bash
docker-compose logs -f
```

### Restart specific service

```bash
docker-compose restart sentinelshield_app
```

### Check container status

```bash
docker-compose ps
```

### Access container shell

```bash
docker-compose exec sentinelshield_app bash
```

### View Nginx configuration

```bash
docker-compose exec nginx cat /etc/nginx/nginx.conf
```

---

# 📝 License

This project is for **educational and demonstration purposes**.  
Use at your own risk in production environments.

---

# 🤝 Contributing

1. Fork the repository  
2. Create a feature branch  
3. Make your changes  
4. Test thoroughly  
5. Submit a pull request  

---

# 📞 Support

If you encounter issues:

1. Check the troubleshooting section
2. Review container logs
3. Open an issue with detailed information

---

⚠️ **Security Notice:**  
This is a **demonstration Web Application Firewall**.  
For production environments, additional security measures and professional security audits are recommended.
