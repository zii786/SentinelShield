# SentinelShield WAF (Web Application Firewall)

A real-time Web Application Firewall that monitors, analyzes, and actively blocks malicious traffic to protect web applications.

## 🚀 Features

- **Real-time Traffic Monitoring**: Analyzes actual web traffic from Nginx logs
- **Active Threat Detection**: Detects rate limiting violations, suspicious user agents, and other attack patterns
- **IP Blocking/Unblocking**: Administrators can manually block or unblock IP addresses
- **Live Dashboard**: Real-time statistics and event monitoring
- **Docker-based Architecture**: Easy deployment with Docker Compose
- **Reverse Proxy**: Nginx acts as a reverse proxy to protect the target application

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

## 📋 Prerequisites

- Docker and Docker Compose
- At least 2GB RAM
- Ports 80 and 8080 available

## 🛠️ Installation & Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd SentinelShield
```

### 2. Configure Environment Variables
The `.env` file has been created automatically. You can modify it in `backend/.env`:

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

### 3. Start the Services
```bash
docker-compose up -d
```

### 4. Access the Applications

- **Target Website**: http://localhost (Port 80)
- **Admin Dashboard**: http://localhost:8080 (Port 8080)
  - Username: `admin`
  - Password: `password123`

## 🔧 How It Works

### Traffic Flow
1. **User Request**: User visits the target website on port 80
2. **Nginx Processing**: Nginx receives the request, logs it, and forwards to target app
3. **Log Analysis**: Python app continuously reads Nginx logs and analyzes for threats
4. **Threat Detection**: Suspicious patterns trigger events in the dashboard
5. **Active Response**: Admins can block malicious IPs through the dashboard

### Security Features
- **Rate Limiting**: Detects IPs making too many requests
- **Suspicious User Agents**: Identifies known attack tools (sqlmap, nmap, etc.)
- **Manual IP Blocking**: Admins can block/unblock IPs in real-time
- **Event Logging**: All security events are logged and displayed

## 📊 Dashboard Features

### Main Dashboard
- Real-time request statistics
- Recent security events
- Quick access to blocking functions

### Logs Page
- Detailed view of all security events
- Filtering and search capabilities

### Blacklist Management
- View all currently blocked IPs
- Unblock IPs with one click
- Manual IP blocking from events

### History
- Historical traffic analysis
- Trend visualization

## 🚨 Security Events

The WAF detects and logs the following events:

1. **Rate Limit Exceeded**: IP making too many requests
2. **Suspicious User-Agent**: Known attack tools detected
3. **Manual IP Block**: Admin-initiated IP blocking
4. **Manual IP Unblock**: Admin-initiated IP unblocking

## 🔍 Monitoring & Health Checks

### Health Check Endpoint
```bash
curl http://localhost:8080/health
```

Returns system status including:
- Log processing status
- Blacklist management status
- Request statistics

### Log Files
- **Nginx Access Logs**: `/var/log/nginx/access.log`
- **Security Events**: `backend/events.json`
- **Application Logs**: `backend/logs.json`

## 🛡️ Production Considerations

### Security
1. **Change Default Credentials**: Update admin username/password in `.env`
2. **Use Strong Secret Key**: Generate a secure SECRET_KEY
3. **Enable HTTPS**: Configure SSL certificates for production
4. **Network Security**: Restrict access to admin dashboard

### Performance
1. **Resource Limits**: Set appropriate Docker resource limits
2. **Log Rotation**: Configure log rotation to prevent disk space issues
3. **Monitoring**: Set up external monitoring for the health endpoint

### Scaling
1. **Load Balancing**: Add multiple Nginx instances behind a load balancer
2. **Database**: Consider using a proper database instead of JSON files
3. **Caching**: Implement Redis for better performance

## 🐛 Troubleshooting

### Common Issues

1. **Dashboard Not Loading**
   - Check if all containers are running: `docker-compose ps`
   - Verify port 8080 is not in use
   - Check container logs: `docker-compose logs sentinelshield_app`

2. **Target Website Not Accessible**
   - Verify port 80 is available
   - Check Nginx logs: `docker-compose logs nginx`
   - Ensure target app is running: `docker-compose logs target_app`

3. **IP Blocking Not Working**
   - Check if Docker socket is mounted correctly
   - Verify blacklist.conf file permissions
   - Check Nginx configuration syntax

### Useful Commands

```bash
# View all container logs
docker-compose logs -f

# Restart specific service
docker-compose restart sentinelshield_app

# Check container status
docker-compose ps

# Access container shell
docker-compose exec sentinelshield_app bash

# View Nginx configuration
docker-compose exec nginx cat /etc/nginx/nginx.conf
```

## 📝 License

This project is for educational and demonstration purposes. Use at your own risk in production environments.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For issues and questions:
1. Check the troubleshooting section
2. Review container logs
3. Create an issue with detailed information

---

**⚠️ Security Notice**: This is a demonstration WAF. For production use, consider additional security measures and professional security auditing. 