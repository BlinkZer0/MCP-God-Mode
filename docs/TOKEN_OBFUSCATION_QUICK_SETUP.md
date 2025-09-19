# 🚨 Token Obfuscation - Quick Setup Guide

## ⚡ **CRITICAL REQUIREMENT**

**⚠️ Token obfuscation WILL NOT WORK without proxy configuration!**

## 🔧 **Quick Setup (2 minutes)**

### **For Cursor Users:**
1. Open Cursor
2. Press `Ctrl+,` (Settings)
3. Search for "proxy"
4. Set HTTP/HTTPS proxy to: `http://localhost:8080`
5. Restart Cursor
6. ✅ **Done!** Token obfuscation now active

### **For Other AI Applications:**
```bash
# Windows Command Prompt
set HTTPS_PROXY=http://localhost:8080
set HTTP_PROXY=http://localhost:8080

# Windows PowerShell
$env:HTTPS_PROXY="http://localhost:8080"
$env:HTTP_PROXY="http://localhost:8080"

# Linux/macOS Terminal
export HTTPS_PROXY=http://localhost:8080
export HTTP_PROXY=http://localhost:8080
```

## 🧪 **Verify It's Working**

```bash
# Check if proxy is running
mcp_mcp-god-mode_token_obfuscation --action get_status

# Check statistics after using AI
mcp_mcp-god-mode_token_obfuscation --action get_stats
```

## 🔍 **Troubleshooting**

**Problem: "Not working"**
- ✅ Check proxy is running: `get_status`
- ✅ Restart your AI application
- ✅ Verify proxy settings are saved

**Problem: "Connection refused"**
- ✅ Start proxy: `--action start_proxy`
- ✅ Check port 8080 is available
- ✅ Try different port: `--proxy_port 8081`

**Problem: "No token reduction"**
- ✅ Confirm proxy configuration
- ✅ Check if AI app is using proxy
- ✅ Run verification test

## 📊 **Expected Results**

- **Token Reduction:** 90-100%
- **Functionality:** Unchanged
- **Performance:** Minimal impact
- **Stealth:** Maximum (undetectable)

## 📖 **Full Documentation**

- [Complete Token Obfuscation Guide](TOKEN_OBFUSCATION_GUIDE.md)
- [Natural Language Interface](TOKEN_OBFUSCATION_NATURAL_LANGUAGE_GUIDE.md)
- [Implementation Details](TOKEN_OBFUSCATION_IMPLEMENTATION_SUMMARY.md)

---

**⚡ Remember: Without proxy configuration, token obfuscation is just a background service doing nothing!**
