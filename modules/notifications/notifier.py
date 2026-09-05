#!/usr/bin/env python3
import requests

class NotificationManager:
    def send_discord(self, message, webhook):
        try:
            requests.post(webhook, json={"content": message}, timeout=10)
            return True
        except:
            return False
    
    def send_telegram(self, message, token, chat_id):
        try:
            url = f"https://api.telegram.org/bot{token}/sendMessage"
            requests.post(url, json={"chat_id": chat_id, "text": message}, timeout=10)
            return True
        except:
            return False
    
    def notify(self, finding, channels=None):
        severity = finding.get("severity", "info")
        title = finding.get("title", "Finding")
        message = f"[{severity.upper()}] {title}"
        
        if channels:
            for channel in channels:
                if channel == "discord":
                    self.send_discord(message, channels["discord"])
