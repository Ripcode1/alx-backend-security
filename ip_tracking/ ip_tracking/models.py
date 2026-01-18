"""
IP Tracking Models

This module contains models for:
- RequestLog: Logging IP addresses, timestamps, paths, and geolocation data
- BlockedIP: Managing blacklisted IP addresses
- SuspiciousIP: Flagging IPs detected by anomaly detection
"""

from django.db import models
from django.utils import timezone


class RequestLog(models.Model):
    """
    Model to log incoming request details including IP address,
    timestamp, request path, and geolocation data.
    
    Task 0: Basic fields (ip_address, timestamp, path)
    Task 2: Extended with geolocation fields (country, city)
    """
    ip_address = models.GenericIPAddressField(
        help_text="The IP address of the client making the request"
    )
    timestamp = models.DateTimeField(
        default=timezone.now,
        help_text="When the request was made"
    )
    path = models.CharField(
        max_length=2048,
        help_text="The URL path that was requested"
    )
    # Task 2: Geolocation fields
    country = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="Country determined from IP geolocation"
    )
    city = models.CharField(
        max_length=100,
        blank=True,
        null=True,
        help_text="City determined from IP geolocation"
    )
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['timestamp']),
            models.Index(fields=['ip_address', 'timestamp']),
        ]
        verbose_name = "Request Log"
        verbose_name_plural = "Request Logs"
    
    def __str__(self):
        return f"{self.ip_address} - {self.path} @ {self.timestamp}"


class BlockedIP(models.Model):
    """
    Model to store blacklisted IP addresses.
    Requests from these IPs will be blocked with a 403 Forbidden response.
    
    Task 1: IP Blacklisting
    """
    ip_address = models.GenericIPAddressField(
        unique=True,
        help_text="The IP address to block"
    )
    reason = models.TextField(
        blank=True,
        null=True,
        help_text="Reason for blocking this IP"
    )
    created_at = models.DateTimeField(
        auto_now_add=True,
        help_text="When this IP was added to the blacklist"
    )
    is_active = models.BooleanField(
        default=True,
        help_text="Whether this block is currently active"
    )
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = "Blocked IP"
        verbose_name_plural = "Blocked IPs"
    
    def __str__(self):
        status = "Active" if self.is_active else "Inactive"
        return f"{self.ip_address} ({status})"


class SuspiciousIP(models.Model):
    """
    Model to flag IPs detected as suspicious by anomaly detection.
    
    Task 4: Anomaly Detection
    """
    ip_address = models.GenericIPAddressField(
        help_text="The suspicious IP address"
    )
    reason = models.TextField(
        help_text="Reason why this IP was flagged as suspicious"
    )
    detected_at = models.DateTimeField(
        default=timezone.now,
        help_text="When the suspicious activity was detected"
    )
    request_count = models.PositiveIntegerField(
        default=0,
        help_text="Number of requests from this IP in the detection window"
    )
    is_reviewed = models.BooleanField(
        default=False,
        help_text="Whether this suspicious activity has been reviewed"
    )
    
    class Meta:
        ordering = ['-detected_at']
        indexes = [
            models.Index(fields=['ip_address']),
            models.Index(fields=['detected_at']),
        ]
        verbose_name = "Suspicious IP"
        verbose_name_plural = "Suspicious IPs"
    
    def __str__(self):
        return f"{self.ip_address} - {self.reason[:50]}..."
