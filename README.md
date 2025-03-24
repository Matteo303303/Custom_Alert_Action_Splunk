# Custom_Alert_Action_Splunk
Custom alert action for Splunk to block IP addresses or user accounts in response to security events. Includes a custom HTML interface, event logger, and supports detection of Port Scanning, Privilege Escalation, and SSH Brute Force. Developed on a Splunk SOC infrastructure deployed on AWS.

# 🛡️Splunk Custom Alert Action – SOC Project

Custom alert action for Splunk to block IP addresses or user accounts in response to security events. Developed as part of a SOC (Security Operations Center) project on AWS.

## 📌 Project Overview

This project enhances Splunk by implementing a custom alert action that automatically blocks malicious IPs or user accounts upon detecting specific security threats.

## ✅ Features

Automated Blocking: Automatically blocks suspicious IP addresses or user accounts.

Custom HTML Interface: Provides a user-friendly UI within Splunk’s alert editor.

Event Logging: Records detailed logs for each action executed.

Attack Detection: Supports detection of:

Port Scanning

Privilege Escalation

SSH Brute Force

## 🏗️ Infrastructure

The project runs on a Splunk SOC infrastructure deployed on AWS, consisting of:

Splunk VM: Search head + Indexer

Forwarder VM: Monitored system

Attack Simulator VM: Generates malicious traffic for testing



## 🚀 Installation

Clone the repository:

Copy the custom_alert_action directory to your Splunk etc/apps folder:

Restart Splunk:

## 📊 Usage

Access Splunk Web and navigate to Alerts.

Create a new alert and select the Custom Alert Action.

Configure the action to block suspicious IPs or users.

## 🧰 Requirements

Splunk Enterprise (tested on version 9.2.0)

Python 3.x

AWS EC2 instances (for testing infrastructure)


## 🤝 Contributing

Feel free to open an issue or submit a pull request for improvements.

