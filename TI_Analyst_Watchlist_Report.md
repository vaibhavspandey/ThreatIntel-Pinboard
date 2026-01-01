## TI Analyst's Watchlist: A Comprehensive Report

### 1. What is it?
The TI Analyst's Watchlist is a web-based application designed to help cybersecurity analysts monitor Threat Intelligence (TI) indicators of compromise (IOCs) across various external data sources. It provides a centralized platform for tracking, enriching, and alerting on changes related to specific IPs, domains, file hashes, and keywords.

### 2. What does it do?
At its core, the TI Analyst's Watchlist allows users to:
*   **Create and Manage Pinboards:** Organize IOCs into logical groups (pinboards).
*   **Add and Monitor IOCs:** Input IPs, domains, hashes (SHA1, SHA256), and keywords for continuous monitoring.
*   **Automated Enrichment:** Periodically query multiple threat intelligence APIs (VirusTotal, MalwareBazaar, urlscan.io, Neiki TIP) and RSS feeds to gather fresh data for pinned IOCs.
*   **Delta Detection & Alerting:** Compare newly fetched data against a stored baseline. If significant changes (deltas) are detected (e.g., increased detection ratios, new DNS resolutions, updated WHOIS, new associated files/tags/comments), the system generates an alert.
*   **Activity Feed:** Provides a "While you were away" dashboard to quickly review recent alerts and community intelligence (VirusTotal comments).

### 3. How does it work? (Technical Overview)
The application follows a microservices architecture orchestrated with Docker Compose:

*   **Frontend (Streamlit):** A Python-based web interface built with Streamlit provides the user-friendly dashboard for managing pinboards, adding IOCs, and viewing alerts.
*   **Backend (FastAPI):** A Python-based API server handles all data persistence and business logic. It stores user data (pinboards, pins, snapshots, alerts) in a PostgreSQL database. It also exposes internal endpoints consumed by the monitor service.
*   **Monitor (Python):** A separate Python service that runs on a recurring schedule (hourly).
    *   It fetches all active IOCs from the backend.
    *   For each IOC, it uses a `connectors` module to query external TI APIs (VirusTotal, MalwareBazaar, urlscan.io, Neiki TIP) and RSS feeds. It implements basic rate-limiting to respect API usage policies.
    *   The fetched data is then passed to a `delta_engine` module, which compares it against the last known state (baseline snapshot) stored in the backend.
    *   If the `delta_engine` identifies significant changes, it sends a request to the backend to create a new `Alert` entry.
    *   A new snapshot of the latest enrichment data is always saved to the backend.
*   **Database (PostgreSQL):** Stores all application data, including user definitions, pinboards, IOCs, historical snapshots of enrichment data, and generated alerts.

### 4. Why is it important? (Significance)
This tool is important because it automates a critical, time-consuming, and often manual task for cybersecurity analysts: staying up-to-date on changes to known or suspected malicious indicators. Without such a tool, analysts would need to manually check multiple sources repeatedly, leading to potential delays in detection and response.

### 5. Is it really useful in the industry? What problems does it solve for the TI industry?
Yes, this type of tool is highly useful and representative of capabilities found in commercial and open-source Threat Intelligence Platforms (TIPs). It solves several key problems for the TI industry:

*   **Analyst Overload & Burnout:** Automates repetitive monitoring tasks, freeing up analysts to focus on deeper analysis, threat hunting, and incident response.
*   **Timely Detection:** Ensures that changes in IOC status are detected and alerted upon quickly, reducing the window of opportunity for adversaries.
*   **Comprehensive Visibility:** Consolidates information from disparate sources (multiple TI feeds, sandboxes, OSINT) into a single pane of glass, providing a more complete picture of an IOC's reputation.
*   **Historical Context:** By storing snapshots, it builds a historical record of an IOC's characteristics, crucial for understanding evolving threats and adversary tactics.
*   **Proactive Defense:** Enables organizations to proactively identify and mitigate risks associated with IOCs that may become more malicious over time or reveal new attack infrastructure.
*   **Reduces "Blind Spots":** By checking multiple sources, it helps ensure that a threat isn't missed because one source hasn't updated yet.

### 6. Who is the target audience?
The primary target audience includes:
*   **Threat Intelligence Analysts:** Individuals responsible for researching, analyzing, and disseminating threat information.
*   **Security Operations Center (SOC) Analysts:** Professionals who monitor security systems for alerts and respond to incidents.
*   **Incident Responders:** Teams that handle cybersecurity incidents from detection to resolution.
*   **Malware Analysts:** Specialists who examine malicious software to understand its behavior and purpose.
*   **Anyone monitoring specific IPs, domains, or hashes for changes in their threat profile.**

### 7. What feature additions can be done in the future?
Based on common TIP functionalities and the discussions we had, here are some potential future feature additions:

*   **Threat Timelines View:** (As discussed) A dedicated graphical view to visualize the chronological order of detection events across different platforms for a given IOC, highlighting which platform flagged it first. This provides valuable "competitive intelligence" on threat data sources.
*   **"Last Scanned" Timestamp:** (As discussed) Displaying the precise time an IOC was last scanned directly within the pin details.
*   **Enhanced IOC Management:**
    *   **IOC Tagging:** Allow users to add custom tags to IOCs for better categorization and searching.
    *   **IOC Search & Filtering:** Robust search functionality across all IOCs, pinboards, and alerts.
    *   **IOC Status (Active/Inactive):** Ability to easily toggle an IOC's active monitoring status.
*   **Advanced Alerting:**
    *   **Configurable Alert Thresholds:** Allow users to define what constitutes a "significant change" (e.g., alert only if VirusTotal detection ratio increases by more than 5 vendors).
    *   **Notification Channels:** Integration with communication platforms like Slack, Microsoft Teams, or email for instant alert delivery.
*   **User Management & RBAC:** For multi-user environments, implement user authentication, authorization, and Role-Based Access Control (RBAC) to manage permissions.
*   **API Key Management:** A secure, in-app interface for users to manage their API keys for external services, rather than relying solely on environment variables.
*   **More Enrichment Sources:** Integrate with additional TI feeds, open-source intelligence (OSINT) tools, or commercial sandboxing solutions.
*   **Automated Actioning:** Based on certain alert criteria, trigger automated actions (e.g., block IP on firewall, submit hash to internal sandbox).
*   **Reporting & Analytics:** Generate reports on trending IOCs, most active pinboards, or API source effectiveness.
*   **Threat Scoring:** Implement a customizable scoring mechanism to assign a threat score to IOCs based on various enrichment data points.
*   **Enhanced UI/UX:** Improvements to the dashboard, potentially interactive elements for drilling down into snapshots and deltas.
*   **Manual Trigger for Scan:** Allow users to manually initiate an on-demand scan for a specific IOC outside the hourly schedule.
*   **Detailed Snapshot View:** Provide a detailed view of the raw JSON snapshot data for an IOC at different points in time, allowing analysts to compare manually.