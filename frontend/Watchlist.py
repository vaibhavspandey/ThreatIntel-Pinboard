import streamlit as st
import requests
import os
import re
from datetime import datetime

# Page config
st.set_page_config(page_title="TI Pinboard", page_icon="📌", layout="wide")

# Custom CSS for hacker look
st.markdown("""
<style>
    body {
        color: #00FF00;
    }
    .st-emotion-cache-1v0mbdj > img {
        border-radius: 0.5rem;
    }
    .st-emotion-cache-1avcm0n {
        background: rgba(0, 255, 0, 0.1);
    }
</style>
""", unsafe_allow_html=True)

# API base URL
API_BASE_URL = os.getenv("API_BASE_URL", "http://localhost:8000")

def extract_threat_actor(snapshot_json: dict, comments_text: str = "") -> str:
    """
    Extracts Threat Actor attribution from VirusTotal JSON and/or comment text
    using regex and specific VT JSON paths.
    """
    pattern = r'(?i)(APT-?\d+|UNC\d+|FIN\d+|Lazarus|Cozy Bear|Agent\s?Tesla|Emotet|Cobalt\s?Strike|TrickBot)'

    # Check VT JSON paths first
    vt_data = snapshot_json.get("virustotal", {}).get("data", {})
    if vt_data:
        attributes = vt_data.get("attributes", {})

        # 1. Check suggested threat label
        threat_label = attributes.get("popular_threat_classification", {}).get("suggested_threat_label", "")
        if threat_label:
            match = re.search(pattern, threat_label)
            if match:
                return match.group(0)

        # 2. Check crowdsourced YARA results
        yara_results = attributes.get("crowdsourced_yara_results", [])
        for yara in yara_results:
            rule_name = yara.get("rule_name", "")
            author = yara.get("author", "")
            description = yara.get("description", "")

            for text_to_check in [rule_name, author, description]:
                if text_to_check:
                    match = re.search(pattern, text_to_check)
                    if match:
                        return match.group(0)

    # 3. Check the provided comments text
    if comments_text:
        match = re.search(pattern, comments_text)
        if match:
            return match.group(0)

    return ""


@st.cache_data(ttl=300)
def fetch_pin_baseline(pin_id: int):
    """Fetch the latest baseline snapshot for a specific pin, cached to prevent N+1 API calls."""
    try:
        resp = requests.get(f"{API_BASE_URL}/api/internal/baseline/{pin_id}", timeout=10)
        if resp.status_code == 200:
            return resp.json().get("full_report_json", {})

    except requests.exceptions.RequestException:
        pass
    return {}

st.title(">> TI Pinboard_")

try:
    # Sidebar with API Status and View Selector
    with st.sidebar:
        # API Status Widget
        try:
            status_response = requests.get(f"{API_BASE_URL}/api/status", timeout=5)
            if status_response.status_code == 200:
                status_data = status_response.json()
                
                st.markdown("---")
                st.subheader("🔌 API Health & Status")
                
                # Helper function to render detailed status
                def render_api_status(name, data):
                    connected = data.get("connected", False)
                    message = data.get("message", "Unknown error")

                    if connected:
                        st.success(f"**{name}**: ✅ Connected")
                        if "Rate Limited" in message:
                            st.warning(f"⚠️ {message}")
                    else:
                        st.error(f"**{name}**: ❌ Disconnected")
                        st.caption(f"Reason: {message}")
                
                render_api_status("VirusTotal", status_data.get("virustotal", {}))
                st.markdown("")
                
                render_api_status("MalwareBazaar", status_data.get("malwarebazaar", {}))
                st.markdown("")

                render_api_status("urlscan.io", status_data.get("urlscan", {}))
                st.markdown("")

                render_api_status("Neiki TIP", status_data.get("neiki", {}))
                
                if st.button("🔄 Force Check API Status", use_container_width=True):
                    requests.get(f"{API_BASE_URL}/api/status?force=true", timeout=15)
                    st.rerun()

                st.markdown("---")
        except requests.exceptions.RequestException:
            st.markdown("---")
            st.warning("⚠️ Unable to check API status. Backend might be down.")
            st.markdown("---")
        
        # View selector
        view = st.radio("View", ["While you were away", "Manage Pinboards"], index=0)

    # Fetch alerts and boards once for all views
    alerts = []
    boards = []
    try:
        alerts_response = requests.get(f"{API_BASE_URL}/api/alerts", timeout=30)
        if alerts_response.status_code == 200:
            alerts = alerts_response.json()
        else:
            st.error(f"Failed to fetch alerts: {alerts_response.status_code}")

        boards_response = requests.get(f"{API_BASE_URL}/api/boards", timeout=30)
        if boards_response.status_code == 200:
            boards = boards_response.json()
        else:
            st.error("Could not fetch pinboards from the API.")
            
    except requests.exceptions.RequestException as e:
        st.error(f"API connection error: {e}")


    # Create a board_id to board_name map
    board_name_map = {board['id']: board['name'] for board in boards}

    # Separate comment alerts from main alerts
    comment_alerts = [alert for alert in alerts if alert['delta_data'].get('field') == 'new_vt_comment']
    domain_weaponized_alerts = [alert for alert in alerts if alert['delta_data'].get('field') == 'DOMAIN_WEAPONIZED']
    main_alerts = [alert for alert in alerts if alert['delta_data'].get('field') not in ('new_vt_comment', 'DOMAIN_WEAPONIZED')]
    
    # Main content
    if view == "While you were away":
        st.header("🚨 While you were away...")
        st.markdown("_Recent changes to your pinned items_")
        
        # Display DOMAIN_WEAPONIZED critical alerts prominently
        if domain_weaponized_alerts:
            for alert in domain_weaponized_alerts:
                pin = alert.get('pin', {})
                delta = alert.get('delta_data', {})
                board_name = board_name_map.get(pin.get('board_id'), 'Unknown Board')
                scan_id = delta.get('scan_id', 'Unknown')

                st.error(f"**🚨 CRITICAL THREAT: Domain Weaponized**\n\n"
                         f"On pinboard **{board_name}**, the domain **`{pin.get('ioc_value')}`** verdict changed to malicious!\n\n"
                         f"**Scan ID:** `{scan_id}`")
        left_col, right_col = st.columns([0.6, 0.4])

        with left_col:
            st.subheader("Activity Feed")
            if not main_alerts:
                st.info("No new activity to report. Add some pins to your pinboards to start monitoring!")
            else:
                # A function to make alert messages more readable
                def get_alert_message(alert: dict, board_map: dict) -> str:
                    delta = alert.get('delta_data', {})
                    pin = alert.get('pin', {})
                    field = delta.get('field', 'unknown')
                    old_val = delta.get('old', 'N/A')
                    new_val = delta.get('new', 'N/A')
                    value = delta.get('value', '')
                    board_name = board_map.get(pin.get('board_id'), 'Unknown Board')

                    header = f"On pinboard **{board_name}**, the {pin.get('ioc_type')} **`{pin.get('ioc_value')}`**:"

                    if field == 'new_urlscan_scan':
                        return f"{header} has a new urlscan.io scan."
                    elif field == 'new_resolution':
                        return f"{header} has a new DNS Resolution: `{value}`"
                    elif field == 'detection_ratio':
                        return f"{header} is now flagged by **{new_val}** VT vendors (previously {old_val})."
                    elif field == 'whois_updated':
                        return f"{header} had its WHOIS record updated."
                    elif field == 'new_communicating_files':
                        return f"{header} has new communicating files detected (Count: `{new_val}`)."
                    elif field == 'new_downloaded_files':
                        return f"{header} has new downloaded files detected (Count: `{new_val}`)."
                    elif field == 'new_mb_tag':
                        return f"{header} has a new MalwareBazaar Tag: `{value}`"
                    elif field == 'mb_signature_updated':
                        return f"{header} had its MalwareBazaar signature updated to `{new_val}`."
                    elif field == 'new_article':
                        return f"{header} was mentioned in a new article: \"{value}\""
                    elif field == 'neiki_reputation_change':
                        return f"{header} had its Neiki TIP reputation change from `{old_val}` to `{new_val}`."
                    elif field == 'neiki_new_associated_domain':
                        return f"{header} has a new associated domain on Neiki TIP: `{value}`."
                    elif field == 'neiki_new_threat_feed':
                        return f"{header} was listed on a new Neiki TIP threat feed: `{value}`."
                    else:
                        # Fallback for any other type
                        if value:
                            return f"{header} {field} - {value}"
                        else:
                            return f"{header} {field} changed from `{old_val}` to `{new_val}`"

                for alert in main_alerts:
                    timestamp = datetime.fromisoformat(alert['timestamp'].replace('Z', '+00:00'))
                    message = get_alert_message(alert, board_name_map)
                    st.info(f"[{timestamp.strftime('%Y-%m-%d %H:%M:%S')}] {message}")
        
        with right_col:
            st.subheader("🗣️ VT Community Intel")
            if not comment_alerts:
                st.write("No new VirusTotal comments.")
            else:
                for alert in comment_alerts:
                    pin = alert['pin']
                    value = alert['delta_data'].get('value', 'N/A')
                    board_name = board_name_map.get(pin.get('board_id'), 'Unknown Board')

                    # Extract TA attribution using the cached snapshot
                    snapshot_json = fetch_pin_baseline(pin['id'])
                    ta_attribution = extract_threat_actor(snapshot_json, value)

                    if ta_attribution:
                        st.warning(f"**`{pin['ioc_value']}`** on **{board_name}**\n\n**Possible Attribution ->** [{ta_attribution}]\n\n> {value}")
                    else:
                        st.warning(f"**`{pin['ioc_value']}`** on **{board_name}**\n\n> {value}")

    
    elif view == "Manage Pinboards":
        st.header("📌 Manage Pinboards")

        # Display existing boards
        if not boards:
            st.info("No pinboards yet. Create one below!")
        else:
            st.subheader("Your Pinboards")
            for board in boards:
                with st.container(border=True):
                    col1, col2 = st.columns([0.8, 0.2])
                    with col1:
                        st.subheader(f"📋 {board['name']}")
                    with col2:
                        if st.button("Delete Board", key=f"delete_{board['id']}", use_container_width=True):
                            resp = requests.delete(f"{API_BASE_URL}/api/boards/{board['id']}", timeout=30)
                            if resp.status_code == 200:
                                st.success(f"Board '{board['name']}' deleted.")
                                st.rerun()
                            else:
                                st.error("Failed to delete board.")

                    if board['pins']:
                        for pin in board['pins']:
                            status = "✅ Active" if pin['active'] else "❌ Inactive"
                            with st.expander(f"**`{pin['ioc_value']}`** ({pin['ioc_type']}) - {status}"):
                                baseline = fetch_pin_baseline(pin['id'])
                                full_report = baseline if isinstance(baseline, dict) else {}

                                # Extract community votes
                                mal_votes = 0
                                harm_votes = 0
                                try:
                                    vt_data = full_report.get("virustotal", {}).get("data", {}).get("attributes", {})
                                    votes = vt_data.get("total_votes", {})
                                    mal_votes = votes.get("malicious", 0)
                                    harm_votes = votes.get("harmless", 0)
                                except Exception:
                                    pass

                                st.markdown(f"**Community Sentiment:** 🔴 {mal_votes} Malicious | 🟢 {harm_votes} Harmless")
                    else:
                        st.write("No pins in this board.")
        
        st.markdown("---")

        st.subheader("Create New Pinboard")
        with st.form("create_board_form"):
            board_name = st.text_input("New Pinboard Name", key="new_pinboard_name_input")
            create_board_btn = st.form_submit_button("Create Pinboard")
            
            if create_board_btn and board_name:
                resp = requests.post(
                    f"{API_BASE_URL}/api/boards",
                    json={"name": board_name},
                    timeout=30
                )
                if resp.status_code == 200:
                    st.success(f"Pinboard '{board_name}' created!")
                    st.rerun()
                else:
                    st.error("Failed to create pinboard")

        if boards:
            st.markdown("---")
            st.subheader("Add New Pin")
            with st.form("add_pin_form"):
                ioc_value = st.text_input("IOC Value", placeholder="e.g., 1.2.3.4, example.com, or https://example.com", key="new_ioc_value")
                
                # Define display options and map them to API values
                ioc_type_options = {"ip": "ip", "domain/url": "domain", "hash": "hash", "keyword": "keyword"}
                selected_ioc_display = st.selectbox("Type", options=list(ioc_type_options.keys()))
                ioc_type = ioc_type_options[selected_ioc_display]

                # Use the boards list we already fetched
                board_options = {board['name']: board['id'] for board in boards}
                selected_board_name = st.selectbox("Pinboard", options=board_options.keys())
                submit_btn = st.form_submit_button("Add Pin")
                
                if submit_btn:
                    if not ioc_value:
                        st.error("Please enter an IOC value")
                    else:
                        resp = requests.post(
                            f"{API_BASE_URL}/api/pins",
                            json={
                                "board_id": board_options[selected_board_name],
                                "ioc_value": ioc_value,
                                "ioc_type": ioc_type
                            },
                            timeout=30
                        )
                        if resp.status_code == 200:
                            st.success("Pin added! The monitor will scan it shortly.")
                            st.rerun()
                        else:
                            error_msg = resp.json().get("detail", "Failed to add pin")
                            st.error(error_msg)

except requests.exceptions.RequestException as e:
    st.error(f"Connection error: {str(e)}. Is the backend running?")
