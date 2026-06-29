import streamlit as st
import streamlit.components.v1 as components
import subprocess
import pandas as pd
import numpy as np
import time
import os

# --- HARDCODED OUT-OF-THE-BOX CONFIGURATION ---
DOCKER_NET = "bbot-auto-net"
NEO4J_CONTAINER = "bbot-neo4j-db"
RUNNER_CONTAINER = "bbot-scan-runner" # Deterministic name to track execution state
NEO4J_URI = "bolt://localhost:7687"
NEO4J_DOCKER_URI = f"bolt://{NEO4J_CONTAINER}:7687"
NEO4J_USER = "neo4j"
NEO4J_PASS = "BBotAutoPass2026"
BBOT_IMAGE = "blacklanternsecurity/bbot:stable"

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False

try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False

st.set_page_config(page_title="BBOT Automated Commander", layout="wide", page_icon="🕷️")

# --- UTILITY: HELPER TO CHECK RUNNING SCANNER ---
def is_scanner_running():
    res = subprocess.run(
        ["docker", "ps", "--filter", f"name={RUNNER_CONTAINER}", "--format", "{{.Names}}"], 
        capture_output=True, text=True
    )
    return RUNNER_CONTAINER in res.stdout.strip()

# --- STATE INITIALIZATION ---
if "infra_ready" not in st.session_state:
    st.session_state.infra_ready = False

# --- AUTO INFRASTRUCTURE MANAGEMENT ---
if not st.session_state.infra_ready:
    with st.status("⚙️ Initializing automated environment (Docker, Neo4j)...", expanded=True) as status:
        try:
            net_check = subprocess.run(["docker", "network", "inspect", DOCKER_NET], capture_output=True, text=True)
            if net_check.returncode != 0:
                subprocess.run(["docker", "network", "create", DOCKER_NET], check=True)
            
            neo_check = subprocess.run(
                ["docker", "ps", "-a", "--filter", f"name={NEO4J_CONTAINER}", "--format", "{{.Status}}"], 
                capture_output=True, text=True
            )
            container_status = neo_check.stdout.strip()
            
            if not container_status:
                cmd = [
                    "docker", "run", "-d",
                    "--name", NEO4J_CONTAINER,
                    "--network", DOCKER_NET,
                    "-p", "7474:7474", "-p", "7687:7687",
                    "-e", f"NEO4J_AUTH={NEO4J_USER}/{NEO4J_PASS}",
                    "neo4j:latest"
                ]
                subprocess.run(cmd, check=True)
                time.sleep(5)
            elif "Up" not in container_status:
                subprocess.run(["docker", "start", NEO4J_CONTAINER], check=True)
                time.sleep(3)
                
            img_check = subprocess.run(["docker", "images", "-q", BBOT_IMAGE], capture_output=True, text=True)
            if not img_check.stdout.strip():
                subprocess.run(["docker", "pull", BBOT_IMAGE], check=True)
                
            st.session_state.infra_ready = True
            status.update(label="✅ Environment Setup Complete!", state="complete", expanded=False)
            
        except Exception as e:
            status.update(label="❌ Environment Setup Failed", state="error", expanded=True)
            st.error(f"Failed to bind Docker environments automatically: {e}")
            st.stop()

# --- SIDEBAR NAVIGATION ---
st.sidebar.title("🕷️ BBOT Engine")
st.sidebar.success("Environment Status: Healthy")
page = st.sidebar.radio("Navigation", ["Run Scan", "CSV Analytics", "Neo4j Analytics", "Help & Documentation"])

# --- PAGE: RUN SCAN ---
if page == "Run Scan":
    st.header("🚀 Execute BBOT Automated Scan")
    
    # Check background execution state
    scanner_active = is_scanner_running()
    
    if scanner_active:
        st.info("⚡ A background BBOT pipeline execution is currently active.")
        
        # STOP ACTION: Send SIGINT (Signal 2) to container for clean flush
        if st.button("🛑 Stop Scan Gracefully (Flush & Save Data)", type="primary"):
            with st.spinner("Sending SIGINT interruption signal. BBOT is flushing buffers to disk and database..."):
                subprocess.run(["docker", "kill", "--signal=SIGINT", RUNNER_CONTAINER])
                # Give BBOT a few seconds to finish its clean exit sequence
                for _ in range(5):
                    if not is_scanner_running():
                        break
                    time.sleep(1)
            st.success("Scan terminated cleanly. All data preserved.")
            st.rerun()
            
        st.subheader("📋 Real-time Pipeline Logs")
        output_box = st.empty()
        
        # Loop dynamically to display logs without locking UI interactions
        while is_scanner_running():
            log_check = subprocess.run(["docker", "logs", "--tail", "25", RUNNER_CONTAINER], capture_output=True, text=True)
            output_box.code(log_check.stdout + log_check.stderr, language="bash")
            time.sleep(1)
        
        st.success("Background scan execution has stopped. You can now analyze results in the data tabs.")
        
    else:
        # Standard configuration layout when idle
        BBOT_FLAGS = ["subdomain-enum", "passive", "active", "safe", "cloud-enum", "code-enum", "web-basic", "web-heavy"]
        BBOT_MODULES = ["httpx", "gowitness", "nuclei", "nmap", "wappalyzer", "dnsbrute"]
            
        col1, col2 = st.columns(2)
        with col1:
            target = st.text_input("Target Domain/IP", value="example.com")
            scan_name = st.text_input("Scan Name Identifier", value="auto_scan")
        with col2:
            selected_flags = st.multiselect("Scan Profiles (Flags)", options=BBOT_FLAGS, default=["subdomain-enum"])
            selected_modules = st.multiselect("Specific Tool Modules", options=BBOT_MODULES)
            
        custom_args = st.text_input("Additional Parameters", value="--allow-deadly")
        
        if st.button("Launch Scan Pipeline", type="primary"):
            host_output_dir = os.path.join(os.getcwd(), "bbot_outputs")
            os.makedirs(host_output_dir, exist_ok=True)

            # Added "-d" (detached) and explicit unique container name
            cmd = [
                "docker", "run", "-d", "--rm",
                "--name", RUNNER_CONTAINER,
                "--network", DOCKER_NET,
                "-v", f"{host_output_dir}:/root/.bbot/scans",
                BBOT_IMAGE
            ]
            
            for t in target.split(","):
                if t.strip(): cmd.extend(["-t", t.strip()])
                
            if scan_name: cmd.extend(["-n", scan_name])
            if selected_flags: cmd.extend(["-f"] + selected_flags)
            if selected_modules: cmd.extend(["-m"] + selected_modules)
            if custom_args: cmd.extend(custom_args.split())
            
            cmd.extend(["-om", "csv", "neo4j"])
            neo_conf = f"modules.neo4j.uri={NEO4J_DOCKER_URI} modules.neo4j.username={NEO4J_USER} modules.neo4j.password={NEO4J_PASS}"
            cmd.extend(["-c"] + neo_conf.split())

            # Spawn detached background container
            subprocess.run(cmd, check=True)
            st.rerun()

# --- PAGE: CSV ANALYTICS ---
elif page == "CSV Analytics":
    st.header("📊 Native CSV Data Science Table")
    output_dir = os.path.join(os.getcwd(), "bbot_outputs")
    
    if not os.path.exists(output_dir):
        st.warning("No output directory found. Run a scan first.")
    else:
        scan_folders = [f for f in os.listdir(output_dir) if os.path.isdir(os.path.join(output_dir, f))]
        if not scan_folders:
            st.info("Scan directory is empty. Run a scan to generate data.")
        else:
            selected_scan = st.selectbox("Select Scan Result", scan_folders)
            csv_path = os.path.join(output_dir, selected_scan, "output.csv")
            
            if os.path.exists(csv_path):
                df = pd.read_csv(csv_path)
                col1, col2, col3 = st.columns(3)
                col1.metric("Discovered Nodes", len(df))
                
                if 'type' in df.columns:
                    unique_types = np.unique(df['type'].astype(str))
                    col2.metric("Unique Signatures", len(unique_types))
                    df['is_critical'] = np.where(df['type'].str.contains('VULN|SECRETS|HIJACK', case=False, na=False), True, False)
                    col3.metric("Critical Exploits/Vulns", df['is_critical'].sum())
                    st.subheader("Asset Layout Metrics")
                    st.bar_chart(df['type'].value_counts())

                st.subheader("Interactive Pandas Data Matrix Frame")
                st.dataframe(df, use_container_width=True)
            else:
                st.error(f"Could not find completed `output.csv` in {selected_scan}. (Is the scan still running?)")

# --- PAGE: NEO4J ANALYTICS ---
elif page == "Neo4j Analytics":
    st.header("🕸️ Native Neo4j Automated Visual Graph Layout")
    if not (NEO4J_AVAILABLE and PYVIS_AVAILABLE):
        st.error("Engine missing target visualization components. Run: `pip install neo4j pyvis`")
        st.stop()
        
    status_box = st.empty()
    try:
        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASS))
        with driver.session() as session:
            node_count = session.run("MATCH (n) RETURN count(n) as count").single()["count"]
            edge_count = session.run("MATCH ()-[r]->() RETURN count(r) as count").single()["count"]
            
        status_box.success(f"✅ Connection Active! The database currently holds **{node_count} nodes** and **{edge_count} relationships**.")
        
        with st.expander("⚠️ Database Management (Purge Old Data)"):
            if st.button("🚨 Wipe Entire Neo4j Database", type="primary"):
                with driver.session() as session:
                    session.run("MATCH (n) DETACH DELETE n")
                st.success("Database purged successfully!")
                st.rerun()

        if node_count > 0:
            st.markdown("---")
            col1, col2 = st.columns([1, 2])
            with col1:
                view_mode = st.selectbox("Select Asset Filter", ["Full Discovery", "DNS & IP Infrastructure Only", "High Value (Vulnerabilities & Findings)"])
            with col2:
                target_filter = st.text_input("Isolate Target Domain/String (Leave blank for all)", placeholder="e.g. google.com")
            
            if st.button("Render Graph Map", type="primary"):
                with st.spinner("Mapping topography..."):
                    with driver.session() as session:
                        base_match = "MATCH (n)-[r]->(m)"
                        conditions = []
                        if view_mode == "DNS & IP Infrastructure Only":
                            conditions.append("('DNS_NAME' IN labels(n) OR 'IP_ADDRESS' IN labels(n))")
                        elif view_mode == "High Value (Vulnerabilities & Findings)":
                            conditions.append("('VULN' IN labels(n) OR 'FINDING' IN labels(n))")
                        if target_filter:
                            conditions.append(f"(n.name CONTAINS '{target_filter}' OR m.name CONTAINS '{target_filter}' OR n.data CONTAINS '{target_filter}' OR m.data CONTAINS '{target_filter}')")

                        query = base_match + (" WHERE " + " AND ".join(conditions) if conditions else "") + " RETURN n, r, m LIMIT 400"
                        result = session.run(query)
                        
                        net = Network(height='700px', width='100%', directed=True, bgcolor="#0E1117", font_color="white")
                        net.force_atlas_2based(spring_length=120)
                        
                        node_count_rendered = 0
                        for record in result:
                            n, r, m = record["n"], record["r"], record["m"]
                            n_props, m_props = dict(n), dict(m)
                            n_label, m_label = list(n.labels)[0] if n.labels else "Unknown", list(m.labels)[0] if m.labels else "Unknown"
                            n_title, m_title = str(n_props.get("name", n_props.get("data", n_label))), str(m_props.get("name", m_props.get("data", m_label)))
                            n_id, m_id = str(n.element_id), str(m.element_id)
                            
                            color_map = {"DNS_NAME": "#1f77b4", "IP_ADDRESS": "#ff7f0e", "VULN": "#d62728", "FINDING": "#d62728", "URL": "#2ca02c"}
                            net.add_node(n_id, label=n_title, title=str(n_props), color=color_map.get(n_label, "#9467bd"))
                            net.add_node(m_id, label=m_title, title=str(m_props), color=color_map.get(m_label, "#9467bd"))
                            net.add_edge(n_id, m_id, title=r.type)
                            node_count_rendered += 1
                        
                        if node_count_rendered == 0:
                            st.warning("No connections found matching your filters.")
                        else:
                            html_str = net.generate_html()
                            components.html(html_str, height=720, scrolling=True)
    except Exception as e:
        status_box.error(f"❌ Connection Error: {e}")

# --- PAGE: HELP & DOCUMENTATION ---
elif page == "Help & Documentation":
    st.header("📖 BBOT Commander Documentation")
    st.markdown("This dashboard provisions an isolated bridge network, runs detached scanners ephemerally, and hooks metrics natively to disk.")