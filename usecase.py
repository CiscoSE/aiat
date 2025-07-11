Copyright (c) {{current_year}} Cisco and/or its affiliates.

This software is licensed to you under the terms of the Cisco Sample
Code License, Version 1.1 (the "License"). You may obtain a copy of the
License at

               https://developer.cisco.com/docs/licenses

All use of the material herein must be in accordance with the terms of
the License. All rights not expressly granted by the License are
reserved. Unless required by applicable law or agreed to separately in
writing, software distributed under the License is distributed on an "AS
IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
or implied.

import os
import json
import re
import logging
import threading
import requests
from flask import Flask, request, jsonify

from langchain_ollama import OllamaLLM
from tetpyclient import RestClient
import lib.zammadhandler as zmhandler

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("myapp")

# ---- Configurable Parameters (set as environment variables or config files) ----
APIC_URL = os.environ.get("APIC_URL", "https://apic.example.com")
APIC_USER = os.environ.get("APIC_USER", "your_apic_user")
APIC_PASS = os.environ.get("APIC_PASS", "your_apic_password")

CSW_API_URL = os.environ.get("CSW_API_URL", "https://csw.example.com")
CSW_CRED_FILE = os.environ.get("CSW_CRED_FILE", "./credentials.json")
WORKLOAD_ID = os.environ.get("WORKLOAD_ID", "YOUR_WORKLOAD_ID")

FW_API_URL = os.environ.get("FW_API_URL", "http://fw.example.com:9000")
FW_USER = os.environ.get("FW_USER", "your_fw_user")
FW_PASS = os.environ.get("FW_PASS", "your_fw_password")
FIREWALL_SOURCE = os.environ.get("FIREWALL_SOURCE", "your_firewall_source")

OLLAMA_URL = os.environ.get("OLLAMA_URL", "http://127.0.0.1:11434")
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwq:32b")


def gatherdata(ip):
    """Retrieve endpoint, tracker, and switch info from Cisco APIC."""
    auth_endpoint = f"{APIC_URL}/api/aaaLogin.json"
    login_payload = {"aaaUser": {"attributes": {"name": APIC_USER, "pwd": APIC_PASS}}}
    epinfo, trackerinfo, switchinfo = {}, {}, {}

    try:
        with requests.Session() as session:
            auth_response = session.post(auth_endpoint, json=login_payload, verify=False)  # Consider setting verify=True for production!
            if auth_response.status_code != 200:
                logger.error(f"APIC authentication failed: {auth_response.status_code}")
                return epinfo, trackerinfo, switchinfo

            event_url = (
                f'{APIC_URL}/api/node/class/fvCEp.json?rsp-subtree=full&rsp-subtree-include=required&'
                f'rsp-subtree-filter=eq(fvIp.addr,"%s")' % ip
            )
            ep_response = session.get(event_url, verify=False)
            if ep_response.status_code != 200:
                logger.warning(f"Failed to get endpoint info: {ep_response.status_code}")
                return epinfo, trackerinfo, switchinfo

            epinfo = ep_response.json()
            if not epinfo.get("imdata"):
                logger.warning("No endpoint data found")
                return epinfo, trackerinfo, switchinfo

            ep_attr = epinfo["imdata"][0]["fvCEp"]["attributes"]
            ep_dn = ep_attr.get("dn")
            fabric_path = ep_attr.get("fabricPathDn", "").split("/")
            if len(fabric_path) < 3:
                logger.warning("Fabric path info incomplete")
                return epinfo, trackerinfo, switchinfo
            path = f"{fabric_path[0]}/{fabric_path[1]}/{fabric_path[2].replace('paths','node')}"

            tracker_url = f"{APIC_URL}/mqapi2/troubleshoot.eptracker.json?ep={ep_dn}&page=0&page-size=15"
            tracker_response = session.get(tracker_url, verify=False)
            if tracker_response.status_code == 200:
                trackerinfo = tracker_response.json().get("imdata", [])[:15]

            switch_url = f"{APIC_URL}/api/node/class/{path}/eventRecord.json"
            params = {"page": 0, "page-size": 50, "order-by": "eventRecord.created|desc", "time-range": "24h"}
            switch_response = session.get(switch_url, params=params, verify=False)
            if switch_response.status_code == 200:
                switchinfo = switch_response.json().get("imdata", [])[:15]

    except Exception as e:
        logger.exception(f"Exception during APIC data gathering: {e}")

    return epinfo, trackerinfo, switchinfo


def getSecData(ip):
    """Get Secure Workload vulnerabilities and firewall logs for an IP."""
    filtered, extra = [], []

    try:
        restclient = RestClient(CSW_API_URL, credentials_file=CSW_CRED_FILE, verify=False)
        resp = restclient.get(f'/workload/{WORKLOAD_ID}/vulnerabilities')
        if resp.text:
            try:
                vulnerabilities = resp.json()
                filtered = [f for f in vulnerabilities if f.get("cvm_severity") == "HIGH"]
            except Exception:
                logger.warning(f"Failed to parse Secure Workload API response")
        else:
            logger.warning("Empty Secure Workload API response")

        headers = {
            'content-type': 'application/json',
            'X-Requested-By': 'Nodered',
            'Accept': 'application/json'
        }
        fw_query = {
            "queries": [{
                "timerange": {"from": 300, "type": "relative"},
                "query": {
                    "type": "elasticsearch",
                    "query_string": f"source:{FIREWALL_SOURCE} AND {ip}"
                },
                "search_types": [
                    {
                        "type": "messages",
                        "name": "rows",
                        "limit": 150,
                        "offset": 0,
                        "sort": [{"field": "timestamp", "order": "DESC"}]
                    },
                    {
                        "type": "pivot",
                        "name": "chart",
                        "series": [{"type": "count", "id": "count()", "field": None}],
                        "row_groups": [{
                            "type": "time",
                            "fields": ["timestamp"],
                            "interval": {"type": "auto", "scaling": 1.0}
                        }],
                        "sort": [],
                        "rollup": True
                    }
                ]
            }],
            "parameters": []
        }
        with requests.Session() as session:
            session.auth = (FW_USER, FW_PASS)
            searchexp = session.post(f"{FW_API_URL}/api/views/search", headers=headers, json=fw_query)
            if searchexp.status_code == 200:
                search_data = searchexp.json()
                messages = []
                try:
                    queryid = search_data["queries"][0]["id"]
                    search_types = search_data["queries"][0]["search_types"]
                    linesid = search_types[0]["id"]
                    result_url = f"{FW_API_URL}/api/views/search/{search_data['id']}/execute"
                    search = session.post(result_url, headers=headers, json=fw_query)
                    if search.status_code == 200:
                        result_json = search.json()
                        messages = result_json["results"][queryid]["search_types"][linesid]["messages"]
                except Exception as e:
                    logger.warning(f"FW logs parse exception: {e}")
                extra = [msg["message"]["full_message"] for msg in messages[:20]]
    except Exception as e:
        logger.exception(f"Exception during Secure Workload or FW log retrieval: {e}")

    return filtered, extra


def run_after_response(data):
    """Background: ACI data retrieval, LLM analysis, and ticket update."""
    try:
        zm = zmhandler.Zammad()
        zm.updateTicket(data["ticket"]["id"], "In bearbeitung")

        epinfo, trackerinfo, switchinfo = gatherdata(data["article"]["body"])
        if not epinfo or not trackerinfo or not switchinfo:
            logger.warning("Incomplete ACI data")
            return

        combined_input = (
            f"Endpoint Information:\n{json.dumps(epinfo, indent=4)}\n\n"
            f"Tracker Information:\n{json.dumps(trackerinfo, indent=4)}\n\n"
            f"Switch Information:\n{json.dumps(switchinfo, indent=4)}"
        )

        model = OllamaLLM(
            base_url=OLLAMA_URL,
            model=OLLAMA_MODEL,
            num_ctx=32000
        )
        question = (
            f"Analyze and provide detailed insights based on the following ACI data:\n{combined_input}\n\n"
            "Please structure your response with clear sections and bullet points, focusing on:\n"
            "- Key findings from endpoint information\n"
            "- Notable events from tracker information\n"
            "- Significant issues in switch information\n"
        )
        result = model.invoke(question)
        final_answer = re.sub(r"<think>.*?</think>", "", result, flags=re.DOTALL).strip()
        zm.updateTicket(data["ticket"]["id"], final_answer)
    except Exception as e:
        logger.exception(f"Error in run_after_response: {e}")


def sec_response(data):
    """Background: Security workload data retrieval, LLM analysis, and ticket update."""
    try:
        zm = zmhandler.Zammad()
        cswdata, fwlogs = getSecData(data["article"]["body"])
        combined_input = (
            f"CVS Information:\n{json.dumps(cswdata, indent=4)}\n\n"
            f"Firewall Logs Information:\n{json.dumps(fwlogs, indent=4)}\n\n"
        )
        model = OllamaLLM(
            base_url=OLLAMA_URL,
            model=OLLAMA_MODEL,
            num_ctx=32000
        )
        question = (
            "You are a senior security analyst working in a SOC.\n"
            "You receive two sets of data:\n"
            "Firewall logs for a VM\n"
            "Vulnerability data from Cisco Secure Workload for that same VM\n"
            "Write a human-style, natural-language analysis for a security incident or vulnerability management ticket. "
            "The output should be professional and concise. Include overview, correlations, risks, remediation, severity, and optional next steps.\n"
            f"Format as SOC ticket note (no bullet points or tables, just natural text):\n{combined_input}\n"
        )
        result = model.invoke(question)
        final_answer = re.sub(r"<think>.*?</think>", "", result, flags=re.DOTALL).strip()
        zm.updateTicket(data["ticket"]["id"], final_answer)
    except Exception as e:
        logger.exception(f"Error in sec_response: {e}")


@app.route('/incoming', methods=['POST'])
def incoming():
    """Main webhook endpoint for ticket events."""
    try:
        data = request.get_json(force=True)
        ticket_id = data.get("ticket", {}).get("id")
        body = data.get("article", {}).get("body")
        logger.info(f"Received event for ticket {ticket_id}, body: {body}")

        # Kick off background processing threads
        threading.Thread(target=run_after_response, args=(data,), daemon=True).start()
        threading.Thread(target=sec_response, args=(data,), daemon=True).start()

        return jsonify({"status": "received"}), 200
    except Exception as e:
        logger.exception("Error in /incoming endpoint")
        return jsonify({"error": "Internal server error"}), 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=False)



