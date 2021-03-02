import requests


class NessusClient:


    def __init__(self, server: str, username: str = None, password: str = None, 
                 access_key: str = None, secret_key: str = None, verify_cert=True):
        """Instance construction. Need to either supply username/password combo or API keys.
           If using API Keys, there is no need to deal with the /session set of resources.

        Args:
            server (str): Server:port combination (IE, https://server:8834)
            username (str): Username with which to login.
            password (str): Password associated with above username.
            access_key (str): accessKey created via UI or /session/keys endpoint.
            secret_key (str): secretKey created via UI or /session/keys endpoint.
            verify_cert (bool, optional): [description]. Defaults to True.
        """

        self.username = username
        self.password = password
        self.base_url = server
        self.session = requests.session()
        self.session.verify = verify_cert

        if access_key and secret_key:
            self.session.headers = {"X-ApiKeys": f"accessKey={access_key}; secretKey={secret_key}"}


    def session_create(self):
        """
        Only usable if you've supplied a username and password during initial instantiation.
        """

        payload = {
            "username": self.username,
            "password": self.password
        }

        response = self.session.post(self.base_url + "/session", json=payload)

        if response.status_code == 200:
            self.session.headers["X-Cookie"] = f'token={response.json()["token"]};'
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)


    def server_properties(self):
        """
        Retrieve server version and other properties.
        """

        response = self.session.get(self.base_url + "/server/properties")

        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)

    
    def server_status(self):
        """
        Retrieve server status (loading, ready, corrupt-db, feed-expired, eval-expired, locked,
        register, register-locked, download-failed, feed-error).
        """

        response = self.session.get(self.base_url + "/server/status")

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 503:
            return {
                "status": "503 - Session Destroy required."
            }
    

    def server_health_alerts(self, end_time: int = None, start_time: int = None):
        """
        List alerts created by the scanner regarding its overall health.

        Args:
            end_time (int, optional): End time for historical data (unixtime); defaults to now.
            start_time (int, optional): Start time for historical data (unixtime); defaults to 24 hrs ago.
        """

        params = {}

        if end_time:
            params["end_time"] = end_time
        if start_time:
            params["start_time"] = start_time

        response = self.session.get(self.base_url + "/settings/health/alerts", params=params)

        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)

    
    def scans_attachment(self, scan_id: str, attachment_id: str, key: str):
        """
        Retrieve requested scan attachment file.

        Args:
            scan_id (str): ID of the scan containing the attachment.
            attachment_id (str): ID of the scan attachment.
            key (str): Attachment access token.
        """

        response = self.session.get(self.base_url + f"/scans/{scan_id}/attachments/{attachment_id}")

        if response.status_code == 200:
            return response.content
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)
    

    def scans_configure(self, scan_id: int, uuid: str, settings: dict):
        """
        Remotely configure schedule and/or policy parameters of a scan.

        Args:
            scan_id (int): ID of the scan to change.
            uuid (str): UUID for the editor template to use.
            kwargs (dict): 
        """
        
        payload = {
            "uuid": uuid,
            "settings": settings
        }

        response = self.session.put(self.base_url + f"/scans/{scan_id}", data=payload)

        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)

    
    def scans_details(self, scan_id: int):
        """
        Retrieve details for a given scan based on ID.

        Args:
            scan_id (int): ID of scan to retrieve.
        """

        response = self.session.get(self.base_url + f"/scans/{scan_id}")

        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)

    
    def scans_export_formats(self, scan_id: int):
        """
        Retrieve available export formats and report options.

        Args:
            scan_id (int): ID of scan to export.
        """

        response = self.session.get(self.base_url + f"/scans/{scan_id}/export/formats")

        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)
    

    def scans_export_download(self, scan_id: int, file_id: int):
        """
        Download an exported scan. Use this method in conjunction with scans_export_request().

        Args:
            scan_id (int): ID of scan to export.
            file_id (int): ID of file to download (retrieved from scans_export_request() method).
        """

        response = self.session.get(self.base_url + f"/scans/{scan_id}/export/{file_id}/download")

        if response.status_code == 200:
            return response.content
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)

    
    def scans_export_request(self, scan_id: int, format: str, scan_info: bool = True, host_info: bool = True, base_score: bool = True,
                             synopsis: bool = True, description: bool = True, see_also: bool = True, solution: bool = True, temporal_score: bool = True,
                             risk_factor: bool = True, base_score_v3: bool = True, temporal_score_v3: bool = True, stig: bool = True,
                             references: bool = True, exploitable_with: bool = True, plugin_info: bool = True, plugin_output: bool = True):
        """
        Export a given scan using its ID.

        Args:
            scan_id (int): ID of scan to export.
            format (str): File format to use (Nessus, HTML, PDF, CSV, or DB).
        """

        payload = {
                    "format": format,
                    "reportContents":
                        {
                         "hostSections":
                            {
                             "host_information": host_info,
                             "scan_information": scan_info
                             },
                         "vulnerabilitySections":
                            {
                             "description": description,
                             "see_also": see_also,
                             "solution": solution,
                             "risk_factor": risk_factor,
                             "cvss_base_score": base_score,
                             "cvss_temporal_score": temporal_score,
                             "cvss3_base_score": base_score_v3,
                             "cvss3_temporal_score": temporal_score_v3,
                             "stig_severity": stig,
                             "references": references,
                             "exploitable_with": exploitable_with,
                             "plugin_information": plugin_info,
                             "plugin_output": plugin_output
                             }
                        }
                    }

        response = self.session.post(self.base_url + f"/scans/{scan_id}/export", data=payload)

        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)
    

    def scans_export_status(self, scan_id: int, file_id: int):
        """
        Check the file status of an exported scan.

        Args:
            scan_id (int): ID of requested scan.
            file_id (int): ID of file to poll.
        """

        response = self.session.get(self.base_url + f"/scans/{scan_id}/export/{file_id}/status")

        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)

    
    def scans_host_details(self, scan_id: int, host_id: int):
        """
        Retrieve details for a given host.

        Args:
            scan_id (int): ID of scan to retrieve.
            host_id (int): ID of the host to retrieve.
        """

        response = self.session.get(self.base_url + f"/scans/{scan_id}/hosts/{host_id}")

        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)

    
    def scans_list(self, folder_id: int = None, last_mod_date: int = None):
        """
        Retrieve the scan list.

        Args:
            folder_id (int): ID of folder whose scans should be listed.
            last_mod_date (int): Limit results to those that have only changed since this time.
        """

        params = {
            "folder_id": folder_id,
            "last_modification_date": last_mod_date
        }

        response = self.session.get(self.base_url + "/scans", params=params)

        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)

    
    def scans_plugin_output(self, scan_id: int, host_id: int, plugin_id: int, history_id: int = None):
        """
        Retrieve output for a given plugin.

        Args:
            scan_id (int): ID of scan to retrieve.
            host_id (int): ID of the host to retrieve.
            plugin_id (int): ID of plugin to retrieve.
            history_id (int, optional): Historical_ID of the historical data to retrieve.
        """

        params = {"history_id": history_id} if history_id else None

        response = self.session.get(self.base_url + f"/scans/{scan_id}/hosts/{host_id}/plugins/{plugin_id}",
                                    params=params)
        
        if response.status_code == 200:
            return response.json()
        else:
            print(response.status_code, "\n", response.headers, "\n", response.text)
