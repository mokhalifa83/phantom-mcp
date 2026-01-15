"""
👻 PHANTOM - Port Scanner

Advanced port scanning using nmap.
"""

import asyncio
from typing import Dict, List, Any, Optional
import nmap

from phantom.logger import get_logger
from phantom.config import PhantomConfig

logger = get_logger("phantom.recon.scanner")


class PortScanner:
    """Port scanning functionality using nmap."""
    
    def __init__(self, config: PhantomConfig):
        """
        Initialize port scanner.
        
        Args:
            config: PHANTOM configuration
        """
        self.config = config
        self.nm = None
        try:
            self.nm = nmap.PortScanner()
            logger.info("Port scanner initialized")
        except Exception as e:
            logger.warning(f"Port scanner initialization failed (nmap not found?): {e}")
            self.nm = None
    
    async def scan(
        self,
        target: str,
        ports: str = "1-1000",
        scan_type: str = "syn",
    ) -> Dict[str, Any]:
        """
        Scan target for open ports.
        
        Args:
            target: IP address or hostname
            ports: Port range (e.g., "1-1000", "80,443")
            scan_type: Type of scan (syn, tcp, udp, intense)
            
        Returns:
            Dictionary containing scan results
            
        Raises:
            RuntimeError: If scan fails
        """
        if not self.nm:
            raise RuntimeError("Nmap not installed or not found in PATH")
            
        logger.info(f"Starting {scan_type} scan on {target}, ports: {ports}")
        
        # Map scan types to nmap arguments
        scan_args = {
            "syn": "-sS",
            "tcp": "-sT",
            "udp": "-sU",
            "intense": "-T4 -A -v",
            "quick": "-T4 -F",
        }
        
        nmap_args = scan_args.get(scan_type, "-sS")
        
        # Add speed setting from config
        speed = self.config.scan.nmap_speed
        if "T" not in nmap_args:
            nmap_args += f" -T{speed}"
        
        try:
            # Run scan in executor to avoid blocking
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.nm.scan(target, ports, arguments=nmap_args)
            )
            
            # Parse results
            results = {
                "target": target,
                "scan_type": scan_type,
                "ports_scanned": ports,
                "open_ports": [],
                "filtered_ports": [],
                "closed_count": 0,
            }
            
            if target in self.nm.all_hosts():
                host_data = self.nm[target]
                
                # Get host status
                results["host_status"] = host_data.state()
                
                # Get open ports
                for proto in host_data.all_protocols():
                    ports_data = host_data[proto]
                    for port in ports_data.keys():
                        port_info = ports_data[port]
                        state = port_info["state"]
                        
                        port_detail = {
                            "port": port,
                            "protocol": proto,
                            "state": state,
                            "service": port_info.get("name", "unknown"),
                            "version": port_info.get("version", ""),
                            "product": port_info.get("product", ""),
                        }
                        
                        if state == "open":
                            results["open_ports"].append(port_detail)
                        elif state == "filtered":
                            results["filtered_ports"].append(port_detail)
                        elif state == "closed":
                            results["closed_count"] += 1
                
                # Get OS detection if available
                if "osmatch" in host_data:
                    os_matches = host_data["osmatch"]
                    if os_matches:
                        results["os_detection"] = [
                            {
                                "name": match["name"],
                                "accuracy": match["accuracy"],
                            }
                            for match in os_matches
                        ]
            
            logger.info(f"Scan completed: {len(results['open_ports'])} open ports found")
            return results
            
        except Exception as e:
            logger.error(f"Port scan failed: {e}")
            raise RuntimeError(f"Port scan failed: {str(e)}")
    
    async def scan_top_ports(self, target: str, count: int = 100) -> Dict[str, Any]:
        """
        Scan top N most common ports.
        
        Args:
            target: Target IP or hostname
            count: Number of top ports to scan
            
        Returns:
            Scan results
        """
        logger.info(f"Scanning top {count} ports on {target}")
        
        nmap_args = f"-sS -T{self.config.scan.nmap_speed} --top-ports {count}"
        
        try:
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.nm.scan(target, arguments=nmap_args)
            )
            
            results = {
                "target": target,
                "scan_type": f"top_{count}_ports",
                "open_ports": [],
            }
            
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    ports_data = self.nm[target][proto]
                    for port, data in ports_data.items():
                        if data["state"] == "open":
                            results["open_ports"].append({
                                "port": port,
                                "protocol": proto,
                                "service": data.get("name", "unknown"),
                                "version": data.get("version", ""),
                            })
            
            return results
            
        except Exception as e:
            logger.error(f"Top ports scan failed: {e}")
            raise RuntimeError(f"Top ports scan failed: {str(e)}")
    
    async def service_version_detection(self, target: str, port: int) -> Dict[str, Any]:
        """
        Detailed service version detection for specific port.
        
        Args:
            target: Target IP or hostname
            port: Port number
            
        Returns:
            Service details
        """
        logger.info(f"Detecting service version on {target}:{port}")
        
        try:
            nmap_args = f"-sV -T{self.config.scan.nmap_speed} -p {port}"
            
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.nm.scan(target, str(port), arguments=nmap_args)
            )
            
            if target in self.nm.all_hosts():
                for proto in self.nm[target].all_protocols():
                    ports_data = self.nm[target][proto]
                    if port in ports_data:
                        return {
                            "port": port,
                            "protocol": proto,
                            "service": ports_data[port].get("name", "unknown"),
                            "product": ports_data[port].get("product", ""),
                            "version": ports_data[port].get("version", ""),
                            "extrainfo": ports_data[port].get("extrainfo", ""),
                            "cpe": ports_data[port].get("cpe", ""),
                        }
            
            return {"port": port, "status": "unknown"}
            
        except Exception as e:
            logger.error(f"Service version detection failed: {e}")
            raise RuntimeError(f"Service version detection failed: {str(e)}")
