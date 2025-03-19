"""
Simplified Container Vulnerability Scanner

This script provides a minimal implementation of a container vulnerability scanner
that uses static analysis (no container execution) for security.
"""
import os
import sys
import json
import logging
import tempfile
import shutil
import subprocess
import tarfile
import glob
import re
import requests
from datetime import datetime

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class SimpleImageAnalyzer:
    """Extract package information from Docker images without running containers."""
    
    def analyze_image(self, image_name):
        """Analyze a Docker image and extract installed packages."""
        logger.info(f"Analyzing image: {image_name}")
        
        # Ensure the image exists locally
        try:
            # Check if image exists
            result = subprocess.run(
                ["docker", "image", "inspect", image_name], 
                capture_output=True, 
                text=True
            )
            if result.returncode != 0:
                logger.info(f"Pulling image: {image_name}")
                subprocess.run(["docker", "pull", image_name], check=True)
        except Exception as e:
            return {"error": f"Failed to pull image: {str(e)}"}
        
        # Create a temporary directory
        temp_dir = tempfile.mkdtemp()
        
        try:
            # Save the image to a tar file
            tar_path = os.path.join(temp_dir, "image.tar")
            logger.info(f"Saving image to tar file")
            subprocess.run(["docker", "save", "-o", tar_path, image_name], check=True)
            
            # Extract the image
            extract_path = os.path.join(temp_dir, "extract")
            os.makedirs(extract_path, exist_ok=True)
            
            logger.info(f"Extracting image contents")
            with tarfile.open(tar_path) as tar:
                tar.extractall(path=extract_path)
            
            # Find package information
            logger.info(f"Scanning for package information")
            packages = self._find_packages(extract_path)
            
            return {
                "image_name": image_name,
                "scan_time": datetime.now().isoformat(),
                "packages": packages,
                "package_count": sum(len(pkgs) for pkgs in packages.values())
            }
            
        except Exception as e:
            logger.error(f"Error analyzing image: {str(e)}")
            return {"error": str(e)}
            
        finally:
            # Clean up
            logger.info("Cleaning up temporary files")
            shutil.rmtree(temp_dir)
    
    def _find_packages(self, extract_path):
        """Find package information in the extracted image."""
        packages = {}
        
        # Check for Debian/Ubuntu packages
        dpkg_files = glob.glob(f"{extract_path}/**/var/lib/dpkg/status", recursive=True)
        if dpkg_files:
            logger.info("Found Debian/Ubuntu packages")
            packages["apt"] = self._parse_dpkg(dpkg_files[0])
        
        # Check for Alpine packages
        apk_files = glob.glob(f"{extract_path}/**/lib/apk/db/installed", recursive=True)
        if apk_files:
            logger.info("Found Alpine packages")
            packages["apk"] = self._parse_apk(apk_files[0])
        
        return packages
    
    def _parse_dpkg(self, status_file):
        """Parse Debian package status file."""
        packages = []
        try:
            with open(status_file, 'r', errors='ignore') as f:
                content = f.read()
                
            # Split file into package entries
            package_blocks = re.split(r'\n\n+', content)
            
            for block in package_blocks:
                if not block.strip():
                    continue
                    
                name_match = re.search(r'Package:\s*(.+)', block)
                version_match = re.search(r'Version:\s*(.+)', block)
                
                if name_match and version_match:
                    name = name_match.group(1).strip()
                    version = version_match.group(1).strip()
                    
                    packages.append({
                        "name": name,
                        "version": version
                    })
            
            return packages
        except Exception as e:
            logger.error(f"Error parsing dpkg status: {str(e)}")
            return []
    
    def _parse_apk(self, db_file):
        """Parse Alpine package database."""
        packages = []
        try:
            with open(db_file, 'r', errors='ignore') as f:
                content = f.read()
                
            # Split file into package entries
            package_blocks = re.split(r'\n\n+', content)
            
            for block in package_blocks:
                if not block.strip():
                    continue
                    
                name_match = re.search(r'P:(.+)', block)
                version_match = re.search(r'V:(.+)', block)
                
                if name_match and version_match:
                    name = name_match.group(1).strip()
                    version = version_match.group(1).strip()
                    
                    packages.append({
                        "name": name,
                        "version": version
                    })
            
            return packages
        except Exception as e:
            logger.error(f"Error parsing apk database: {str(e)}")
            return []

class SimpleVulnerabilityChecker:
    """Check packages for known vulnerabilities."""
    
    def __init__(self):
        # NVD API URL
        self.nvd_base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    def check_vulnerabilities(self, packages, max_check=10):
        """
        Check packages for vulnerabilities.
        
        To simplify for testing, we only check the first few packages.
        """
        results = {}
        count = 0
        
        # Flatten packages from different sources
        all_packages = []
        for pkg_type, pkg_list in packages.items():
            all_packages.extend(pkg_list)
        
        # Only check a limited number of packages for demo purposes
        for package in all_packages[:max_check]:
            pkg_name = package["name"]
            pkg_version = package["version"]
            pkg_id = f"{pkg_name}@{pkg_version}"
            
            logger.info(f"Checking vulnerabilities for {pkg_id}")
            
            # Simple API request to NVD
            try:
                # Only query a basic term to avoid rate limiting
                params = {
                    "keywordSearch": pkg_name,
                    "resultsPerPage": 5  # Limit for testing
                }
                
                response = requests.get(self.nvd_base_url, params=params)
                
                if response.status_code == 200:
                    data = response.json()
                    vulns = self._extract_vulnerabilities(data, pkg_name)
                    
                    if vulns:
                        results[pkg_id] = vulns
                        count += len(vulns)
                else:
                    logger.warning(f"API error: {response.status_code}")
                    
            except Exception as e:
                logger.error(f"Error checking {pkg_name}: {str(e)}")
                
        logger.info(f"Found {count} potential vulnerabilities")
        return results
    
    def _extract_vulnerabilities(self, data, package_name):
        """Extract relevant vulnerabilities from NVD data."""
        vulnerabilities = []
        
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id", "")
            
            # Get description
            description = ""
            for desc in cve.get("descriptions", []):
                if desc.get("lang") == "en":
                    description = desc.get("value", "")
                    break
            
            # Get severity
            metrics = cve.get("metrics", {})
            cvss_v3 = metrics.get("cvssMetricV31", [{}])[0] if "cvssMetricV31" in metrics else {}
            
            severity = cvss_v3.get("baseSeverity", "UNKNOWN") if cvss_v3 else "UNKNOWN"
            
            # Simple check if the package name appears in the description
            # (This is a simplified approach - production code should be more sophisticated)
            if package_name.lower() in description.lower():
                vulnerabilities.append({
                    "cve_id": cve_id,
                    "description": description,
                    "severity": severity
                })
        
        return vulnerabilities

def generate_report(analysis_result, vulnerability_results):
    """Generate a simple vulnerability report."""
    
    # Count vulnerabilities by severity
    severity_counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0
    }
    
    for pkg_id, vulns in vulnerability_results.items():
        for vuln in vulns:
            severity = vuln.get("severity", "UNKNOWN").upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
            else:
                severity_counts["UNKNOWN"] += 1
    
    # Build report
    report = {
        "image": analysis_result.get("image_name", "unknown"),
        "scan_time": analysis_result.get("scan_time", datetime.now().isoformat()),
        "package_count": analysis_result.get("package_count", 0),
        "vulnerability_count": sum(severity_counts.values()),
        "severity_counts": severity_counts,
        "vulnerabilities": []
    }
    
    # Add vulnerability details
    for pkg_id, vulns in vulnerability_results.items():
        pkg_parts = pkg_id.split('@')
        pkg_name = pkg_parts[0]
        pkg_version = pkg_parts[1] if len(pkg_parts) > 1 else "unknown"
        
        for vuln in vulns:
            report["vulnerabilities"].append({
                "package": pkg_name,
                "version": pkg_version,
                "cve_id": vuln.get("cve_id", ""),
                "severity": vuln.get("severity", "UNKNOWN"),
                "description": vuln.get("description", "")
            })
    
    return report

def save_report(report, output_dir="./reports"):
    """Save the report to a file."""
    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # Create filename
    image_name = report["image"].replace("/", "_").replace(":", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"{image_name}_{timestamp}.json"
    filepath = os.path.join(output_dir, filename)
    
    # Save report
    try:
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        logger.info(f"Report saved to: {filepath}")
        return filepath
    except Exception as e:
        logger.error(f"Failed to save report: {str(e)}")
        return None

def print_report_summary(report):
    """Print a summary of the vulnerability report."""
    print("\n" + "=" * 60)
    print(f"VULNERABILITY SCAN RESULTS FOR {report['image']}")
    print("=" * 60)
    
    print(f"\nScan Time: {report['scan_time']}")
    print(f"Total Packages: {report['package_count']}")
    print(f"Vulnerabilities Found: {report['vulnerability_count']}")
    
    print("\nSeverity Breakdown:")
    for severity, count in report['severity_counts'].items():
        print(f"  {severity}: {count}")
    
    if report['vulnerabilities']:
        print("\nTop Vulnerabilities:")
        for i, vuln in enumerate(report['vulnerabilities'][:5]):  # Show top 5
            print(f"\n{i+1}. {vuln['cve_id']} ({vuln['severity']})")
            print(f"   Package: {vuln['package']} {vuln['version']}")
            desc = vuln['description']
            if len(desc) > 80:
                desc = desc[:77] + "..."
            print(f"   {desc}")
    
    print("\n" + "=" * 60)

def scan_image(image_name, output_dir="./reports"):
    """Main function to scan an image for vulnerabilities."""
    logger.info(f"Starting vulnerability scan for {image_name}")
    
    # Initialize components
    analyzer = SimpleImageAnalyzer()
    checker = SimpleVulnerabilityChecker()
    
    # Analyze image
    analysis_result = analyzer.analyze_image(image_name)
    
    if "error" in analysis_result:
        logger.error(f"Analysis failed: {analysis_result['error']}")
        return None
    
    # Check for vulnerabilities
    vulnerability_results = checker.check_vulnerabilities(analysis_result.get("packages", {}))
    
    # Generate and save report
    report = generate_report(analysis_result, vulnerability_results)
    save_report(report, output_dir)
    
    # Print summary
    print_report_summary(report)
    
    return report

if __name__ == "__main__":
    # Simple command line interface
    if len(sys.argv) < 2:
        print("Usage: python simple_scanner.py IMAGE_NAME [OUTPUT_DIR]")
        sys.exit(1)
    
    image_name = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "./reports"
    
    scan_image(image_name, output_dir)