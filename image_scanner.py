#!/usr/bin/env python3

import tarfile
import json
import os
import sys
import re


def pattern_based_extraction(layer_tar_path):
    """Extract files matching patterns directly while reading the tarfile"""
    
    # Define patterns to match (using regular expressions for flexibility)
    patterns = [
        r"^var/lib/dpkg/status$",                        # Debian/Ubuntu
        r"^var/lib/apt/lists/.*_Packages$",              # Debian package lists
        r"^lib/apk/db/installed$",                       # Alpine
        r"^var/lib/rpm/.*",                              # RPM-based
        r"^etc/os-release$",                             # OS detection
        r"^etc/.*-release$",                             # Various release files
        r"^etc/issue$"                                   # OS identification
    ]
    
    # Compile regular expressions
    compiled_patterns = [re.compile(pattern) for pattern in patterns]
    
    # Store extracted content
    extracted_files = {}
    
    with tarfile.open(layer_tar_path, 'r') as tar:
        for member in tar:
            # Skip directories
            if member.isdir():
                continue
                
            # Check if this file matches any pattern
            for pattern in compiled_patterns:
                if pattern.match(member.name):
                    try:
                        f = tar.extractfile(member)
                        if f:
                            extracted_files[member.name] = f.read()
                    except Exception as e:
                        print(f"Error extracting {member.name}: {e}")
                    break
    
    return extracted_files

def extract_dpkg_packages_in_memory(file_contents):
    """Extract Debian/Ubuntu packages from in-memory status file"""
    packages = []
    
    # # Process dpkg status file if available
    if "var/lib/dpkg/status" in file_contents:
        content = file_contents["var/lib/dpkg/status"].decode('utf-8', errors='replace')
        pkg_blocks = content.split("\n\n")
        
        for block in pkg_blocks:
            if not block.strip():
                continue
                
            pkg_info = {}
            lines = block.split("\n")
            for line in lines:
                if not line or ":" not in line:
                    continue
                key, value = line.split(":", 1)
                pkg_info[key.strip()] = value.strip()
            
            if "Package" in pkg_info and "Version" in pkg_info:
                packages.append({
                    "name": pkg_info["Package"],
                    "version": pkg_info["Version"],
                    "architecture": pkg_info.get("Architecture", ""),
                    "source": pkg_info.get("Source", pkg_info["Package"])
                })
    
    # Process apt lists if available
    apt_lists_files = [k for k in file_contents.keys() if k.startswith("var/lib/apt/lists/") and k.endswith("_Packages")]
    for list_file in apt_lists_files:
        content = file_contents[list_file].decode('utf-8', errors='replace')
        pkg_blocks = content.split("\n\n")
        
        for block in pkg_blocks:
            if not block.strip():
                continue
                
            pkg_info = {}
            lines = block.split("\n")
            for line in lines:
                if not line or ":" not in line:
                    continue
                key, value = line.split(":", 1)
                pkg_info[key.strip()] = value.strip()
            
            if "Package" in pkg_info and "Version" in pkg_info:
                packages.append({
                    "name": pkg_info["Package"],
                    "version": pkg_info["Version"],
                    "architecture": pkg_info.get("Architecture", ""),
                    "source": pkg_info.get("Source", pkg_info["Package"])
                })
    
    return packages

def extract_apk_packages_in_memory(file_contents):
    """Extract Alpine Linux packages from in-memory installed db"""
    packages = []
    
    if "lib/apk/db/installed" in file_contents:
        content = file_contents["lib/apk/db/installed"].decode('utf-8', errors='replace')
        pkg_blocks = content.split("\n\n")
        
        for block in pkg_blocks:
            if not block.strip():
                continue
            
            pkg_info = {}
            lines = block.split("\n")
            for line in lines:
                if not line:
                    continue
                
                if line.startswith("P:"):
                    pkg_info["name"] = line[2:].strip()
                elif line.startswith("V:"):
                    pkg_info["version"] = line[2:].strip()
                elif line.startswith("A:"):
                    pkg_info["architecture"] = line[2:].strip()
                elif line.startswith("T:"):
                    pkg_info["description"] = line[2:].strip()
            
            if "name" in pkg_info and "version" in pkg_info:
                packages.append(pkg_info)
    
    return packages

def extract_rpm_packages_in_memory(file_contents):
    """Extract RPM-based packages from in-memory files"""
    packages = []
    
    # Process RPM database if available
    if "var/lib/rpm/Packages" in file_contents:
        # We need to write the RPM database to a temporary directory
        import tempfile
        import shutil
        import subprocess
        import os
        
        # Create temporary directory to hold the RPM database
        temp_dir = tempfile.mkdtemp()
        try:
            # Create necessary subdirectories
            rpm_dir = os.path.join(temp_dir, "var", "lib", "rpm")
            os.makedirs(rpm_dir, exist_ok=True)
            
            # Write the Packages file
            with open(os.path.join(rpm_dir, "Packages"), "wb") as f:
                f.write(file_contents["var/lib/rpm/Packages"])
            
            # Write other RPM database files if they exist
            for file_path in file_contents:
                if file_path.startswith("var/lib/rpm/") and file_path != "var/lib/rpm/Packages":
                    dest_path = os.path.join(temp_dir, file_path)
                    os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                    with open(dest_path, "wb") as f:
                        f.write(file_contents[file_path])
            
            # Run rpm command to query the database
            try:
                result = subprocess.run(
                    ["rpm", "--dbpath", rpm_dir, "-qa", "--queryformat", "%{NAME}|%{VERSION}|%{ARCH}\n"],
                    capture_output=True,
                    text=True,
                    check=False  # Don't raise exception on non-zero exit
                )
                
                # Process the output
                for line in result.stdout.splitlines():
                    # Skip warning lines
                    if line.startswith("warning:"):
                        continue
                    
                    # Parse package information
                    if "|" in line:
                        parts = line.strip().split("|")
                        if len(parts) >= 2:
                            pkg_info = {
                                "Package": parts[0],
                                "Version": parts[1],
                                "Architecture": parts[2] if len(parts) > 2 else ""
                            }
                            
                            packages.append({
                                "name": pkg_info["Package"],
                                "version": pkg_info["Version"],
                                "architecture": pkg_info.get("Architecture", ""),
                                "source": pkg_info.get("Package")
                            })
            except Exception as e:
                print(f"Error running rpm command: {e}")
                
        finally:
            # Clean up temporary directory
            shutil.rmtree(temp_dir)
    
    return packages

def detect_os_in_memory(file_contents):
    """Detect OS from in-memory files"""
    os_info = {"id": "unknown", "version_id": "unknown"}
    
    # Check os-release first
    if "etc/os-release" in file_contents:
        content = file_contents["etc/os-release"].decode('utf-8', errors='replace')
        info = {}
        for line in content.splitlines():
            if '=' in line:
                key, value = line.split('=', 1)
                info[key] = value.strip('"\'')
        
        os_info = {
            "id": info.get("ID", "unknown"),
            "version_id": info.get("VERSION_ID", "unknown"),
            "name": info.get("NAME", "unknown")
        }
    
    # Check other OS-specific files if needed
    elif "etc/debian_version" in file_contents:
        version = file_contents["etc/debian_version"].decode('utf-8', errors='replace').strip()
        os_info = {"id": "debian", "version_id": version}
    elif "etc/alpine-release" in file_contents:
        version = file_contents["etc/alpine-release"].decode('utf-8', errors='replace').strip()
        os_info = {"id": "alpine", "version_id": version}
    
    # Determine package manager based on files
    if "var/lib/dpkg/status" in file_contents:
        os_info["package_manager"] = "apt"
    elif "lib/apk/db/installed" in file_contents:
        os_info["package_manager"] = "apk"
    elif "var/lib/rpm/Packages" in file_contents:
        os_info["package_manager"] = "rpm"
    
    return os_info

def analyze_docker_image_optimized(image_path, out_file = ""):
    """Analyze a Docker image efficiently using in-memory processing"""
    # Track cumulative package state
    all_packages = {}
    os_info = None
    
    # Create a temporary directory to extract necessary files
    temp_dir = os.path.join(os.path.dirname(image_path), "temp_extract")
    os.makedirs(temp_dir, exist_ok=True)

    # Extract manifest.json and layer tarballs
    with tarfile.open(image_path, 'r') as tar:
        # Get the manifest file
        manifest_member = tar.getmember('manifest.json')
        manifest_file = tar.extractfile(manifest_member)
        manifest_data = json.loads(manifest_file.read())
        
        layer_num = 0
        # Extract each layer tarball
        for layer_ref in manifest_data[0]["Layers"]:
            layer_member = tar.getmember(layer_ref)
            layer_path = os.path.join(temp_dir, os.path.basename(layer_ref))
            # Logging
            print(f"Examining layer number {layer_num}") 

            # Extract the layer tarball
            with open(layer_path, 'wb') as f:
                f.write(tar.extractfile(layer_member).read())
            
            # Extract files from this layer if they match a package manager pattern
            extracted_files = pattern_based_extraction(layer_path)
            
            # Detect OS if not already detected
            if not os_info or os_info["id"] == "unknown":
                os_info = detect_os_in_memory(extracted_files)
            
            # Extract packages based on OS type
            # Extract packages based on OS type
            layer_packages = []
            if os_info.get("package_manager") == "apt":
                layer_packages = extract_dpkg_packages_in_memory(extracted_files)
            elif os_info.get("package_manager") == "apk":
                layer_packages = extract_apk_packages_in_memory(extracted_files)
            elif os_info.get("package_manager") == "rpm": # TODO figure out how the hell to get rpm packages
                layer_packages = extract_rpm_packages_in_memory(extracted_files)
            
            # Update package database (newer layers override older ones)
            for pkg in layer_packages:
                package_key = pkg["name"]
                all_packages[package_key] = pkg

            print(f"Detected {len(layer_packages)} packages in layer {layer_num}")
            layer_num += 1
            # print(f"\nLayer packages: {layer_packages}\n")

            
            # Clean up the layer file
            os.remove(layer_path)
    
    # Clean up temp directory
    os.rmdir(temp_dir)
    
    # Convert back to list
    packages_list = list(all_packages.values())
    
    result = {
        "os": os_info,
        "packages": packages_list,
        "package_count": len(packages_list)
    }
    
    
    if out_file != "":
        with open(out_file, 'w') as f:
            json.dump(result, f, indent=2)
            #os.execvp("echo", ["echo", f"Output written to {out_file}"])
    else:
        print(json.dumps(result, indent=2))
    return result

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <docker_image.tar>")
        sys.exit(1)

    if not (os.path.isfile(sys.argv[1])):
        print(f"Provided file: {sys.argv[0]} doesn't exist")
        sys.exit(1)
    
    result = analyze_docker_image_optimized(sys.argv[1]) if len(sys.argv)<3 else analyze_docker_image_optimized(sys.argv[1], sys.argv[2])
    
    
    # Output is already handled in the function with json.dumps

    # result = analyze_docker_image_optimized("centos_postgres.tar") # hardcoded for testing
