# DISVA - Docker Image Static Vulnerability Analyzer

## disvā (Pali) - abs. *having seen; having understood; having found out* [√dis + tvā]

Hi, welcome to our Intro to Cloud Computing course project -- **DISVA** Docker Image Static Vulnerability Analyzer.

DISVA identifies a packages found within a docker image and produces a list of vulnerabilities associated with those packages, sourced from the CVE database. We do this by generating a .tar archive of the target image with `docker save <image_name> > <tarball_name>`, generating a JSON of packages, and sending that to the CVE API, which responds with a JSON of vulnerabilities.

- First, we examine the manifest in the toplevel directory of the archive, and proceed through the layers which comprise the docker image. We selectively extract files relevant to operating system version and package management from each of the layers, using regular expressions. All files that get extracted are stored in a temporary directory, temp_extract, which is then cleaned up when the tool finishes. We try to do as little file writing and as much in-memory processing as possible for speed's sake, but we may tweak this because the contents of docker files can be arbitrarily large.
- We then determine the package manager being used and extract the list of packages using an appropriate method. We currently support parsing the installed packages of the DPKG + apt, apk, and rpm package managers. DPKG + apt, and apk support is fairly simple, and rpm is more complex. Rpm uses a binary database file at /var/lib/rpm/Packages, which is only meant to be parsed by rpm. To support this, the scanner queries the database with rpm --dbpath /absolute/path/to/rpm/db/root -qa to get the installed packages. This technically makes this scanner a partial dynamic-analysis tool, but this seems to be the only way to access the package information cleanly from the extracted files.
- This initial scan produces a well-formatted JSON (e.g., packages_out.json by default) detailing the detected OS and the list of packages. This file then serves as the input for the next stage.
- The generated package and OS information produces the input to the vulnerability scanning stage. Using the NVD REST API, DISVA queries for vulnerabilities related to the detected OS version and, separately, for groups of discovered packages. Package name queries are batched to the NVD API to handle large sets efficiently. A vulnerability is associated with a package if the package name is found within the CVE's description text. The final output is a JSON detailing these potential vulnerabilities, including CVE IDs and a snippet of their descriptions.
- This project was heavily inspired by the EMBA project found at https://github.com/e-m-b-a/emba, though ours is obviously nowhere near as feature rich.
- If you find this interesting, please consider checking out the far more mature [dive](https://github.com/wagoodman/dive) and [syft](https://github.com/anchore/syft) projects.
- This project utilized LLMs for some code and documentation generation, specifically Anthropic's Claude 3.7 Sonnet model. All generative content was verified by a human.
- To ensure that the layer scanning works properly, I compared the outputs of running the tool on both ubuntu:latest and the ubuntu image defined in Dockerfile.ubuntu_tree, which simply installs one more package in the image. I additionally ran it on mongo:latest, redis:latest, nginx:latest, alpine:latest, and centos/postgresql-10-centos7:latest, and it succesfully identified installed packages in all cases.

Package list output:
![image](https://github.com/user-attachments/assets/2cd4ccda-4217-4cf9-a663-887cda8290df)

Vulnerabilities list output:
![image](https://github.com/user-attachments/assets/4532d58d-bff5-4e94-9c8a-dd7f18d353a1)

## Setup (Local Development):

1.  **Clone the repository (or download and extract the ZIP):**
    ```bash
    git clone https://github.com/callisto-h/DISVA-Docker_Image_Static_Vulnerability_Scanner.git
    cd DISVA-Docker_Image_Static_Vulnerability_Scanner
    ```

2.  **Create a virtual environment (recommended):**
    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

3.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Configure your NVD API Key:**
    *   Copy the example environment file:
        ```bash
        cp .env.example .env
        ```
    *   Edit the `.env` file and add your NVD API key:
        ```
        NVD_API_KEY="YOUR_ACTUAL_NVD_API_KEY_HERE"
        ```

## Usage

### Local Usage (Running Python Scripts Directly)

First, create an archive file from the target docker image:

```bash
docker save <image> > <image.tar>
# Example: docker save ubuntu:latest > ubuntu_latest.tar
```

Run the vulnerability scanner script from the project root directory:

```bash
python3 vulnerability_scan.py <path_to_docker_image.tar> [packages_output.json] [vulnerabilities_output.json] [OPTIONS]
```

Or, to only produce a list of packages in a docker image:

```bash
python3 image_scanner.py <path_to_docker_image.tar> [packages_output.json]
```

**Arguments for `vulnerability_scan.py`:**

*   `<path_to_docker_image.tar>`: (Required) Path to the Docker image saved as a .tar file.
*   `[packages_output.json]`: (Optional) Path to save the extracted package information. Defaults to `packages_out.json` in the current directory.
*   `[vulnerabilities_output.json]`: (Optional) Path to save the vulnerability scan results. Defaults to `vulnerable_out.json` in the current directory.
*   `[OPTIONS]`: (Optional) Further options like CVSS severity filtering (e.g., `HIGH`).

**Example (Local Usage):**

```bash
# Create the image archive
docker save nginx:latest > nginx_latest.tar

# Run the vulnerability scanner
python3 vulnerability_scan.py nginx_latest.tar nginx_packages.json nginx_vulnerabilities.json HIGH
```

### Usage with Docker Container

You can also run DISVA as a Docker container. This is convenient as it bundles all dependencies.

1.  **Pull the Docker Image:**
    ```bash
    docker pull chess2/disva:latest
    ```

2.  **Prepare your Input and Output:**
    *   Ensure you have your Docker image saved as a `.tar` file on your host machine (e.g., `my_image.tar`).
    *   Create a directory on your host machine where the output JSON files will be saved (e.g., `mkdir scan_results`).

3.  **Run the DISVA Container:**
    You'll need to provide your NVD API key as an environment variable and mount your input `.tar` file and output directory into the container.

    ```bash
    docker run --rm \
        -e NVD_API_KEY="YOUR_ACTUAL_NVD_API_KEY_HERE" \
        -v /path/to/your/image.tar:/app/input_image.tar:ro \
        -v /path/to/your/scan_results_directory:/app/outputs \
        chess2/disva:latest \
        /app/input_image.tar /app/outputs/packages.json /app/outputs/vulnerabilities.json [OPTIONAL_FLAGS]
    ```

    **Explanation of `docker run` options:**
    *   `--rm`: Automatically removes the container when it finishes.
    *   `-e NVD_API_KEY="YOUR_ACTUAL_NVD_API_KEY_HERE"`: **Crucial!** Replace with your NVD API key.
    *   `-v /path/to/your/image.tar:/app/input_image.tar:ro`:
        *   Replace `/path/to/your/image.tar` with the actual path to your saved Docker image TAR file on your host machine.
        *   This mounts it as `input_image.tar` inside the container's `/app` directory.
        *   `:ro` makes it read-only inside the container.
    *   `-v /path/to/your/scan_results_directory:/app/outputs`:
        *   Replace `/path/to/your/scan_results_directory` with the actual path to the directory on your host where you want output files.
        *   This mounts it as the `/app/outputs` directory inside the container.
    *   `chess2/disva:latest`: The name of the Docker image.
    *   `/app/input_image.tar /app/outputs/packages.json /app/outputs/vulnerabilities.json [OPTIONAL_FLAGS]`: These are the arguments passed to the `vulnerability_scan.py` script *inside* the container.
        *   The first argument is the path to the input TAR file *inside the container*.
        *   The second and third arguments are the paths for the output JSON files *inside the container's mounted output directory*.
        *   `[OPTIONAL_FLAGS]` can be added for severity filtering, e.g., `HIGH`.

    **Example (Docker Usage):**
    Let's say your image TAR is at `~/docker_images/my_app.tar` and you want outputs in `~/disva_results`.

    First, create the output directory if it doesn't exist:
    ```bash
    mkdir -p ~/disva_results
    ```

    Then run the container:
    ```bash
    docker run --rm \
        -e NVD_API_KEY="abcdef12345YOURKEY" \
        -v ~/docker_images/my_app.tar:/app/input_image.tar:ro \
        -v ~/disva_results:/app/outputs \
        chess2/disva:latest \
        /app/input_image.tar /app/outputs/my_app_packages.json /app/outputs/my_app_vulnerabilities.json
    ```
    After the command completes, `my_app_packages.json` and `my_app_vulnerabilities.json` will be in your `~/disva_results` directory.
