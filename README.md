# Opennic2Web - WIP

Based on Tor2Web/Tor2Web which is licensed under AGPLv3, Opennic2Web is licensed under the AGPLv3-or-later.

## Usage

Replace an OpenNIC url `http://opennic.oss/` with `http://opennic.oss.opennic.cf/` (link doesn't work yet).

## Build

Clone the repository, then run the following commands:

```sh
# Create a virtual env and activate it
pip -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run it
./o2w.py

# Deactivate the virtual env when you're done
deactivate
```

The server only listens on port 8080 only for now.

## Roadmap to 1.0

- Blocklist support, and reporting
- Error handling
- Finish the error pages
- Add logo in banner