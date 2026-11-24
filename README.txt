IP Reputation Project

Purpose:
By using the supplied IP's, we run through the list and check the chanace of risk each IP has ata accessing a server
based upon a measure of its score from high to low

Files:
- suspicious_ips.txt: synthetic documentation-range IPs used for the main batch analysis. Do not scan or contact these addresses.
- mock_reputation_data.json: synthetic API-like reputation data for the same IPs. This makes the main project reproducible for every student.
- approved_live_test_ips.txt: well-known public DNS resolver IPs that may be used ONLY to test an AbuseIPDB CHECK request. 
  Reputation results can change and are not part of the fixed answer key.

Requirements:
Python version/
    Python 3.13.17

Structure of my Folder:
 -.venv
 -data/
    approved_live_test_ips
    mock_reputation_data
    suspicious_ips
    test_ips.txt
 -Output/
    report.csv
    report.json
 -.gitignore
 -config.json
 -Ip_reputations.py
 -README.txt
 -requirements.txt

 Setting the API keys:
  -Go to abuseipdb.com
  -Create an account and click create key
  -Give it name, for me I named it "uni-project"
  -Once created, set the key as an environmental variable in               PowerShell with $env and setx commands 
  -WARNING: Do not commit the API key in code, as it is unsafe to do so because other people can gain easy access to it

Running the IP Investigation:
 1.Add your imports:
   -Import csv(Save report and formating the output), json(Hold and print information into the print out), 
   ipaddress(Used to create/poke/manipulate IPv4 and IPv6 addresses and networks.), os(allows the program to be portable
   acroos differnet platforms) and requests(Helps when gettting information from the HTTP library)
 2.Set your constants:
   -API_URL
   -DEFAULT_THRESHOLD  #Note: These act as a fallback for the threshold as well as printing an erro message should it not work
   -RISk_ORDER
 3.Create code for your inputs and configurations:
   -Load your thresholds, including parametres for success and failure's that occur
   -Load your IP's from the supplied file
   -Validate each IP
 4.Request and check the API key you create:
   -Set out configurations for success and failure of the API key requested from other platforms
 5.Analyse the IP's to find if they're unique or invalid, their location and whether their safe(whitelisted)
 6.Save a report to csv and json
 7.Print the value's given to the code, where its saved and the API key provided:
  -Your main() text

Config.json:
 1. What each value means:
  medium_threshold: the minimum abuse confidence score (0-100) for an IP to be classed MEDIUM.
  high_threshold: the minimum score for HIGH.
  Anything below medium_threshold is LOW.

 2. The rules the values must follow:
  Your load_config enforces 0 <= medium < high <= 100, and both must be whole numbers. If they're broken: the script prints a warning and falls back to the defaults (25 and 75).

 3. The whitelist override
  Whitelisted IPs are always LOW regardless of thresholds, so changing the numbers never affects them.

 4. A short example of the effect
  A small table shows the configurability is real:

  Setting	            An IP with score 60 is classed
  medium 25, high 75 (default)	  MEDIUM
  medium 25, high 50	           HIGH
  medium 70, high 90	           LOW

 5. If edited:
  lowering the thresholds catches more potential threats but produces more false positives for the analyst to review, 
  while raising them gives a shorter, more confident list but risks missing lower-scoring threats. 
  A team with plenty of analyst time might lower them, and an overloaded one might raise them

Classifying Risk:
 -If there's no data in the Ip, the risk is UNKNOWN
 -If the IP is whitelisted, the IP will be LOW, no matter the score
 -If the IP is greater than than the higher threshold limit, its shown as HIGH
 -Finally, if a IP is at or above the medium threshold, then its score is MEDIUM
 else its just LOW

What each table means:
 -High: If a IP is labelled as high, it will be investigated first or blocked
 -Medium: It will be reviewed at a given time
 -Low: No action needs to be taken against this IP until good reason is provided
 Results are sorted from HIGH first to LOW last in the table when printed.
 These values can be altered in the config.json file to change the cut off point
 -Limitation: Scores come from crowd-sourced reports, which can be mistaken, outdated or deliberately false, A report may describe a previous owner of the address
 and A low score doesn't mean safe. New or targeted attackers may have no reports yet.

Security:
Never commit API keys to GitHub. Do not scan or connect to the supplied IP addresses. This project performs reputation lookups only.
