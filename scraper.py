import re
from urllib.parse import urlparse

# receives a URL and corresponding Web response. parse the web response, extract enough information from the page
# to be able to answer the questions for the report
# lastly, return the list of URLs scapped
def scraper(url, resp):
    print("hi")
    links = extract_next_links(url, resp)
    return [link for link in links if is_valid(link)]

num_links = 0
file_call = 0
url_already_parsed = set()
def extract_next_links(url, resp):
    print("\n\n" + url + "\n\n")
    # Implementation required.
    # url: the URL that was used to get the page
    # resp.url: the actual url of the page
    # resp.status: the status code returned by the server. 200 is OK, you got the page. Other numbers mean that there was some kind of problem.
    # resp.error: when status is not 200, you can check the error here, if needed.
    # resp.raw_response: this is where the page actually is. More specifically, the raw_response has two parts:
    #         resp.raw_response.url: the url, again
    #         resp.raw_response.content: the content of the page!
    # Return a list with the hyperlinks (as strings) scrapped from resp.raw_response.content

    link_list = []

    if (resp.status != 200):
        print("Problem getting page.")
        return link_list

    # website_content = str(resp.raw_response.content).split(" ")
    decode_site = resp.raw_response.content.decode('utf-8', errors = 'ignore')

    
    https_pattern = r'(https?://[^\s]+)'
    found = re.findall(https_pattern, decode_site)

    
    
    for i in found:
        if i not in url_already_parsed:
            i = i[i.find("http"): ]
            if (i.find("\"") != -1):
                i = i[0: i.find("\"") ]
            # elif (i.find("\'") != -1):
            #     i = i[0: i.find("\'") ]
            if (i.find("#") != -1):
                i = i[: i.find("#")]
            i = i.replace("\\/", '/').replace("\\", "")
            link_list.append(i)
    
    for i in link_list:
        print(i)
    

    global num_links, file_call

    num_links += len(link_list)
    file_call += 1
        
    print("Links: " + str(num_links))
    print("File called: " + str(file_call))
    return link_list

# 
check = 0
url_current = ""
def is_valid(url):
    global url_current, check
    check += 1
    
    # print("IS VALI/D CHECKING " + str(check))
    # Decide whether to crawl this url or not. 
    # If you decide to crawl it, return True; otherwise return False.
    # There are already some conditions that return False.


    try:
        parsed = urlparse(url)
        if parsed.scheme not in set(["http", "https"]):
            return False

        accept_hostnames = [
            r".*\.ics\.uci\.edu$",
            r".*\.cs\.uci\.edu$",
            r".*\.informatics\.uci\.edu$", 
            r".*\.stat\.uci\.edu$",
        ]

        valid_hostname = False

        for link in accept_hostnames:
            if not parsed.hostname:
                return False
            if re.match(link, parsed.hostname):
                valid_hostname = True
            
        
        if not valid_hostname:
            return False
        
        
        
        return not re.match(
            r".*\.(css|js|bmp|gif|jpe?g|ico"
            + r"|png|tiff?|mid|mp2|mp3|mp4"
            + r"|wav|avi|mov|mpeg|ram|m4v|mkv|ogg|ogv|pdf"
            + r"|ps|eps|tex|ppt|pptx|doc|docx|xls|xlsx|names"
            + r"|data|dat|exe|bz2|tar|msi|bin|7z|psd|dmg|iso"
            + r"|epub|dll|cnf|tgz|sha1"
            + r"|thmx|mso|arff|rtf|jar|csv"
            + r"|rm|smil|wmv|swf|wma|zip|rar|gz)$", parsed.path.lower())

    except TypeError:
        print ("TypeError for ", parsed)
        raise
